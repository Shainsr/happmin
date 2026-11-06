import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_v2ray/flutter_v2ray.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:shared_preferences/shared_preferences.dart';

const MethodChannel kQuickControlsChannel = MethodChannel('com.example.happ_vpn/quick_controls');

enum PingMode { real, tcp }

class ServerEndpoint {
  final String host;
  final int port;
  const ServerEndpoint(this.host, this.port);
}

// ============================================================================
//  ShainVPN
//  - تشخیص کامل سرورهای سابسکریپشن (base64 / متن ساده / JSON / لینک‌های custom)
//  - پارسر اختصاصی برای vless / vmess / trojan / ss (xhttp, reality, grpc, ws, ...)
//  - گزارش دقیق اینکه چند سرور خوانده شد، چندتا نشد و چرا
// ============================================================================

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ShainVPNApp());
}

// ---------------------------------------------------------------------------
//  ثابت‌ها
// ---------------------------------------------------------------------------

/// User-Agent هایی که به ترتیب برای دریافت سابسکریپشن امتحان می‌شن.
/// بعضی پنل‌ها بسته به UA فرمت خروجی رو عوض می‌کنن.
const List<String> kUserAgents = [
  'v2rayNG/1.9.5',
  'Happ/2.7.0',
  'ShainVPN/1.1 (Android)',
];

const List<String> kDnsOptions = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '94.140.14.14'];

const List<String> kSupportedSchemes = ['vless', 'vmess', 'trojan', 'ss'];

enum AppThemeModeSetting { dark, light, cream }

// ---------------------------------------------------------------------------
//  پارس لینک‌ها
// ---------------------------------------------------------------------------

class ParsedLink {
  final String scheme;
  final String userInfo;
  final String host;
  final int port;
  final Map<String, String> params; // کلیدها lowercase هستن
  final String fragment;

  ParsedLink(this.scheme, this.userInfo, this.host, this.port, this.params, this.fragment);
}

class ConvertedConfig {
  final String remark;
  final String protocol;
  final Map<String, dynamic> config;

  ConvertedConfig(this.remark, this.protocol, this.config);
}

class LinkParser {
  static String safeDecode(String s) {
    try {
      return Uri.decodeComponent(s);
    } catch (_) {
      return s;
    }
  }

  /// دیکود base64 با تحمل خطا: URL-safe، بدون padding، فاصله و خط جدید
  static String? decodeBase64Loose(String input) {
    var s = input.trim().replaceAll(RegExp(r'\s+'), '');
    if (s.isEmpty) return null;
    s = s.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
    final mod = s.length % 4;
    if (mod == 1) return null;
    if (mod == 2) s += '==';
    if (mod == 3) s += '=';
    try {
      return utf8.decode(base64.decode(s), allowMalformed: true);
    } catch (_) {
      return null;
    }
  }

  static MapEntry<String, int>? parseHostPort(String input) {
    final s = input.trim();
    if (s.isEmpty) return null;
    if (s.startsWith('[')) {
      final close = s.indexOf(']');
      if (close < 0) return null;
      final host = s.substring(1, close);
      final after = s.substring(close + 1);
      if (!after.startsWith(':')) return null;
      final port = int.tryParse(after.substring(1));
      if (port == null || port <= 0 || port > 65535) return null;
      return MapEntry(host, port);
    }
    final colon = s.lastIndexOf(':');
    if (colon <= 0) return null;
    final port = int.tryParse(s.substring(colon + 1));
    if (port == null || port <= 0 || port > 65535) return null;
    return MapEntry(s.substring(0, colon), port);
  }

  static ParsedLink? splitLink(String link) {
    final schemeEnd = link.indexOf('://');
    if (schemeEnd <= 0) return null;
    final scheme = link.substring(0, schemeEnd).toLowerCase();
    var rest = link.substring(schemeEnd + 3);

    var fragment = '';
    final hashIdx = rest.indexOf('#');
    if (hashIdx >= 0) {
      fragment = safeDecode(rest.substring(hashIdx + 1)).trim();
      rest = rest.substring(0, hashIdx);
    }

    var query = '';
    final qIdx = rest.indexOf('?');
    if (qIdx >= 0) {
      query = rest.substring(qIdx + 1);
      rest = rest.substring(0, qIdx);
    }

    final slashIdx = rest.indexOf('/');
    if (slashIdx >= 0) rest = rest.substring(0, slashIdx);

    var userInfo = '';
    final atIdx = rest.lastIndexOf('@');
    if (atIdx >= 0) {
      userInfo = safeDecode(rest.substring(0, atIdx));
      rest = rest.substring(atIdx + 1);
    }

    final hp = parseHostPort(rest);
    if (hp == null) return null;

    final params = <String, String>{};
    if (query.isNotEmpty) {
      for (final pair in query.split('&')) {
        if (pair.isEmpty) continue;
        final eq = pair.indexOf('=');
        final key = (eq < 0 ? pair : pair.substring(0, eq)).toLowerCase();
        final value = eq < 0 ? '' : safeDecode(pair.substring(eq + 1));
        params[key] = value;
      }
    }
    return ParsedLink(scheme, userInfo, hp.key, hp.value, params, fragment);
  }

  static String _p(Map<String, String> p, String key, [String fallback = '']) {
    final v = p[key];
    return (v == null || v.isEmpty) ? fallback : v;
  }

  static bool _truthy(String? v) {
    if (v == null) return false;
    final l = v.toLowerCase();
    return l == '1' || l == 'true' || l == 'yes';
  }

  static Map<String, dynamic> _wrap(Map<String, dynamic> outbound) => {
        'log': {'loglevel': 'warning'},
        'inbounds': standardInbounds(),
        'outbounds': [
          outbound,
          {'tag': 'direct', 'protocol': 'freedom', 'settings': {}},
          {'tag': 'blackhole', 'protocol': 'blackhole', 'settings': {}},
        ],
      };

  static List<Map<String, dynamic>> standardInbounds() => [
        {
          'tag': 'in_proxy',
          'port': 10808,
          'protocol': 'socks',
          'listen': '127.0.0.1',
          'settings': {'auth': 'noauth', 'udp': true, 'userLevel': 8},
          'sniffing': {
            'enabled': true,
            'destOverride': ['http', 'tls'],
            'routeOnly': false,
          },
        }
      ];

  static Map<String, dynamic> _stream(
    Map<String, String> p, {
    required String host,
    String defaultSecurity = 'none',
  }) {
    var net = _p(p, 'type', _p(p, 'net', 'tcp')).toLowerCase();
    if (net == 'raw') net = 'tcp';
    if (net == 'splithttp') net = 'xhttp';
    if (net == 'mkcp') net = 'kcp';
    if (net == 'http') net = 'h2';

    final path = _p(p, 'path');
    final hostHeader = _p(p, 'host');
    final stream = <String, dynamic>{'network': net};

    switch (net) {
      case 'ws':
        final ws = <String, dynamic>{'path': path.isEmpty ? '/' : path};
        if (hostHeader.isNotEmpty) ws['headers'] = {'Host': hostHeader};
        stream['wsSettings'] = ws;
        break;
      case 'grpc':
        stream['grpcSettings'] = {
          'serviceName': _p(p, 'servicename', path),
          'multiMode': _p(p, 'mode') == 'multi',
        };
        break;
      case 'httpupgrade':
        stream['httpupgradeSettings'] = {
          'path': path.isEmpty ? '/' : path,
          'host': hostHeader,
        };
        break;
      case 'xhttp':
        final x = <String, dynamic>{
          'path': path.isEmpty ? '/' : path,
          'host': hostHeader,
          'mode': _p(p, 'mode', 'auto'),
        };
        final extra = _p(p, 'extra');
        if (extra.isNotEmpty) {
          try {
            final decoded = jsonDecode(extra);
            if (decoded is Map) x['extra'] = decoded;
          } catch (_) {}
        }
        stream['xhttpSettings'] = x;
        break;
      case 'kcp':
        final kcp = <String, dynamic>{
          'header': {'type': _p(p, 'headertype', 'none')},
        };
        final seed = _p(p, 'seed');
        if (seed.isNotEmpty) kcp['seed'] = seed;
        stream['kcpSettings'] = kcp;
        break;
      case 'h2':
        stream['httpSettings'] = {
          'path': path.isEmpty ? '/' : path,
          'host': hostHeader.isEmpty ? <String>[] : hostHeader.split(','),
        };
        break;
      case 'tcp':
      default:
        if (_p(p, 'headertype') == 'http') {
          stream['tcpSettings'] = {
            'header': {
              'type': 'http',
              'request': {
                'version': '1.1',
                'method': 'GET',
                'path': [path.isEmpty ? '/' : path],
                'headers': {
                  'Host': hostHeader.isEmpty ? <String>[] : hostHeader.split(','),
                  'Connection': ['keep-alive'],
                },
              },
            },
          };
        }
        break;
    }

    final sec = _p(p, 'security', defaultSecurity).toLowerCase();
    if (sec == 'tls') {
      stream['security'] = 'tls';
      final tls = <String, dynamic>{
        'serverName': _p(p, 'sni', _p(p, 'peer', hostHeader.isNotEmpty ? hostHeader : host)),
        'allowInsecure': _truthy(p['allowinsecure']) || _truthy(p['insecure']),
      };
      final fp = _p(p, 'fp');
      if (fp.isNotEmpty) tls['fingerprint'] = fp;
      final alpn = _p(p, 'alpn');
      if (alpn.isNotEmpty) tls['alpn'] = alpn.split(',');
      stream['tlsSettings'] = tls;
    } else if (sec == 'reality') {
      stream['security'] = 'reality';
      stream['realitySettings'] = {
        'serverName': _p(p, 'sni', host),
        'fingerprint': _p(p, 'fp', 'chrome'),
        'publicKey': _p(p, 'pbk'),
        'shortId': _p(p, 'sid'),
        'spiderX': _p(p, 'spx'),
      };
    }
    return stream;
  }

  static ConvertedConfig? convert(String link) {
    final l = link.trim();
    final lower = l.toLowerCase();
    try {
      if (lower.startsWith('vless://')) return _vless(l);
      if (lower.startsWith('vmess://')) return _vmess(l);
      if (lower.startsWith('trojan://')) return _trojan(l);
      if (lower.startsWith('ss://')) return _shadowsocks(l);
    } catch (_) {}
    return null;
  }

  static String _remarkOrDefault(ParsedLink p) =>
      p.fragment.isNotEmpty ? p.fragment : '${p.host}:${p.port}';

  static ConvertedConfig? _vless(String link) {
    final p = splitLink(link);
    if (p == null || p.userInfo.isEmpty) return null;
    final user = <String, dynamic>{
      'id': p.userInfo,
      'encryption': _p(p.params, 'encryption', 'none'),
      'level': 8,
    };
    final flow = _p(p.params, 'flow');
    if (flow.isNotEmpty) user['flow'] = flow;

    final outbound = <String, dynamic>{
      'tag': 'proxy',
      'protocol': 'vless',
      'settings': {
        'vnext': [
          {
            'address': p.host,
            'port': p.port,
            'users': [user],
          }
        ],
      },
      'streamSettings': _stream(p.params, host: p.host),
    };
    return ConvertedConfig(_remarkOrDefault(p), 'VLESS', _wrap(outbound));
  }

  static ConvertedConfig? _trojan(String link) {
    final p = splitLink(link);
    if (p == null || p.userInfo.isEmpty) return null;
    final outbound = <String, dynamic>{
      'tag': 'proxy',
      'protocol': 'trojan',
      'settings': {
        'servers': [
          {'address': p.host, 'port': p.port, 'password': p.userInfo, 'level': 8}
        ],
      },
      'streamSettings': _stream(p.params, host: p.host, defaultSecurity: 'tls'),
    };
    return ConvertedConfig(_remarkOrDefault(p), 'TROJAN', _wrap(outbound));
  }

  static ConvertedConfig? _vmess(String link) {
    var payload = link.substring('vmess://'.length).trim();
    var fragment = '';
    final hashIdx = payload.indexOf('#');
    if (hashIdx >= 0) {
      fragment = safeDecode(payload.substring(hashIdx + 1)).trim();
      payload = payload.substring(0, hashIdx);
    }

    final decoded = decodeBase64Loose(payload);
    if (decoded != null && decoded.trim().startsWith('{')) {
      final j = jsonDecode(decoded);
      if (j is! Map) return null;
      String s(String k) => (j[k] ?? '').toString();

      final host = s('add');
      final port = int.tryParse(s('port'));
      final id = s('id');
      if (host.isEmpty || port == null || id.isEmpty) return null;

      final net = s('net').isEmpty ? 'tcp' : s('net');
      final params = <String, String>{
        'type': net,
        'headertype': s('type') == 'multi' || s('type') == 'gun' ? '' : s('type'),
        'host': s('host'),
        'path': s('path'),
        'security': s('tls') == 'tls' ? 'tls' : 'none',
        'sni': s('sni'),
        'fp': s('fp'),
        'alpn': s('alpn'),
        'allowinsecure': s('allowInsecure'),
      };
      if (net == 'grpc') {
        params['servicename'] = s('path');
        params['mode'] = s('type') == 'multi' ? 'multi' : '';
      }

      final outbound = <String, dynamic>{
        'tag': 'proxy',
        'protocol': 'vmess',
        'settings': {
          'vnext': [
            {
              'address': host,
              'port': port,
              'users': [
                {
                  'id': id,
                  'alterId': int.tryParse(s('aid')) ?? 0,
                  'security': s('scy').isEmpty ? 'auto' : s('scy'),
                  'level': 8,
                }
              ],
            }
          ],
        },
        'streamSettings': _stream(params, host: host),
      };
      final remark = s('ps').isNotEmpty ? s('ps') : (fragment.isNotEmpty ? fragment : '$host:$port');
      return ConvertedConfig(remark, 'VMESS', _wrap(outbound));
    }

    // فرمت vmess://uuid@host:port?...
    final p = splitLink(link);
    if (p == null || p.userInfo.isEmpty) return null;
    final outbound = <String, dynamic>{
      'tag': 'proxy',
      'protocol': 'vmess',
      'settings': {
        'vnext': [
          {
            'address': p.host,
            'port': p.port,
            'users': [
              {'id': p.userInfo, 'alterId': 0, 'security': _p(p.params, 'encryption', 'auto'), 'level': 8}
            ],
          }
        ],
      },
      'streamSettings': _stream(p.params, host: p.host),
    };
    return ConvertedConfig(_remarkOrDefault(p), 'VMESS', _wrap(outbound));
  }

  static ConvertedConfig? _shadowsocks(String link) {
    var rest = link.substring('ss://'.length).trim();
    var fragment = '';
    final hashIdx = rest.indexOf('#');
    if (hashIdx >= 0) {
      fragment = safeDecode(rest.substring(hashIdx + 1)).trim();
      rest = rest.substring(0, hashIdx);
    }
    final qIdx = rest.indexOf('?');
    if (qIdx >= 0) rest = rest.substring(0, qIdx);
    while (rest.endsWith('/')) {
      rest = rest.substring(0, rest.length - 1);
    }

    String? creds;
    String? hostPart;

    if (rest.contains('@')) {
      final at = rest.lastIndexOf('@');
      final userPart = rest.substring(0, at);
      hostPart = rest.substring(at + 1);
      creds = userPart.contains(':') ? safeDecode(userPart) : decodeBase64Loose(userPart);
    } else {
      final decoded = decodeBase64Loose(rest);
      if (decoded == null) return null;
      final at = decoded.lastIndexOf('@');
      if (at < 0) return null;
      creds = decoded.substring(0, at);
      hostPart = decoded.substring(at + 1);
    }

    if (creds == null) return null;
    final colon = creds.indexOf(':');
    if (colon <= 0) return null;
    final method = creds.substring(0, colon);
    final password = creds.substring(colon + 1);

    final hp = parseHostPort(hostPart);
    if (hp == null) return null;

    final outbound = <String, dynamic>{
      'tag': 'proxy',
      'protocol': 'shadowsocks',
      'settings': {
        'servers': [
          {
            'address': hp.key,
            'port': hp.value,
            'method': method,
            'password': password,
            'level': 8,
          }
        ],
      },
    };
    final remark = fragment.isNotEmpty ? fragment : '${hp.key}:${hp.value}';
    return ConvertedConfig(remark, 'SHADOWSOCKS', _wrap(outbound));
  }
}

// ---------------------------------------------------------------------------
//  استخراج سرورها از متن سابسکریپشن
// ---------------------------------------------------------------------------

class ExtractedEntries {
  final List<String> links = [];
  final List<Map<String, dynamic>> jsonConfigs = [];
  bool looksLikeHtml = false;
  bool looksLikeClash = false;
}

ExtractedEntries extractEntries(String body, {int depth = 0}) {
  final out = ExtractedEntries();
  final text = body.replaceAll('\uFEFF', '').trim();
  if (text.isEmpty) return out;

  // ۱) JSON (کانفیگ کامل Xray یا لیستی از کانفیگ‌ها)
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      final j = jsonDecode(text);
      final list = j is List ? j : [j];
      for (final e in list) {
        if (e is Map && e['outbounds'] is List) {
          out.jsonConfigs.add(Map<String, dynamic>.from(e));
        }
      }
      if (out.jsonConfigs.isNotEmpty) return out;
    } catch (_) {}
  }

  // ۲) صفحهٔ HTML (یعنی لینک اشتباهه یا پنل کانفیگ نداده)
  final head = text.substring(0, min(300, text.length)).toLowerCase();
  if (head.contains('<html') || head.contains('<!doctype')) {
    out.looksLikeHtml = true;
    return out;
  }

  // ۳) Clash
  if (RegExp(r'^\s*proxies\s*:', multiLine: true).hasMatch(text)) {
    out.looksLikeClash = true;
    return out;
  }

  // ۴) متن ساده شامل لینک‌ها
  if (text.contains('://')) {
    final schemeChars = RegExp(r'[A-Za-z0-9+.\-]');
    for (final raw in text.split(RegExp(r'[\r\n]+'))) {
      final line = raw.trim();
      if (line.isEmpty) continue;
      final count = '://'.allMatches(line).length;
      if (count == 0) continue;

      if (count == 1) {
        final idx = line.indexOf('://');
        var start = idx;
        while (start > 0 && schemeChars.hasMatch(line[start - 1])) {
          start--;
        }
        if (start < idx) out.links.add(line.substring(start));
      } else {
        // چند لینک توی یک خط
        for (final m in RegExp(r'[A-Za-z][A-Za-z0-9+.\-]*://\S+').allMatches(line)) {
          out.links.add(m.group(0)!);
        }
      }
    }
    if (out.links.isNotEmpty) return out;
  }

  // ۵) base64
  if (depth < 2) {
    final decoded = LinkParser.decodeBase64Loose(text);
    if (decoded != null && decoded.trim().isNotEmpty) {
      return extractEntries(decoded, depth: depth + 1);
    }
  }
  return out;
}

class ImportReport {
  final List<ServerItem> servers = [];
  int failed = 0;
  final Map<String, int> unsupported = {};
  bool looksLikeHtml = false;
  bool looksLikeClash = false;
  String rawPreview = '';
  int httpStatus = 0;
  String? error;

  int get added => servers.length;
  bool get hasProblems =>
      error != null || failed > 0 || unsupported.isNotEmpty || looksLikeHtml || looksLikeClash || added == 0;
}

String _schemeOf(String link) {
  final i = link.indexOf('://');
  return i <= 0 ? '' : link.substring(0, i).toLowerCase();
}

ImportReport buildImport(String body, {required String subId, required String subName}) {
  final report = ImportReport();
  final trimmed = body.trim();
  report.rawPreview = trimmed.length > 600 ? trimmed.substring(0, 600) : trimmed;

  final extracted = extractEntries(body);
  report.looksLikeHtml = extracted.looksLikeHtml;
  report.looksLikeClash = extracted.looksLikeClash;

  final stamp = DateTime.now().microsecondsSinceEpoch;
  var index = 0;

  // JSON configs
  for (final cfg in extracted.jsonConfigs) {
    try {
      final outbounds = cfg['outbounds'] as List;
      Map? main;
      for (final o in outbounds) {
        if (o is Map && o['tag'] == 'proxy') main = o;
      }
      main ??= outbounds.firstWhere(
        (o) => o is Map && !['freedom', 'blackhole', 'dns'].contains(o['protocol']),
        orElse: () => null,
      ) as Map?;

      cfg['inbounds'] = LinkParser.standardInbounds();
      final remark = (cfg['remarks'] ?? cfg['remark'] ?? cfg['ps'] ?? '').toString().trim();
      final protocol = (main?['protocol'] ?? 'V2RAY').toString().toUpperCase();
      index++;
      report.servers.add(ServerItem(
        id: '${subId}_${stamp}_$index',
        rawUrl: '',
        remark: remark.isEmpty ? 'Server $index' : remark,
        protocol: protocol,
        subId: subId,
        subName: subName,
        fullJsonConfig: jsonEncode(cfg),
      ));
    } catch (_) {
      report.failed++;
    }
  }

  // لینک‌ها
  final seen = <String>{};
  for (final link in extracted.links) {
    if (!seen.add(link)) continue;
    final scheme = _schemeOf(link);
    if (scheme == 'http' || scheme == 'https') continue;

    if (!kSupportedSchemes.contains(scheme)) {
      report.unsupported[scheme] = (report.unsupported[scheme] ?? 0) + 1;
      continue;
    }

    String? fullConfig;
    String remark = '';
    String protocol = scheme.toUpperCase();

    // لینک‌هایی که پارسر پلاگین احتمالاً نمی‌فهمه، اول با پارسر خودمون
    final preferOwn = RegExp(r'(type|net)=(xhttp|splithttp|httpupgrade|raw)', caseSensitive: false).hasMatch(link);

    void tryPlugin() {
      if (fullConfig != null) return;
      try {
        final parser = FlutterV2ray.parseFromURL(link);
        fullConfig = parser.getFullConfiguration();
        remark = parser.remark.trim();
      } catch (_) {}
    }

    void tryOwn() {
      if (fullConfig != null) return;
      final c = LinkParser.convert(link);
      if (c != null) {
        fullConfig = jsonEncode(c.config);
        remark = c.remark;
        protocol = c.protocol;
      }
    }

    if (preferOwn) {
      tryOwn();
      tryPlugin();
    } else {
      tryPlugin();
      tryOwn();
    }

    if (fullConfig == null) {
      report.failed++;
      continue;
    }

    index++;
    report.servers.add(ServerItem(
      id: '${subId}_${stamp}_$index',
      rawUrl: link,
      remark: remark.isEmpty ? '$protocol $index' : remark,
      protocol: protocol == 'SS' ? 'SHADOWSOCKS' : protocol,
      subId: subId,
      subName: subName,
      fullJsonConfig: fullConfig!,
    ));
  }
  return report;
}

// ---------------------------------------------------------------------------
//  دریافت سابسکریپشن از اینترنت
// ---------------------------------------------------------------------------

class FetchResult {
  int status = 0;
  String body = '';
  Map<String, String> headers = {};
  String? error;
}

Future<FetchResult> fetchSubscription(String url, String userAgent, String hwid) async {
  final r = FetchResult();
  final client = HttpClient();
  client.connectionTimeout = const Duration(seconds: 15);
  client.badCertificateCallback = (cert, host, port) => true;
  try {
    final req = await client.getUrl(Uri.parse(url.trim()));
    req.headers.set('User-Agent', userAgent);
    req.headers.set('Accept', '*/*');
    req.headers.set('x-hwid', hwid);
    req.headers.set('x-device-os', 'Android');
    final resp = await req.close().timeout(const Duration(seconds: 30));
    r.status = resp.statusCode;
    resp.headers.forEach((name, values) {
      r.headers[name.toLowerCase()] = values.join(',');
    });
    final bb = BytesBuilder();
    await for (final chunk in resp) {
      bb.add(chunk);
      if (bb.length > 8 * 1024 * 1024) break;
    }
    r.body = utf8.decode(bb.toBytes(), allowMalformed: true);
  } catch (e) {
    r.error = e.toString();
  } finally {
    client.close(force: true);
  }
  return r;
}

// ---------------------------------------------------------------------------
//  استخراج endpoint برای TCP Ping
// ---------------------------------------------------------------------------

ServerEndpoint? extractServerEndpoint(String rawConfig) {
  try {
    final decoded = jsonDecode(rawConfig);
    if (decoded is! Map<String, dynamic>) return null;
    final outbounds = decoded['outbounds'];
    if (outbounds is! List) return null;

    for (final outbound in outbounds) {
      if (outbound is! Map) continue;
      final protocol = (outbound['protocol'] ?? '').toString().toLowerCase();
      if (protocol.isEmpty || protocol == 'freedom' || protocol == 'blackhole' || protocol == 'dns') {
        continue;
      }
      final settings = outbound['settings'];
      if (settings is! Map) continue;

      for (final key in ['vnext', 'servers']) {
        final endpoints = settings[key];
        if (endpoints is! List) continue;
        for (final item in endpoints) {
          if (item is! Map) continue;
          final host = (item['address'] ?? '').toString().trim();
          final portValue = item['port'];
          final port = portValue is int ? portValue : int.tryParse('$portValue');
          if (host.isNotEmpty && port != null && port > 0 && port <= 65535) {
            return ServerEndpoint(host, port);
          }
        }
      }
    }
  } catch (_) {
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
//  مدل‌ها
// ---------------------------------------------------------------------------

class ServerItem {
  String id;
  String rawUrl;
  String remark;
  String protocol;
  String subId;
  String subName;
  String fullJsonConfig;
  int? realPing; // تأخیر واقعی از هسته Xray، -1 = ناموفق
  int? tcpPing; // زمان برقراری TCP، -1 = ناموفق
  bool isPingingReal;
  bool isPingingTcp;

  bool get isPinging => isPingingReal || isPingingTcp;

  ServerItem({
    required this.id,
    required this.rawUrl,
    required this.remark,
    required this.protocol,
    required this.subId,
    required this.subName,
    required this.fullJsonConfig,
    this.realPing,
    this.tcpPing,
    this.isPingingReal = false,
    this.isPingingTcp = false,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'rawUrl': rawUrl,
        'remark': remark,
        'protocol': protocol,
        'subId': subId,
        'subName': subName,
        'fullJsonConfig': fullJsonConfig,
        'realPing': realPing,
        'tcpPing': tcpPing,
      };

  factory ServerItem.fromJson(Map<String, dynamic> json) => ServerItem(
        id: json['id'] ?? DateTime.now().microsecondsSinceEpoch.toString(),
        rawUrl: json['rawUrl'] ?? '',
        remark: json['remark'] ?? 'سرور',
        protocol: json['protocol'] ?? 'V2RAY',
        subId: json['subId'] ?? 'manual',
        subName: json['subName'] ?? 'دستی',
        fullJsonConfig: json['fullJsonConfig'] ?? '',
        realPing: json['realPing'] is int ? json['realPing'] as int : null,
        tcpPing: json['tcpPing'] is int ? json['tcpPing'] as int : null,
      );
}

class SubscriptionItem {
  String id;
  String name;
  String url;
  int updatedAt; // epoch ms، صفر یعنی هرگز
  int serverCount;
  bool isUpdating;
  bool autoName;
  int usedBytes;
  int totalBytes;
  int expireSec;
  String? lastError;

  SubscriptionItem({
    required this.id,
    required this.name,
    required this.url,
    this.updatedAt = 0,
    this.serverCount = 0,
    this.isUpdating = false,
    this.autoName = false,
    this.usedBytes = 0,
    this.totalBytes = 0,
    this.expireSec = 0,
    this.lastError,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'url': url,
        'updatedAt': updatedAt,
        'serverCount': serverCount,
        'autoName': autoName,
        'usedBytes': usedBytes,
        'totalBytes': totalBytes,
        'expireSec': expireSec,
      };

  factory SubscriptionItem.fromJson(Map<String, dynamic> json) => SubscriptionItem(
        id: json['id'] ?? '',
        name: json['name'] ?? 'اشتراک',
        url: json['url'] ?? '',
        updatedAt: json['updatedAt'] is int ? json['updatedAt'] : 0,
        serverCount: json['serverCount'] ?? 0,
        autoName: json['autoName'] ?? false,
        usedBytes: json['usedBytes'] ?? 0,
        totalBytes: json['totalBytes'] ?? 0,
        expireSec: json['expireSec'] ?? 0,
      );
}

// ---------------------------------------------------------------------------
//  توابع کمکی نمایش
// ---------------------------------------------------------------------------

String fmtBytes(num bytes, {bool isSpeed = false}) {
  final suffix = isSpeed ? '/s' : '';
  if (bytes < 1024) return '${bytes.toInt()} B$suffix';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB$suffix';
  if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB$suffix';
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB$suffix';
}

String fmtAgo(int ms) {
  if (ms <= 0) return 'هرگز';
  final d = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(ms));
  if (d.inMinutes < 1) return 'همین الان';
  if (d.inMinutes < 60) return '${d.inMinutes} دقیقه پیش';
  if (d.inHours < 24) return '${d.inHours} ساعت پیش';
  return '${d.inDays} روز پیش';
}

Color pingColor(int ping) {
  if (ping < 0) return Colors.red;
  if (ping < 300) return Colors.green;
  if (ping < 800) return Colors.orange;
  return Colors.red;
}

// ---------------------------------------------------------------------------
//  اپ
// ---------------------------------------------------------------------------

class ShainVPNApp extends StatefulWidget {
  const ShainVPNApp({super.key});

  @override
  State<ShainVPNApp> createState() => _ShainVPNAppState();
}

class _ShainVPNAppState extends State<ShainVPNApp> {
  AppThemeModeSetting currentTheme = AppThemeModeSetting.dark;

  @override
  void initState() {
    super.initState();
    loadSavedTheme();
  }

  Future<void> loadSavedTheme() async {
    final prefs = await SharedPreferences.getInstance();
    final themeIndex = prefs.getInt('saved_theme_mode') ?? 0;
    if (!mounted) return;
    setState(() {
      currentTheme = AppThemeModeSetting.values[themeIndex.clamp(0, AppThemeModeSetting.values.length - 1)];
    });
  }

  Future<void> setTheme(AppThemeModeSetting mode) async {
    setState(() => currentTheme = mode);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('saved_theme_mode', mode.index);
  }

  ThemeData getThemeData() {
    late final ThemeData baseTheme;
    switch (currentTheme) {
      case AppThemeModeSetting.light:
        baseTheme = ThemeData(
          brightness: Brightness.light,
          scaffoldBackgroundColor: const Color(0xFFF4F4F6),
          cardColor: const Color(0xFFFFFFFF),
          colorScheme: const ColorScheme.light(
            primary: Color(0xFF0061FF),
            secondary: Color(0xFF00C853),
            surface: Color(0xFFFFFFFF),
          ),
          navigationBarTheme: NavigationBarThemeData(
            backgroundColor: const Color(0xFFEFEFF2),
            indicatorColor: const Color(0xFF0061FF).withOpacity(0.2),
          ),
        );
        break;
      case AppThemeModeSetting.cream:
        baseTheme = ThemeData(
          brightness: Brightness.light,
          scaffoldBackgroundColor: const Color(0xFFF7F4EE),
          cardColor: const Color(0xFFFFFFFF),
          colorScheme: const ColorScheme.light(
            primary: Color(0xFF8D6E63),
            secondary: Color(0xFF66BB6A),
            surface: Color(0xFFFFFFFF),
          ),
          navigationBarTheme: NavigationBarThemeData(
            backgroundColor: const Color(0xFFEFECE6),
            indicatorColor: const Color(0xFF8D6E63).withOpacity(0.2),
          ),
        );
        break;
      case AppThemeModeSetting.dark:
        baseTheme = ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: const Color(0xFF000000),
          cardColor: const Color(0xFF17171A),
          colorScheme: const ColorScheme.dark(
            primary: Color(0xFF3E82F7),
            secondary: Color(0xFF00E676),
            surface: Color(0xFF17171A),
          ),
          navigationBarTheme: NavigationBarThemeData(
            backgroundColor: const Color(0xFF121214),
            indicatorColor: const Color(0xFF3E82F7).withOpacity(0.25),
          ),
        );
        break;
    }

    // Vazirmatn is a modern Vazir-family Persian font. google_fonts caches it
    // after the first successful download, so no font binary is embedded here.
    return baseTheme.copyWith(
      textTheme: GoogleFonts.vazirmatnTextTheme(baseTheme.textTheme),
      primaryTextTheme: GoogleFonts.vazirmatnTextTheme(baseTheme.primaryTextTheme),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'ShainVPN',
      theme: getThemeData(),
      home: MainShell(onThemeChanged: setTheme, currentTheme: currentTheme),
    );
  }
}

class MainShell extends StatefulWidget {
  final Function(AppThemeModeSetting) onThemeChanged;
  final AppThemeModeSetting currentTheme;

  const MainShell({
    super.key,
    required this.onThemeChanged,
    required this.currentTheme,
  });

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  late final FlutterV2ray flutterV2ray;
  V2RayStatus v2rayStatus = V2RayStatus();
  String coreVersion = '...';

  int currentTab = 0;
  List<ServerItem> servers = [];
  List<SubscriptionItem> subscriptions = [];
  String selectedServerId = '';
  String selectedGroupFilter = 'ALL';
  String searchQuery = '';
  bool sortByPing = false;
  PingMode selectedPingMode = PingMode.real;
  bool isTestingAll = false;
  int pingTestsCompleted = 0;
  int pingTestsTotal = 0;

  bool isProxyOnly = false;
  bool bypassLan = true;
  bool bypassIran = true;
  bool enableMux = false;
  bool autoUpdateSubs = true;
  String selectedDns = '1.1.1.1';
  String hwid = '';

  bool get isConnected => v2rayStatus.state == 'CONNECTED';
  bool get isConnecting => v2rayStatus.state == 'CONNECTING';

  @override
  void initState() {
    super.initState();
    kQuickControlsChannel.setMethodCallHandler((call) async {
      if (call.method == 'quickToggleVpn' && mounted) {
        await _consumePendingQuickAction();
      }
    });
    flutterV2ray = FlutterV2ray(
      onStatusChanged: (status) {
        if (mounted) setState(() => v2rayStatus = status);
        unawaited(_syncNativeConnectionState(status.state == 'CONNECTED', status.state));
      },
    );
    initEngineAndLoadData();
  }

  Future<void> initEngineAndLoadData() async {
    try {
      await flutterV2ray.initializeV2Ray();
    } catch (e) {
      if (mounted) showSnack('راه‌اندازی هسته VPN ناموفق بود: $e');
    }
    String ver = '';
    try {
      ver = await flutterV2ray.getCoreVersion();
    } catch (_) {}
    await loadPersistentData();
    if (!mounted) return;
    setState(() => coreVersion = ver.isEmpty ? '-' : ver);
    await _syncNativeConnectionState(isConnected, v2rayStatus.state);
    await _consumePendingQuickAction();
    _autoUpdateOldSubscriptions();
  }

  Future<void> _syncNativeConnectionState(bool connected, String status) async {
    try {
      await kQuickControlsChannel.invokeMethod<void>('setConnectionState', {
        'connected': connected,
        'status': status,
      });
    } catch (_) {
      // Quick Settings and the launcher widget are Android-only extras.
    }
  }

  Future<void> _consumePendingQuickAction() async {
    try {
      final action = await kQuickControlsChannel.invokeMethod<String>('consumePendingAction');
      if (action == 'toggleVpn' && mounted) await toggleVpn();
    } catch (_) {}
  }

  // ------------------------------------------------------------------ ذخیره

  Future<void> savePersistentData() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('selectedServerId', selectedServerId);
      await prefs.setBool('isProxyOnly', isProxyOnly);
      await prefs.setBool('bypassLan', bypassLan);
      await prefs.setBool('bypassIran', bypassIran);
      await prefs.setBool('enableMux', enableMux);
      await prefs.setBool('autoUpdateSubs', autoUpdateSubs);
      await prefs.setString('selectedDns', selectedDns);
      await prefs.setString('pingMode', selectedPingMode.name);
      await prefs.setBool('sortByPing', sortByPing);
      await prefs.setString('hwid', hwid);

      final serversJson = servers.map((e) => jsonEncode(e.toJson())).toList();
      await prefs.setStringList('saved_servers_list', serversJson);

      final subsJson = subscriptions.map((e) => jsonEncode(e.toJson())).toList();
      await prefs.setStringList('saved_subs_list', subsJson);
    } catch (_) {}
  }

  Future<void> loadPersistentData() async {
    try {
      final prefs = await SharedPreferences.getInstance();

      var savedHwid = prefs.getString('hwid') ?? '';
      if (savedHwid.isEmpty) {
        final rnd = Random.secure();
        savedHwid = List.generate(16, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
      }

      final loadedServers = <ServerItem>[];
      for (final e in prefs.getStringList('saved_servers_list') ?? <String>[]) {
        try {
          loadedServers.add(ServerItem.fromJson(jsonDecode(e)));
        } catch (_) {}
      }
      final loadedSubs = <SubscriptionItem>[];
      for (final e in prefs.getStringList('saved_subs_list') ?? <String>[]) {
        try {
          loadedSubs.add(SubscriptionItem.fromJson(jsonDecode(e)));
        } catch (_) {}
      }

      if (!mounted) return;
      setState(() {
        hwid = savedHwid;
        selectedServerId = prefs.getString('selectedServerId') ?? '';
        isProxyOnly = prefs.getBool('isProxyOnly') ?? false;
        bypassLan = prefs.getBool('bypassLan') ?? true;
        bypassIran = prefs.getBool('bypassIran') ?? true;
        enableMux = prefs.getBool('enableMux') ?? false;
        autoUpdateSubs = prefs.getBool('autoUpdateSubs') ?? true;
        selectedDns = prefs.getString('selectedDns') ?? '1.1.1.1';
        selectedPingMode = PingMode.values.firstWhere(
          (mode) => mode.name == prefs.getString('pingMode'),
          orElse: () => PingMode.real,
        );
        sortByPing = prefs.getBool('sortByPing') ?? false;
        servers = loadedServers;
        subscriptions = loadedSubs;
        if (selectedServerId.isEmpty && servers.isNotEmpty) {
          selectedServerId = servers.first.id;
        }
      });
    } catch (_) {}
  }

  // ------------------------------------------------------------------ کانفیگ

  String buildCustomizedConfig(String rawJson) {
    try {
      final Map<String, dynamic> config = jsonDecode(rawJson);
      config['dns'] = {
        'servers': [selectedDns, '8.8.8.8', '1.1.1.1']
      };

      if (config['outbounds'] is List && (config['outbounds'] as List).isNotEmpty) {
        final List outbounds = config['outbounds'];
        if (outbounds[0] is Map) {
          outbounds[0]['mux'] = {
            'enabled': enableMux,
            'concurrency': enableMux ? 8 : -1,
          };
        }
        final hasDirect = outbounds.any((o) => o is Map && o['tag'] == 'direct');
        if (!hasDirect) {
          outbounds.add({'tag': 'direct', 'protocol': 'freedom', 'settings': {}});
        }
      }

      final List<dynamic> rules = [];
      if (bypassLan) {
        rules.add({
          'type': 'field',
          'ip': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'],
          'outboundTag': 'direct'
        });
      }
      if (bypassIran) {
        rules.add({
          'type': 'field',
          'domain': ['regexp:.*\\.ir\$'],
          'outboundTag': 'direct'
        });
        rules.add({
          'type': 'field',
          'ip': ['2.144.0.0/14', '5.52.0.0/16', '31.2.128.0/17', '37.98.0.0/16', '78.38.0.0/15', '79.127.0.0/16'],
          'outboundTag': 'direct'
        });
      }

      if (rules.isNotEmpty) {
        config['routing'] = {
          'domainStrategy': 'IPIfNonMatch',
          'rules': rules,
        };
        // برای اینکه قانون دامنه (.ir) کار کنه، sniffing باید روشن باشه
        if (config['inbounds'] is List) {
          for (final inb in config['inbounds']) {
            if (inb is Map) {
              inb['sniffing'] = {
                'enabled': true,
                'destOverride': ['http', 'tls'],
                'routeOnly': false,
              };
            }
          }
        }
      }

      return jsonEncode(config);
    } catch (_) {
      return rawJson;
    }
  }

  ServerItem? get selectedServer {
    if (servers.isEmpty) return null;
    try {
      return servers.firstWhere((s) => s.id == selectedServerId);
    } catch (_) {
      return servers.first;
    }
  }

  // ------------------------------------------------------------------ اتصال

  Future<void> toggleVpn() async {
    if (isTestingAll) {
      showSnack('تا پایان تست پینگ، کنترل اتصال موقتاً غیرفعال است.');
      return;
    }
    if (isConnected || isConnecting) {
      await flutterV2ray.stopV2Ray();
      return;
    }

    final target = selectedServer;
    if (target == null) {
      showSnack('لطفاً ابتدا یک سرور اضافه یا انتخاب کنید!');
      return;
    }

    if (!isProxyOnly && !await flutterV2ray.requestPermission()) {
      showSnack('مجوز ساخت تونل VPN صادر نشد!');
      return;
    }

    final finalConfig = buildCustomizedConfig(target.fullJsonConfig);
    try {
      await flutterV2ray.startV2Ray(
        remark: target.remark,
        config: finalConfig,
        proxyOnly: isProxyOnly,
        bypassSubnets: null,
      );
    } catch (e) {
      showSnack('اتصال ناموفق بود: $e');
    }
  }

  Future<void> reconnectIfNeeded() async {
    if (!isConnected && !isConnecting) return;
    await flutterV2ray.stopV2Ray();
    for (var i = 0; i < 25 && v2rayStatus.state != 'DISCONNECTED'; i++) {
      await Future.delayed(const Duration(milliseconds: 150));
    }
    await toggleVpn();
  }

  // ------------------------------------------------------------------ سابسکریپشن

  Future<void> updateSubscription(SubscriptionItem sub, {bool silent = false}) async {
    if (sub.isUpdating) return;
    setState(() {
      sub.isUpdating = true;
      sub.lastError = null;
    });

    ImportReport? best;
    FetchResult? bestFetch;
    String? networkError;

    for (final ua in kUserAgents) {
      final res = await fetchSubscription(sub.url, ua, hwid);
      if (res.error != null) {
        networkError = res.error;
        break; // مشکل شبکه است، تغییر User-Agent کمکی نمی‌کنه
      }
      if (res.status != 200) {
        best ??= ImportReport()..httpStatus = res.status;
        best.httpStatus = res.status;
        continue;
      }
      final report = buildImport(res.body, subId: sub.id, subName: sub.name);
      report.httpStatus = res.status;
      if (best == null || report.added > best.added || best.httpStatus != 200) {
        best = report;
        bestFetch = res;
      }
      if (report.added > 0 && report.failed == 0 && report.unsupported.isEmpty) break;
    }

    if (!mounted) return;

    if (networkError != null && best == null) {
      setState(() {
        sub.isUpdating = false;
        sub.lastError = networkError;
      });
      if (!silent) showSnack('خطا در اتصال به سابسکریپشن ❌');
      return;
    }

    final report = best ?? ImportReport();

    if (report.added > 0) {
      // سرور انتخاب‌شدهٔ قبلی رو اگه هنوز هست نگه می‌داریم
      final prev = selectedServer;
      final prevRemark = (prev != null && prev.subId == sub.id) ? prev.remark : null;

      servers.removeWhere((s) => s.subId == sub.id);
      servers.addAll(report.servers);

      if (prevRemark != null) {
        for (final s in report.servers) {
          if (s.remark == prevRemark) selectedServerId = s.id;
        }
      }
      if (!servers.any((s) => s.id == selectedServerId) && servers.isNotEmpty) {
        selectedServerId = servers.first.id;
      }
    } else {
      sub.lastError = report.httpStatus != 200 && report.httpStatus != 0
          ? 'پاسخ سرور: ${report.httpStatus}'
          : 'سروری پیدا نشد';
    }

    // اطلاعات حجم و انقضا از هدرها
    if (bestFetch != null) {
      final info = bestFetch.headers['subscription-userinfo'];
      if (info != null) {
        for (final part in info.split(';')) {
          final kv = part.trim().split('=');
          if (kv.length != 2) continue;
          final value = double.tryParse(kv[1].trim())?.toInt() ?? 0;
          switch (kv[0].trim().toLowerCase()) {
            case 'upload':
              sub.usedBytes = value;
              break;
            case 'download':
              sub.usedBytes = (sub.usedBytes) + value;
              break;
            case 'total':
              sub.totalBytes = value;
              break;
            case 'expire':
              sub.expireSec = value;
              break;
          }
        }
      }
      final title = bestFetch.headers['profile-title'];
      if (title != null && title.isNotEmpty && sub.autoName) {
        var t = title.trim();
        if (t.toLowerCase().startsWith('base64:')) {
          t = LinkParser.decodeBase64Loose(t.substring(7)) ?? t;
        }
        if (t.isNotEmpty) {
          sub.name = t;
          for (final s in servers.where((s) => s.subId == sub.id)) {
            s.subName = t;
          }
        }
      }
    }

    setState(() {
      sub.isUpdating = false;
      if (report.added > 0) {
        sub.serverCount = report.added;
        sub.updatedAt = DateTime.now().millisecondsSinceEpoch;
      }
    });
    await savePersistentData();

    if (silent) return;
    if (report.hasProblems) {
      _showReportDialog(sub.name, report);
    } else {
      showSnack('اشتراک «${sub.name}» آپدیت شد: ${report.added} سرور ✅');
    }
  }

  Future<void> updateAllSubscriptions() async {
    if (subscriptions.isEmpty) {
      showSnack('هیچ سابسکریپشنی ثبت نشده است!');
      return;
    }
    for (final sub in List<SubscriptionItem>.from(subscriptions)) {
      await updateSubscription(sub);
    }
  }

  Future<void> _autoUpdateOldSubscriptions() async {
    if (!autoUpdateSubs) return;
    final cutoff = DateTime.now().subtract(const Duration(hours: 6)).millisecondsSinceEpoch;
    for (final sub in List<SubscriptionItem>.from(subscriptions)) {
      if (sub.updatedAt < cutoff) {
        await updateSubscription(sub, silent: true);
      }
    }
  }

  // ------------------------------------------------------------------ افزودن

  Future<void> importFromClipboard() async {
    final ClipboardData? data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (text.isEmpty) {
      showSnack('کلیپ‌بورد خالی است! 📋');
      return;
    }
    await processInput(text);
  }

  Future<void> processInput(String input, {String? name}) async {
    final text = input.trim();
    if (text.isEmpty) return;

    final isUrl = RegExp(r'^https?://\S+$', caseSensitive: false).hasMatch(text);
    if (isUrl) {
      final existing = subscriptions.where((s) => s.url == text);
      if (existing.isNotEmpty) {
        showSnack('این اشتراک قبلاً اضافه شده، در حال آپدیت...');
        await updateSubscription(existing.first);
        return;
      }

      var subName = (name ?? '').trim();
      var auto = false;
      if (subName.isEmpty) {
        final frag = Uri.tryParse(text)?.fragment ?? '';
        subName = frag.isNotEmpty ? LinkParser.safeDecode(frag) : 'اشتراک ${subscriptions.length + 1}';
        auto = frag.isEmpty;
      }

      final sub = SubscriptionItem(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        name: subName,
        url: text,
        autoName: auto,
      );
      setState(() => subscriptions.add(sub));
      await savePersistentData();
      await updateSubscription(sub);
      return;
    }

    // لینک مستقیم سرور (یک یا چند تا) یا متن base64
    final report = buildImport(text, subId: 'manual', subName: 'دستی');
    final existingUrls = servers.where((s) => s.subId == 'manual').map((s) => s.rawUrl).toSet();
    final fresh = report.servers.where((s) => s.rawUrl.isEmpty || !existingUrls.contains(s.rawUrl)).toList();

    if (fresh.isNotEmpty) {
      setState(() {
        servers.addAll(fresh);
        if (selectedServerId.isEmpty) selectedServerId = fresh.first.id;
      });
      await savePersistentData();
    }

    if (report.failed > 0 || report.unsupported.isNotEmpty || report.added == 0) {
      _showReportDialog('افزودن دستی', report);
    } else if (fresh.isEmpty) {
      showSnack('این سرورها قبلاً اضافه شده بودن');
    } else {
      showSnack('${fresh.length} سرور اضافه شد! 🎉');
    }
  }

  void _showAddSheet() {
    final textCtrl = TextEditingController();
    final nameCtrl = TextEditingController();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: Padding(
          padding: EdgeInsets.fromLTRB(16, 0, 16, MediaQuery.of(ctx).viewInsets.bottom + 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('افزودن سرور یا اشتراک', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              const Text(
                'لینک سابسکریپشن (https://...) یا لینک مستقیم سرور (vless:// vmess:// trojan:// ss://) رو وارد کن. چند لینک رو هم می‌تونی با هم بچسبونی.',
                style: TextStyle(color: Colors.grey, fontSize: 12),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: textCtrl,
                minLines: 3,
                maxLines: 6,
                textDirection: TextDirection.ltr,
                decoration: InputDecoration(
                  border: const OutlineInputBorder(),
                  hintText: 'https://...  یا  vless://...',
                  suffixIcon: IconButton(
                    icon: const Icon(Icons.content_paste_rounded),
                    tooltip: 'چسباندن',
                    onPressed: () async {
                      final d = await Clipboard.getData(Clipboard.kTextPlain);
                      if (d?.text != null) textCtrl.text = d!.text!.trim();
                    },
                  ),
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: nameCtrl,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  labelText: 'نام اشتراک (اختیاری)',
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                icon: const Icon(Icons.add_rounded),
                label: const Text('افزودن'),
                onPressed: () {
                  final t = textCtrl.text;
                  final n = nameCtrl.text;
                  if (t.trim().isEmpty) return;
                  Navigator.pop(ctx);
                  processInput(t, name: n);
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ------------------------------------------------------------------ گزارش

  void _showReportDialog(String title, ImportReport r) {
    if (!mounted) return;
    final lines = <String>[];

    if (r.added > 0) lines.add('✅ ${r.added} سرور خوانده شد');
    if (r.failed > 0) lines.add('⚠️ ${r.failed} لینک خراب بود یا قابل پردازش نبود');
    if (r.unsupported.isNotEmpty) {
      final parts = r.unsupported.entries.map((e) => '${e.key} (${e.value})').join('، ');
      lines.add('🚫 پروتکل پشتیبانی‌نشده: $parts');
      lines.add('هستهٔ Xray فقط vless / vmess / trojan / shadowsocks رو اجرا می‌کنه. پروتکل‌هایی مثل hysteria2 و tuic به هستهٔ sing-box نیاز دارن.');
    }
    if (r.looksLikeHtml) {
      lines.add('🌐 سرور به‌جای کانفیگ، یک صفحهٔ وب برگردوند. لینک اشتباهه، منقضی شده، یا پنل نیاز به ثبت دستگاه (HWID) داره.');
    }
    if (r.looksLikeClash) {
      lines.add('📄 خروجی به فرمت Clash است که پشتیبانی نمی‌شه. از پنل لینک نسخهٔ v2ray/base64 بگیر.');
    }
    if (r.httpStatus != 0 && r.httpStatus != 200 && r.added == 0) {
      lines.add('❌ پاسخ سرور: کد ${r.httpStatus}');
    }
    if (r.added == 0 && r.unsupported.isEmpty && !r.looksLikeHtml && !r.looksLikeClash && r.httpStatus == 200) {
      lines.add('هیچ لینک معتبری توی خروجی پیدا نشد. نمونهٔ خروجی خام پایین نشون داده شده تا بشه بررسی کرد.');
    }

    showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: Text('نتیجه: $title'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final l in lines)
                  Padding(padding: const EdgeInsets.only(bottom: 8), child: Text(l)),
                if (r.rawPreview.isNotEmpty && r.added == 0) ...[
                  const SizedBox(height: 4),
                  const Text('خروجی خام:', style: TextStyle(color: Colors.grey, fontSize: 12)),
                  const SizedBox(height: 4),
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.black12,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: SelectableText(
                      r.rawPreview,
                      textDirection: TextDirection.ltr,
                      style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                    ),
                  ),
                ],
              ],
            ),
          ),
          actions: [
            if (r.rawPreview.isNotEmpty && r.added == 0)
              TextButton(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: r.rawPreview));
                  showSnack('کپی شد');
                },
                child: const Text('کپی خروجی خام'),
              ),
            FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('باشه')),
          ],
        ),
      ),
    );
  }

  // ------------------------------------------------------------------ پینگ

  Future<int> _measureTcpPing(ServerItem server) async {
    final endpoint = extractServerEndpoint(server.fullJsonConfig);
    if (endpoint == null) return -1;

    final stopwatch = Stopwatch()..start();
    Socket? socket;
    try {
      socket = await Socket.connect(
        endpoint.host,
        endpoint.port,
        timeout: const Duration(seconds: 4),
      );
      stopwatch.stop();
      return stopwatch.elapsedMilliseconds;
    } on SocketException {
      return -1;
    } on TimeoutException {
      return -1;
    } catch (_) {
      return -1;
    } finally {
      socket?.destroy();
    }
  }

  /// Measures request #2 through the same HttpClient connection and TLS session.
  /// A temporary Xray HTTP inbound forwards both requests through one core session.
  Future<int> _measureKeepAlivePing(ServerItem server) async {
    HttpClient? client;
    var coreStarted = false;
    var httpPort = 0;

    try {
      final config = jsonDecode(server.fullJsonConfig) as Map<String, dynamic>;
      final inbounds = config['inbounds'] is List
          ? List<dynamic>.from(config['inbounds'] as List)
          : <dynamic>[];

      // Ask the OS for an available local port, then release it for Xray to bind.
      final reservation = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      httpPort = reservation.port;
      await reservation.close();
      if (inbounds.any((item) => item is Map && item['port'] == httpPort)) {
        throw StateError('Temporary HTTP proxy port conflicts with an existing inbound');
      }

      inbounds.add({
        'tag': 'shain_keepalive_http_in',
        'listen': '127.0.0.1',
        'port': httpPort,
        'protocol': 'http',
        'settings': <String, dynamic>{},
      });
      config['inbounds'] = inbounds;

      // This temporary proxy-only core does not replace the Android VPN tunnel.
      coreStarted = true;
      await flutterV2ray.startV2Ray(
        remark: '${server.remark} • KeepAlive test',
        config: jsonEncode(config),
        proxyOnly: true,
        bypassSubnets: null,
      ).timeout(const Duration(seconds: 15));

      client = HttpClient();
      client!.findProxy = (_) => 'PROXY 127.0.0.1:$httpPort';
      client!
        ..connectionTimeout = const Duration(seconds: 8)
        ..idleTimeout = const Duration(seconds: 20)
        ..maxConnectionsPerHost = 1;

      Future<void> sendProbe() async {
        final request = await client!
            .getUrl(Uri.https('www.gstatic.com', '/generate_204'))
            .timeout(const Duration(seconds: 10));
        request.persistentConnection = true;
        request.headers.set(HttpHeaders.connectionHeader, 'keep-alive');
        request.headers.set(HttpHeaders.userAgentHeader, 'ShainVPN-KeepAlive/1.0');

        final response = await request.close().timeout(const Duration(seconds: 12));
        await response.drain<void>().timeout(const Duration(seconds: 5));
        if (response.statusCode != HttpStatus.noContent) {
          throw HttpException('KeepAlive probe returned HTTP ${response.statusCode}');
        }
      }

      // Give Xray a moment to bind the temporary HTTP inbound.
      await Future.delayed(const Duration(milliseconds: 250));

      // Request #1 establishes the route and TLS connection.
      await sendProbe();

      // Request #2 is sent by the same HttpClient, allowing TLS keep-alive reuse.
      final stopwatch = Stopwatch()..start();
      await sendProbe();
      stopwatch.stop();
      return stopwatch.elapsedMilliseconds;
    } catch (_) {
      return -1;
    } finally {
      client?.close(force: true);
      if (coreStarted) {
        try {
          await flutterV2ray.stopV2Ray();
        } catch (_) {}
      }
    }
  }

  Future<void> pingSingleServer(
    ServerItem server, {
    PingMode? mode,
    bool save = true,
  }) async {
    final testMode = mode ?? selectedPingMode;
    if (!mounted || server.isPinging) return;

    if (testMode == PingMode.real && (isConnected || isConnecting) && !isTestingAll) {
      showSnack('برای KeepAlive Ping ابتدا اتصال VPN را قطع کن.');
      return;
    }

    setState(() {
      if (testMode == PingMode.real) {
        server.isPingingReal = true;
      } else {
        server.isPingingTcp = true;
      }
    });

    var result = -1;
    try {
      if (testMode == PingMode.real) {
        result = await _measureKeepAlivePing(server);
      } else {
        result = await _measureTcpPing(server);
      }
    } catch (_) {
      result = -1;
    } finally {
      if (mounted) {
        setState(() {
          if (testMode == PingMode.real) {
            server.realPing = result;
            server.isPingingReal = false;
          } else {
            server.tcpPing = result;
            server.isPingingTcp = false;
          }
        });
      }
      if (save) await savePersistentData();
    }
  }

  Future<void> testAllPings() async {
    if (isTestingAll || servers.isEmpty) return;
    final mode = selectedPingMode;
    if (mode == PingMode.real && (isConnected || isConnecting)) {
      showSnack('برای اجرای KeepAlive Ping، ابتدا VPN را قطع کن.');
      return;
    }

    final list = List<ServerItem>.from(servers);
    setState(() {
      isTestingAll = true;
      pingTestsCompleted = 0;
      pingTestsTotal = list.length;
    });

    try {
      // Deliberately sequential: each config gets its own temporary core
      // session, so two server tests never compete for the local proxy ports.
      for (final server in list) {
        if (!mounted) break;
        await pingSingleServer(server, mode: mode, save: false);
        if (mounted) {
          setState(() => pingTestsCompleted++);
        }
        // Let Android finish releasing the previous temporary core session.
        if (mode == PingMode.real) {
          await Future.delayed(const Duration(milliseconds: 250));
        }
      }
    } finally {
      if (mounted) setState(() => isTestingAll = false);
      await savePersistentData();
    }
  }

  // ------------------------------------------------------------------ لیست‌ها

  List<ServerItem> get filteredServers {
    final list = servers.where((s) {
      final matchGroup = selectedGroupFilter == 'ALL' || s.subId == selectedGroupFilter;
      final matchSearch = searchQuery.isEmpty || s.remark.toLowerCase().contains(searchQuery.toLowerCase());
      return matchGroup && matchSearch;
    }).toList();

    if (sortByPing) {
      int? value(ServerItem server) => selectedPingMode == PingMode.real
          ? server.realPing
          : server.tcpPing;

      int rank(ServerItem server) {
        final ping = value(server);
        if (ping == null) return 1; // هنوز اندازه‌گیری نشده
        if (ping < 0) return 2; // ناموفق، در انتهای لیست
        return 0;
      }

      list.sort((a, b) {
        final rankCompare = rank(a).compareTo(rank(b));
        if (rankCompare != 0) return rankCompare;
        return (value(a) ?? 0).compareTo(value(b) ?? 0);
      });
    }
    return list;
  }

  void deleteServer(ServerItem s) {
    setState(() {
      servers.removeWhere((x) => x.id == s.id);
      if (selectedServerId == s.id) {
        selectedServerId = servers.isNotEmpty ? servers.first.id : '';
      }
    });
    savePersistentData();
  }

  Future<void> deleteSubscription(SubscriptionItem sub) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('حذف اشتراک'),
          content: Text('اشتراک «${sub.name}» و تمام سرورهاش حذف بشن؟'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('لغو')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('حذف')),
          ],
        ),
      ),
    );
    if (ok != true) return;
    setState(() {
      servers.removeWhere((s) => s.subId == sub.id);
      subscriptions.removeWhere((s) => s.id == sub.id);
      if (selectedGroupFilter == sub.id) selectedGroupFilter = 'ALL';
      if (!servers.any((s) => s.id == selectedServerId)) {
        selectedServerId = servers.isNotEmpty ? servers.first.id : '';
      }
    });
    await savePersistentData();
  }

  Future<void> renameSubscription(SubscriptionItem sub) async {
    final ctrl = TextEditingController(text: sub.name);
    final newName = await showDialog<String>(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('تغییر نام'),
          content: TextField(controller: ctrl, autofocus: true),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('لغو')),
            FilledButton(onPressed: () => Navigator.pop(ctx, ctrl.text.trim()), child: const Text('ذخیره')),
          ],
        ),
      ),
    );
    if (newName == null || newName.isEmpty) return;
    setState(() {
      sub.name = newName;
      sub.autoName = false;
      for (final s in servers.where((s) => s.subId == sub.id)) {
        s.subName = newName;
      }
    });
    await savePersistentData();
  }

  void showSnack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg, textDirection: TextDirection.rtl),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
    );
  }

  // ------------------------------------------------------------------ UI

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.rtl,
      child: Scaffold(
        body: IndexedStack(
          index: currentTab,
          children: [
            _buildHomeTab(),
            _buildServersTab(),
            _buildSubscriptionsTab(),
            _buildSettingsTab(),
          ],
        ),
        bottomNavigationBar: NavigationBar(
          selectedIndex: currentTab,
          onDestinationSelected: (idx) => setState(() => currentTab = idx),
          destinations: [
            const NavigationDestination(icon: Icon(Icons.shield_outlined), label: 'اتصال'),
            NavigationDestination(
              icon: Badge(
                isLabelVisible: servers.isNotEmpty,
                label: Text('${servers.length}'),
                child: const Icon(Icons.dns_outlined),
              ),
              label: 'سرورها',
            ),
            NavigationDestination(
              icon: Badge(
                isLabelVisible: subscriptions.isNotEmpty,
                label: Text('${subscriptions.length}'),
                child: const Icon(Icons.rss_feed_rounded),
              ),
              label: 'سابسکریپشن',
            ),
            const NavigationDestination(icon: Icon(Icons.settings_outlined), label: 'تنظیمات'),
          ],
        ),
      ),
    );
  }

  Widget _buildHomeTab() {
    final activeServer = selectedServer;
    final statusText = isConnected
        ? 'متصل و امن 🔑'
        : isConnecting
            ? 'در حال اتصال...'
            : 'قطع است 💤';
    final statusColor = isConnected
        ? Colors.greenAccent
        : isConnecting
            ? Colors.orangeAccent
            : Colors.grey;

    return NestedScrollView(
      headerSliverBuilder: (context, _) => [
        SliverAppBar.large(
          title: const Text('ShainVPN 🛡️', style: TextStyle(fontWeight: FontWeight.w800)),
          actions: [
            IconButton(
              icon: const Icon(Icons.content_paste_go_rounded),
              onPressed: importFromClipboard,
              tooltip: 'افزودن سریع از کلیپ‌بورد',
            ),
          ],
        ),
      ],
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Theme.of(context).cardColor,
                borderRadius: BorderRadius.circular(30),
                border: Border.all(color: isConnected ? Colors.greenAccent.withOpacity(0.5) : Colors.white10),
              ),
              child: Column(
                children: [
                  Text(statusText, style: TextStyle(color: statusColor, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 20),
                  GestureDetector(
                    onTap: toggleVpn,
                    child: Container(
                      width: 140,
                      height: 140,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: isConnected
                            ? Colors.green
                            : isConnecting
                                ? Colors.orange
                                : Theme.of(context).colorScheme.primary,
                      ),
                      child: isConnecting
                          ? const Padding(
                              padding: EdgeInsets.all(44),
                              child: CircularProgressIndicator(color: Colors.white, strokeWidth: 3),
                            )
                          : Icon(
                              isConnected ? Icons.shield_rounded : Icons.power_settings_new_rounded,
                              size: 54,
                              color: Colors.white,
                            ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(v2rayStatus.duration, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                  const Divider(height: 30),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      _buildMetric('دانلود', fmtBytes(v2rayStatus.downloadSpeed, isSpeed: true)),
                      _buildMetric('آپلود', fmtBytes(v2rayStatus.uploadSpeed, isSpeed: true)),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Material(
              color: Theme.of(context).cardColor,
              borderRadius: BorderRadius.circular(22),
              child: InkWell(
                borderRadius: BorderRadius.circular(22),
                onTap: _showAddSheet,
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 22),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(22),
                    border: Border.all(
                      color: Theme.of(context).colorScheme.primary.withOpacity(0.35),
                      width: 1.2,
                    ),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 54,
                        height: 54,
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primary.withOpacity(0.12),
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Icon(
                          Icons.add_link_rounded,
                          size: 30,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                      const SizedBox(width: 14),
                      const Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'وارد کردن کانفیگ / ایمپورت کانفیگ',
                              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
                            ),
                            SizedBox(height: 5),
                            Text(
                              'لینک سرور، سابسکریپشن یا متن کانفیگ را وارد کن',
                              style: TextStyle(fontSize: 12, color: Colors.grey),
                            ),
                          ],
                        ),
                      ),
                      const Icon(Icons.chevron_left_rounded, size: 28),
                    ],
                  ),
                ),
              ),
            ),
            const SizedBox(height: 16),
            if (activeServer == null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Theme.of(context).cardColor,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Column(
                  children: [
                    const Icon(Icons.cloud_off_rounded, size: 40, color: Colors.grey),
                    const SizedBox(height: 8),
                    const Text('هنوز سروری اضافه نکردی'),
                    const SizedBox(height: 12),
                    FilledButton.icon(
                      onPressed: _showAddSheet,
                      icon: const Icon(Icons.add_rounded),
                      label: const Text('افزودن سرور یا اشتراک'),
                    ),
                  ],
                ),
              )
            else
              ListTile(
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                tileColor: Theme.of(context).cardColor,
                leading: const Icon(Icons.public_rounded),
                title: Text(activeServer.remark, maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text('${activeServer.protocol} • ${activeServer.subName}'),
                trailing: _pingSummary(activeServer),
                onTap: () => setState(() => currentTab = 1),
              ),
          ],
        ),
      ),
    );
  }

  Widget _pingChip(ServerItem server, PingMode mode) {
    final isReal = mode == PingMode.real;
    final ping = isReal ? server.realPing : server.tcpPing;
    final isBusy = isReal ? server.isPingingReal : server.isPingingTcp;
    final label = isReal ? 'KeepAlive' : 'TCP';
    final value = isBusy
        ? null
        : ping == null
            ? '—'
            : ping < 0
                ? 'خطا'
                : '$ping ms';
    final color = ping == null ? Colors.grey : pingColor(ping);

    return InkWell(
      borderRadius: BorderRadius.circular(10),
      onTap: server.isPinging ? null : () => pingSingleServer(server, mode: mode),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.10),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(label, style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w600)),
            const SizedBox(width: 4),
            if (isBusy)
              SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 1.5, color: color))
            else
              Text(value!, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }

  Widget _pingSummary(ServerItem server) {
    return Wrap(
      spacing: 5,
      runSpacing: 4,
      alignment: WrapAlignment.end,
      children: [
        _pingChip(server, PingMode.real),
        _pingChip(server, PingMode.tcp),
      ],
    );
  }

  Widget _buildServersTab() {
    final list = filteredServers;
    final hasManual = servers.any((s) => s.subId == 'manual');

    return Scaffold(
      appBar: AppBar(
        title: Text('سرورها (${list.length})'),
        actions: [
          isTestingAll
              ? const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 14),
                  child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                )
              : IconButton(icon: const Icon(Icons.bolt_rounded), tooltip: 'تست ترتیبی همهٔ سرورها با ${selectedPingMode == PingMode.real ? "KeepAlive" : "TCP"}', onPressed: testAllPings),
          IconButton(icon: const Icon(Icons.add_rounded), tooltip: 'افزودن', onPressed: _showAddSheet),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Row(
              children: [
                Expanded(
                  child: SegmentedButton<PingMode>(
                    segments: const [
                      ButtonSegment(value: PingMode.real, label: Text('KeepAlive Ping'), icon: Icon(Icons.bolt_rounded)),
                      ButtonSegment(value: PingMode.tcp, label: Text('TCP Ping'), icon: Icon(Icons.compare_arrows_rounded)),
                    ],
                    selected: {selectedPingMode},
                    onSelectionChanged: isTestingAll
                        ? null
                        : (values) {
                            setState(() => selectedPingMode = values.first);
                            savePersistentData();
                          },
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filledTonal(
                  tooltip: sortByPing ? 'لغو مرتب‌سازی پینگ' : 'مرتب‌سازی از کمترین پینگ',
                  onPressed: () => setState(() => sortByPing = !sortByPing),
                  icon: Icon(sortByPing ? Icons.sort_rounded : Icons.sort_by_alpha_rounded),
                ),
              ],
            ),
          ),
          if (isTestingAll)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  LinearProgressIndicator(
                    value: pingTestsTotal == 0 ? null : pingTestsCompleted / pingTestsTotal,
                  ),
                  const SizedBox(height: 5),
                  Text(
                    'پینگ ترتیبی $pingTestsCompleted از $pingTestsTotal سرور',
                    style: const TextStyle(fontSize: 11, color: Colors.grey),
                  ),
                ],
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 4, 18, 0),
            child: Text(
              selectedPingMode == PingMode.real
                  ? 'KeepAlive Ping: درخواست دوم روی همان اتصال TLS بازشده اندازه‌گیری می‌شود.'
                  : 'TCP Ping: زمان برقراری اتصال TCP به آدرس و پورت سرور.',
              style: const TextStyle(color: Colors.grey, fontSize: 11),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: TextField(
              onChanged: (v) => setState(() => searchQuery = v),
              decoration: InputDecoration(
                hintText: 'جستجو در سرورها',
                prefixIcon: const Icon(Icons.search_rounded),
                isDense: true,
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(16)),
              ),
            ),
          ),
          if (subscriptions.isNotEmpty || hasManual)
            SizedBox(
              height: 52,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                children: [
                  _groupChip('ALL', 'همه'),
                  for (final sub in subscriptions) _groupChip(sub.id, sub.name),
                  if (hasManual) _groupChip('manual', 'دستی'),
                ],
              ),
            ),
          Expanded(
            child: list.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.dns_outlined, size: 48, color: Colors.grey),
                        const SizedBox(height: 8),
                        Text(servers.isEmpty ? 'هیچ سروری موجود نیست' : 'نتیجه‌ای پیدا نشد'),
                        if (servers.isEmpty) ...[
                          const SizedBox(height: 12),
                          FilledButton.icon(
                            onPressed: _showAddSheet,
                            icon: const Icon(Icons.add_rounded),
                            label: const Text('افزودن'),
                          ),
                        ],
                      ],
                    ),
                  )
                : ListView.separated(
                    padding: const EdgeInsets.all(16),
                    itemCount: list.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 8),
                    itemBuilder: (context, index) => _serverTile(list[index]),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _groupChip(String id, String label) {
    return Padding(
      padding: const EdgeInsets.only(left: 8),
      child: ChoiceChip(
        label: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
        selected: selectedGroupFilter == id,
        onSelected: (_) => setState(() => selectedGroupFilter = id),
      ),
    );
  }

  Widget _serverTile(ServerItem server) {
    final isSelected = server.id == selectedServerId;
    return Dismissible(
      key: ValueKey(server.id),
      direction: DismissDirection.horizontal,
      background: Container(
        decoration: BoxDecoration(color: Colors.red, borderRadius: BorderRadius.circular(16)),
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.symmetric(horizontal: 20),
        child: const Icon(Icons.delete_rounded, color: Colors.white),
      ),
      onDismissed: (_) => deleteServer(server),
      child: ListTile(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        tileColor: Theme.of(context).cardColor,
        leading: Icon(
          isSelected ? Icons.check_circle_rounded : Icons.radio_button_unchecked,
          color: isSelected ? Colors.blue : Colors.grey,
        ),
        title: Text(server.remark, maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: Text('${server.protocol} • ${server.subName}'),
        trailing: _pingSummary(server),
        onLongPress: () => _showServerSheet(server),
        onTap: () async {
          setState(() => selectedServerId = server.id);
          await savePersistentData();
          await reconnectIfNeeded();
        },
      ),
    );
  }

  void _showServerSheet(ServerItem server) {
    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                title: Text(server.remark, style: const TextStyle(fontWeight: FontWeight.bold)),
                subtitle: Text('${server.protocol} • ${server.subName}'),
              ),
              if (server.rawUrl.isNotEmpty)
                ListTile(
                  leading: const Icon(Icons.link_rounded),
                  title: const Text('کپی لینک سرور'),
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: server.rawUrl));
                    Navigator.pop(ctx);
                    showSnack('لینک کپی شد');
                  },
                ),
              ListTile(
                leading: const Icon(Icons.data_object_rounded),
                title: const Text('کپی کانفیگ JSON'),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: server.fullJsonConfig));
                  Navigator.pop(ctx);
                  showSnack('کانفیگ کپی شد');
                },
              ),
              ListTile(
                leading: const Icon(Icons.speed_rounded),
                title: const Text('تست پینگ'),
                onTap: () {
                  Navigator.pop(ctx);
                  pingSingleServer(server);
                },
              ),
              ListTile(
                leading: const Icon(Icons.delete_outline_rounded, color: Colors.red),
                title: const Text('حذف سرور', style: TextStyle(color: Colors.red)),
                onTap: () {
                  Navigator.pop(ctx);
                  deleteServer(server);
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSubscriptionsTab() {
    return Scaffold(
      appBar: AppBar(
        title: const Text('سابسکریپشن‌ها'),
        actions: [
          IconButton(icon: const Icon(Icons.sync_rounded), tooltip: 'آپدیت همه', onPressed: updateAllSubscriptions),
          IconButton(icon: const Icon(Icons.add_rounded), tooltip: 'افزودن', onPressed: _showAddSheet),
        ],
      ),
      body: subscriptions.isEmpty
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.rss_feed_rounded, size: 48, color: Colors.grey),
                  const SizedBox(height: 8),
                  const Text('هیچ اشتراکی اضافه نشده است'),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _showAddSheet,
                    icon: const Icon(Icons.add_rounded),
                    label: const Text('افزودن اشتراک'),
                  ),
                ],
              ),
            )
          : ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: subscriptions.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, index) => _subscriptionTile(subscriptions[index]),
            ),
    );
  }

  Widget _subscriptionTile(SubscriptionItem sub) {
    final details = <String>[
      '${sub.serverCount} سرور',
      'آپدیت: ${fmtAgo(sub.updatedAt)}',
    ];
    if (sub.expireSec > 0) {
      final days = DateTime.fromMillisecondsSinceEpoch(sub.expireSec * 1000).difference(DateTime.now()).inDays;
      details.add(days >= 0 ? '$days روز مانده' : 'منقضی شده');
    }
    final hasUsage = sub.totalBytes > 0;
    final usage = hasUsage ? (sub.usedBytes / sub.totalBytes).clamp(0.0, 1.0) : 0.0;

    return Container(
      decoration: BoxDecoration(color: Theme.of(context).cardColor, borderRadius: BorderRadius.circular(16)),
      padding: const EdgeInsets.fromLTRB(16, 12, 8, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(sub.name, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ),
              if (sub.isUpdating)
                const Padding(
                  padding: EdgeInsets.all(12),
                  child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                )
              else
                IconButton(icon: const Icon(Icons.refresh_rounded), onPressed: () => updateSubscription(sub)),
              PopupMenuButton<String>(
                onSelected: (v) {
                  if (v == 'rename') renameSubscription(sub);
                  if (v == 'copy') {
                    Clipboard.setData(ClipboardData(text: sub.url));
                    showSnack('لینک اشتراک کپی شد');
                  }
                  if (v == 'delete') deleteSubscription(sub);
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'rename', child: Text('تغییر نام')),
                  PopupMenuItem(value: 'copy', child: Text('کپی لینک')),
                  PopupMenuItem(value: 'delete', child: Text('حذف', style: TextStyle(color: Colors.red))),
                ],
              ),
            ],
          ),
          Text(details.join(' • '), style: const TextStyle(color: Colors.grey, fontSize: 12)),
          if (hasUsage) ...[
            const SizedBox(height: 8),
            Padding(
              padding: const EdgeInsets.only(left: 8),
              child: LinearProgressIndicator(value: usage, minHeight: 6, borderRadius: BorderRadius.circular(6)),
            ),
            const SizedBox(height: 4),
            Text(
              '${fmtBytes(sub.usedBytes)} از ${fmtBytes(sub.totalBytes)}',
              style: const TextStyle(color: Colors.grey, fontSize: 12),
            ),
          ],
          if (sub.lastError != null) ...[
            const SizedBox(height: 6),
            Text('⚠️ ${sub.lastError}', style: const TextStyle(color: Colors.orange, fontSize: 12)),
          ],
        ],
      ),
    );
  }

  Widget _buildSettingsTab() {
    return Scaffold(
      appBar: AppBar(title: const Text('تنظیمات و تم')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text('انتخاب تم برنامه 🎨', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          const SizedBox(height: 8),
          SegmentedButton<AppThemeModeSetting>(
            segments: const [
              ButtonSegment(value: AppThemeModeSetting.dark, label: Text('تیره'), icon: Icon(Icons.dark_mode)),
              ButtonSegment(value: AppThemeModeSetting.light, label: Text('روشن'), icon: Icon(Icons.light_mode)),
              ButtonSegment(value: AppThemeModeSetting.cream, label: Text('کرم'), icon: Icon(Icons.color_lens)),
            ],
            selected: {widget.currentTheme},
            onSelectionChanged: (val) => widget.onThemeChanged(val.first),
          ),
          const SizedBox(height: 20),
          const Text('مسیردهی و شبکه ⚙️', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          const Text('تغییرات از اتصال بعدی اعمال می‌شن.', style: TextStyle(color: Colors.grey, fontSize: 12)),
          const SizedBox(height: 8),
          SwitchListTile(
            title: const Text('بای‌پاس سایت‌ها و آی‌پی‌های ایران 🇮🇷'),
            subtitle: const Text('عبور مستقیم ترافیک داخلی بدون قطع VPN'),
            value: bypassIran,
            onChanged: (val) {
              setState(() => bypassIran = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('بای‌پاس شبکهٔ محلی (LAN)'),
            value: bypassLan,
            onChanged: (val) {
              setState(() => bypassLan = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('فناوری Mux'),
            subtitle: const Text('با بعضی سرورها (مثل Reality) بهتره خاموش بمونه'),
            value: enableMux,
            onChanged: (val) {
              setState(() => enableMux = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('حالت پروکسی (بدون تونل VPN)'),
            subtitle: const Text('فقط پروکسی محلی SOCKS روی پورت 10808 اجرا می‌شه'),
            value: isProxyOnly,
            onChanged: (val) {
              setState(() => isProxyOnly = val);
              savePersistentData();
            },
          ),
          const SizedBox(height: 12),
          const Text('DNS', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            children: [
              for (final d in kDnsOptions)
                ChoiceChip(
                  label: Text(d),
                  selected: selectedDns == d,
                  onSelected: (_) {
                    setState(() => selectedDns = d);
                    savePersistentData();
                  },
                ),
            ],
          ),
          const SizedBox(height: 20),
          const Text('سابسکریپشن', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          SwitchListTile(
            title: const Text('آپدیت خودکار هنگام باز شدن برنامه'),
            subtitle: const Text('اشتراک‌هایی که بیش از ۶ ساعت از آپدیتشون گذشته'),
            value: autoUpdateSubs,
            onChanged: (val) {
              setState(() => autoUpdateSubs = val);
              savePersistentData();
            },
          ),
          const SizedBox(height: 20),
          const Text('دسترسی سریع', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          const ListTile(
            leading: Icon(Icons.widgets_outlined),
            title: Text('Quick Settings و ویجت صفحهٔ اصلی'),
            subtitle: Text(
              'کاشی Happ VPN را از بخش ویرایش پنل سریع اندروید اضافه کن. برای ویجت هم در فهرست Widgets لانچر، Happ VPN را روی صفحهٔ اصلی قرار بده. لمس آن‌ها برنامه را برای اجرای فرمان اتصال یا قطع اتصال باز می‌کند.',
            ),
          ),
          const SizedBox(height: 20),
          const Text('درباره', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey)),
          ListTile(
            leading: const Icon(Icons.memory_rounded),
            title: const Text('نسخهٔ هسته'),
            subtitle: Text(coreVersion, textDirection: TextDirection.ltr),
          ),
          ListTile(
            leading: const Icon(Icons.delete_sweep_rounded, color: Colors.red),
            title: const Text('پاک کردن همهٔ سرورها و اشتراک‌ها', style: TextStyle(color: Colors.red)),
            onTap: _confirmClearAll,
          ),
        ],
      ),
    );
  }

  Future<void> _confirmClearAll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('پاک کردن همه چیز؟'),
          content: const Text('تمام سرورها و اشتراک‌ها حذف می‌شن.'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('لغو')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('پاک کن')),
          ],
        ),
      ),
    );
    if (ok != true) return;
    if (isConnected || isConnecting) await flutterV2ray.stopV2Ray();
    setState(() {
      servers.clear();
      subscriptions.clear();
      selectedServerId = '';
      selectedGroupFilter = 'ALL';
    });
    await savePersistentData();
  }

  Widget _buildMetric(String title, String val) {
    return Column(
      children: [
        Text(title, style: const TextStyle(color: Colors.grey, fontSize: 12)),
        const SizedBox(height: 4),
        Text(val, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
      ],
    );
  }
}
