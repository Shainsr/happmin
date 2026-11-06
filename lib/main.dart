import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_v2ray/flutter_v2ray.dart';
import 'package:shared_preferences/shared_preferences.dart';

typedef JsonMap = Map<String, dynamic>;
typedef StringMap = Map<String, String>;
typedef IntMap = Map<String, int>;

const MethodChannel kQuickControlsChannel =
    MethodChannel('com.example.happ_vpn/quick_controls');

// ---------------------------------------------------------------------------
//  تنظیمات ارتباط با سازنده (برای دریافت درخواست سرور از سمت کاربر)
// ---------------------------------------------------------------------------
// وب‌هوک HTTPS باید روی سرور سازنده تنظیم شود؛ کلید محرمانه را داخل APK قرار ندهید.
const String kCreatorWebhookUrl = '';
const String kCreatorDefaultSubUrl = '';

enum PingMode { real, tcp }

class ServerEndpoint {
  final String host;
  final int port;
  const ServerEndpoint(this.host, this.port);
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ShinVPNApp());
}

// نقطه ورود پس‌زمینه برای ویجت و Quick Settings بدون باز شدن صفحه برنامه
@pragma('vm:entry-point')
Future<void> vpnBackgroundMain() async {
  WidgetsFlutterBinding.ensureInitialized();
  final prefs = await SharedPreferences.getInstance();
  final isConnected = prefs.getBool('bg_vpn_connected') ?? false;
  final config = prefs.getString('native_ready_config') ?? '';
  final remark = prefs.getString('native_ready_remark') ?? 'SHIN Server';
  final isProxyOnly = prefs.getBool('isProxyOnly') ?? false;

  final v2ray = FlutterV2ray(
    onStatusChanged: (status) async {
      final connected = status.state == 'CONNECTED';
      await prefs.setBool('bg_vpn_connected', connected);
      try {
        await kQuickControlsChannel.invokeMethod('setConnectionState', {
          'connected': connected,
          'status': status.state,
        });
      } catch (_) {}
    },
  );

  try {
    await v2ray.initializeV2Ray();
    if (isConnected) {
      await v2ray.stopV2Ray();
    } else if (config.isNotEmpty) {
      await v2ray.startV2Ray(
        remark: remark,
        config: config,
        proxyOnly: isProxyOnly,
        bypassSubnets: null,
      );
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
//  ثابت‌ها و تنظیمات پایه
// ---------------------------------------------------------------------------

const String kAppVersion = '4.11.0';

const List<String> kUserAgents = [
  'SHIN/4.11.0 (Android; Xray/26.10.31)',
  'v2rayNG/1.9.12',
  'SHIN/4.11.0 (Android)',
];

const List<String> kDnsOptions = [
  '1.1.1.1',
  '8.8.8.8',
  '9.9.9.9',
  '94.140.14.14',
];

const List<String> kSupportedSchemes = [
  'vless',
  'vmess',
  'trojan',
  'ss',
  'socks',
  'socks5',
];

enum AppThemeModeSetting { dark, midnight, light, cream }

// ---------------------------------------------------------------------------
//  پارسر پیشرفته لینک‌ها
// ---------------------------------------------------------------------------

class ParsedLink {
  final String scheme;
  final String userInfo;
  final String host;
  final int port;
  final StringMap params;
  final String fragment;

  ParsedLink(
    this.scheme,
    this.userInfo,
    this.host,
    this.port,
    this.params,
    this.fragment,
  );
}

class ConvertedConfig {
  final String remark;
  final String protocol;
  final JsonMap config;

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

  static ServerEndpoint? parseHostPort(String input) {
    final s = input.trim();
    if (s.isEmpty) return null;
    if (s.startsWith('[')) {
      final close = s.indexOf(']');
      if (close <= 0) return null;
      final host = s.substring(1, close);
      final after = s.substring(close + 1);
      if (!after.startsWith(':')) return null;
      final port = int.tryParse(after.substring(1));
      if (port == null || port <= 0 || port > 65535) return null;
      return ServerEndpoint(host, port);
    }
    final colon = s.lastIndexOf(':');
    if (colon <= 0) return null;
    final port = int.tryParse(s.substring(colon + 1));
    if (port == null || port <= 0 || port > 65535) return null;
    return ServerEndpoint(s.substring(0, colon), port);
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

    final StringMap params = {};
    if (query.isNotEmpty) {
      for (final pair in query.split('&')) {
        if (pair.isEmpty) continue;
        final eq = pair.indexOf('=');
        final key = (eq <= 0 ? pair : pair.substring(0, eq)).toLowerCase();
        final value = eq <= 0 ? '' : safeDecode(pair.substring(eq + 1));
        params[key] = value;
      }
    }
    return ParsedLink(scheme, userInfo, hp.host, hp.port, params, fragment);
  }

  static String _p(StringMap p, String key, [String fallback = '']) {
    final v = p[key];
    return (v == null || v.isEmpty) ? fallback : v;
  }

  static bool _truthy(String? v) {
    if (v == null) return false;
    final l = v.toLowerCase();
    return l == '1' || l == 'true' || l == 'yes';
  }

  static JsonMap _wrap(JsonMap outbound) => {
        'log': {'loglevel': 'none'},
        'inbounds': standardInbounds(),
        'outbounds': [
          outbound,
          {'tag': 'direct', 'protocol': 'freedom', 'settings': {}},
          {'tag': 'blackhole', 'protocol': 'blackhole', 'settings': {}},
        ],
      };

  static List<JsonMap> standardInbounds() => [
        {
          'tag': 'in_proxy',
          'port': 10808,
          'protocol': 'socks',
          'listen': '127.0.0.1',
          'settings': {'auth': 'noauth', 'udp': true, 'userLevel': 8},
          'sniffing': {
            'enabled': true,
            'destOverride': ['http', 'tls', 'quic'],
            'routeOnly': false,
          },
        }
      ];

  static JsonMap _stream(
    StringMap p, {
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
    final JsonMap stream = {'network': net};

    switch (net) {
      case 'ws':
        final JsonMap ws = {'path': path.isEmpty ? '/' : path};
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
        final JsonMap x = {
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
        final JsonMap kcp = {
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
                  'Host':
                      hostHeader.isEmpty ? <String>[] : hostHeader.split(','),
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
      final JsonMap tls = {
        'serverName': _p(
            p, 'sni', _p(p, 'peer', hostHeader.isNotEmpty ? hostHeader : host)),
        'allowInsecure':
            _truthy(p['allowinsecure']) || _truthy(p['insecure']),
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
      if (lower.startsWith('socks://') || lower.startsWith('socks5://')) {
        return _socks(l);
      }
    } catch (_) {}
    return null;
  }

  static String _remarkOrDefault(ParsedLink p) =>
      p.fragment.isNotEmpty ? p.fragment : '${p.host}:${p.port}';

  static ConvertedConfig? _vless(String link) {
    final p = splitLink(link);
    if (p == null || p.userInfo.isEmpty) return null;
    final JsonMap user = {
      'id': p.userInfo,
      'encryption': _p(p.params, 'encryption', 'none'),
      'level': 8,
    };
    final flow = _p(p.params, 'flow');
    if (flow.isNotEmpty) user['flow'] = flow;

    final JsonMap outbound = {
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
    final JsonMap outbound = {
      'tag': 'proxy',
      'protocol': 'trojan',
      'settings': {
        'servers': [
          {
            'address': p.host,
            'port': p.port,
            'password': p.userInfo,
            'level': 8
          }
        ],
      },
      'streamSettings':
          _stream(p.params, host: p.host, defaultSecurity: 'tls'),
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
      final StringMap params = {
        'type': net,
        'headertype':
            s('type') == 'multi' || s('type') == 'gun' ? '' : s('type'),
        'host': s('host'),
        'path': s('path'),
        'security': s('tls') == 'tls'
            ? 'tls'
            : (s('tls') == 'reality' ? 'reality' : 'none'),
        'sni': s('sni'),
        'fp': s('fp'),
        'alpn': s('alpn'),
        'allowinsecure': s('allowInsecure'),
      };
      if (net == 'grpc') {
        params['servicename'] = s('path');
        params['mode'] = s('type') == 'multi' ? 'multi' : '';
      }

      final JsonMap outbound = {
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
      final remark = s('ps').isNotEmpty
          ? s('ps')
          : (fragment.isNotEmpty ? fragment : '$host:$port');
      return ConvertedConfig(remark, 'VMESS', _wrap(outbound));
    }

    final p = splitLink(link);
    if (p == null || p.userInfo.isEmpty) return null;
    final JsonMap outbound = {
      'tag': 'proxy',
      'protocol': 'vmess',
      'settings': {
        'vnext': [
          {
            'address': p.host,
            'port': p.port,
            'users': [
              {
                'id': p.userInfo,
                'alterId': 0,
                'security': _p(p.params, 'encryption', 'auto'),
                'level': 8
              }
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
      creds = userPart.contains(':')
          ? safeDecode(userPart)
          : decodeBase64Loose(userPart);
    } else {
      final decoded = decodeBase64Loose(rest);
      if (decoded == null) return null;
      final at = decoded.lastIndexOf('@');
      if (at <= 0) return null;
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

    final JsonMap outbound = {
      'tag': 'proxy',
      'protocol': 'shadowsocks',
      'settings': {
        'servers': [
          {
            'address': hp.host,
            'port': hp.port,
            'method': method,
            'password': password,
            'level': 8,
          }
        ],
      },
    };
    final remark =
        fragment.isNotEmpty ? fragment : '${hp.host}:${hp.port}';
    return ConvertedConfig(remark, 'SHADOWSOCKS', _wrap(outbound));
  }

  static ConvertedConfig? _socks(String link) {
    final p = splitLink(link);
    if (p == null) return null;

    String? user;
    String? pass;
    if (p.userInfo.isNotEmpty) {
      var cred = p.userInfo;
      if (!cred.contains(':')) {
        cred = decodeBase64Loose(cred) ?? cred;
      }
      final idx = cred.indexOf(':');
      if (idx > 0) {
        user = cred.substring(0, idx);
        pass = cred.substring(idx + 1);
      }
    }

    final JsonMap serverObj = {
      'address': p.host,
      'port': p.port,
    };
    if (user != null && user.isNotEmpty) {
      serverObj['users'] = [
        {'user': user, 'pass': pass ?? '', 'level': 8}
      ];
    }

    final JsonMap outbound = {
      'tag': 'proxy',
      'protocol': 'socks',
      'settings': {
        'servers': [serverObj],
      },
    };
    return ConvertedConfig(_remarkOrDefault(p), 'SOCKS', _wrap(outbound));
  }
}

// ---------------------------------------------------------------------------
//  استخراج سرورها از متن سابسکریپشن یا ورودی JSON
// ---------------------------------------------------------------------------

class ExtractedEntries {
  final List<String> links = [];
  final List<JsonMap> jsonConfigs = [];
  bool looksLikeHtml = false;
  bool looksLikeClash = false;
}

ExtractedEntries extractEntries(String body, {int depth = 0}) {
  final out = ExtractedEntries();
  final text = body.replaceAll('\uFEFF', '').trim();
  if (text.isEmpty) return out;

  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      final j = jsonDecode(text);
      final list = j is List ? j : [j];
      for (final e in list) {
        if (e is Map && e['outbounds'] is List) {
          out.jsonConfigs.add(JsonMap.from(e));
        }
      }
      if (out.jsonConfigs.isNotEmpty) return out;
    } catch (_) {}
  }

  final head = text.substring(0, min(300, text.length)).toLowerCase();
  if (head.contains('html') || head.contains('doctype')) {
    out.looksLikeHtml = true;
    return out;
  }

  if (RegExp(r'^\s*proxies\s*:', multiLine: true).hasMatch(text)) {
    out.looksLikeClash = true;
    return out;
  }

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
        if (start != idx) out.links.add(line.substring(start));
      } else {
        for (final m in RegExp(r'[A-Za-z][A-Za-z0-9+.\-]*://\S+')
            .allMatches(line)) {
          out.links.add(m.group(0)!);
        }
      }
    }
    if (out.links.isNotEmpty) return out;
  }

  if (depth <= 1) {
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
  final IntMap unsupported = {};
  bool looksLikeHtml = false;
  bool looksLikeClash = false;
  String rawPreview = '';
  int httpStatus = 0;
  String? error;

  int get added => servers.length;
  bool get hasProblems =>
      error != null ||
      failed > 0 ||
      unsupported.isNotEmpty ||
      looksLikeHtml ||
      looksLikeClash ||
      added == 0;
}

String _schemeOf(String link) {
  final i = link.indexOf('://');
  return i <= 0 ? '' : link.substring(0, i).toLowerCase();
}

ImportReport buildImport(
  String body, {
  required String subId,
  required String subName,
}) {
  final report = ImportReport();
  final trimmed = body.trim();
  report.rawPreview =
      trimmed.length > 600 ? trimmed.substring(0, 600) : trimmed;

  final extracted = extractEntries(body);
  report.looksLikeHtml = extracted.looksLikeHtml;
  report.looksLikeClash = extracted.looksLikeClash;

  final stamp = DateTime.now().microsecondsSinceEpoch;
  var index = 0;

  for (final cfg in extracted.jsonConfigs) {
    try {
      final outbounds = cfg['outbounds'] as List;
      Map? main;
      for (final o in outbounds) {
        if (o is Map && o['tag'] == 'proxy') main = o;
      }
      main ??= outbounds.firstWhere(
        (o) =>
            o is Map &&
            !['freedom', 'blackhole', 'dns'].contains(o['protocol']),
        orElse: () => null,
      ) as Map?;

      cfg['inbounds'] = LinkParser.standardInbounds();
      final remark =
          (cfg['remarks'] ?? cfg['remark'] ?? cfg['ps'] ?? '').toString().trim();
      final protocol = (main?['protocol'] ?? 'JSON').toString().toUpperCase();
      index++;
      report.servers.add(ServerItem(
        id: '${subId}_${stamp}_$index',
        rawUrl: '',
        remark: remark.isEmpty ? 'Custom JSON $index' : remark,
        protocol: protocol,
        subId: subId,
        subName: subName,
        fullJsonConfig: jsonEncode(cfg),
      ));
    } catch (_) {
      report.failed++;
    }
  }

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

    final preferOwn = RegExp(
      r'(type|net)=(xhttp|splithttp|httpupgrade|raw)|^socks',
      caseSensitive: false,
    ).hasMatch(link);

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
      protocol: protocol == 'SS'
          ? 'SHADOWSOCKS'
          : (protocol == 'SOCKS5' ? 'SOCKS' : protocol),
      subId: subId,
      subName: subName,
      fullJsonConfig: fullConfig!,
    ));
  }
  return report;
}

// ---------------------------------------------------------------------------
//  دریافت سابسکریپشن
// ---------------------------------------------------------------------------

class FetchResult {
  int status = 0;
  String body = '';
  StringMap headers = {};
  String? error;
  String? resolvedUrl;
}

List<String> resolveSubscriptionCandidateUrls(
  String primaryUrl,
  String? fallbackUrl,
) {
  final candidates = <String>[];
  try {
    final uri = Uri.parse(primaryUrl.trim());
    final newUrlParam =
        uri.queryParameters['new-url'] ?? uri.queryParameters['new_url'];
    if (newUrlParam != null && newUrlParam.startsWith('http')) {
      candidates.add(newUrlParam);
    }
    candidates.add(primaryUrl.trim());
    final queryFallback = uri.queryParameters['fallback-url'] ??
        uri.queryParameters['fallback_url'];
    if (queryFallback != null && queryFallback.startsWith('http')) {
      candidates.add(queryFallback);
    }
  } catch (_) {
    candidates.add(primaryUrl.trim());
  }
  if (fallbackUrl != null && fallbackUrl.trim().startsWith('http')) {
    if (!candidates.contains(fallbackUrl.trim())) {
      candidates.add(fallbackUrl.trim());
    }
  }
  return candidates;
}

Future<FetchResult> fetchSubscription(
  String url,
  String userAgent,
  String hwid,
) async {
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
    final resp = await req.close().timeout(const Duration(seconds: 25));
    r.status = resp.statusCode;
    r.resolvedUrl = url.trim();
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

ServerEndpoint? extractServerEndpoint(String rawConfig) {
  try {
    final decoded = jsonDecode(rawConfig);
    if (decoded is! Map) return null;
    final outbounds = decoded['outbounds'];
    if (outbounds is! List) return null;

    for (final outbound in outbounds) {
      if (outbound is! Map) continue;
      final protocol = (outbound['protocol'] ?? '').toString().toLowerCase();
      if (protocol.isEmpty ||
          protocol == 'freedom' ||
          protocol == 'blackhole' ||
          protocol == 'dns') {
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
          final port =
              portValue is int ? portValue : int.tryParse('$portValue');
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
//  مدل‌های داده
// ---------------------------------------------------------------------------

class ServerItem {
  String id;
  String rawUrl;
  String remark;
  String protocol;
  String subId;
  String subName;
  String fullJsonConfig;
  int? realPing;
  int? tcpPing;
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

  JsonMap toJson() => {
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

  factory ServerItem.fromJson(JsonMap json) => ServerItem(
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
  String fallbackUrl;
  int updatedAt;
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
    this.fallbackUrl = '',
    this.updatedAt = 0,
    this.serverCount = 0,
    this.isUpdating = false,
    this.autoName = false,
    this.usedBytes = 0,
    this.totalBytes = 0,
    this.expireSec = 0,
    this.lastError,
  });

  JsonMap toJson() => {
        'id': id,
        'name': name,
        'url': url,
        'fallbackUrl': fallbackUrl,
        'updatedAt': updatedAt,
        'serverCount': serverCount,
        'autoName': autoName,
        'usedBytes': usedBytes,
        'totalBytes': totalBytes,
        'expireSec': expireSec,
      };

  factory SubscriptionItem.fromJson(JsonMap json) => SubscriptionItem(
        id: json['id'] ?? '',
        name: json['name'] ?? 'اشتراک',
        url: json['url'] ?? '',
        fallbackUrl: json['fallbackUrl'] ?? '',
        updatedAt: json['updatedAt'] is int ? json['updatedAt'] : 0,
        serverCount: json['serverCount'] ?? 0,
        autoName: json['autoName'] ?? false,
        usedBytes: json['usedBytes'] ?? 0,
        totalBytes: json['totalBytes'] ?? 0,
        expireSec: json['expireSec'] ?? 0,
      );
}

// ---------------------------------------------------------------------------
//  توابع فرمت‌بندی و رنگ‌ها
// ---------------------------------------------------------------------------

String fmtBytes(num bytes, {bool isSpeed = false}) {
  final suffix = isSpeed ? '/s' : '';
  if (bytes <= 1023) return '${bytes.toInt()} B$suffix';
  if (bytes <= 1024 * 1024) {
    return '${(bytes / 1024).toStringAsFixed(1)} KB$suffix';
  }
  if (bytes <= 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB$suffix';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB$suffix';
}

String fmtAgo(int ms) {
  if (ms <= 0) return 'هرگز';
  final d = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(ms));
  if (d.inMinutes <= 0) return 'همین الان';
  if (d.inMinutes <= 59) return '${d.inMinutes} دقیقه پیش';
  if (d.inHours <= 23) return '${d.inHours} ساعت پیش';
  return '${d.inDays} روز پیش';
}

Color pingColor(int ping) {
  if (ping <= 0) return const Color(0xFFFF5252);
  if (ping <= 250) return const Color(0xFF00E676);
  if (ping <= 600) return const Color(0xFFFFAB40);
  return const Color(0xFFFF5252);
}

Color protocolBadgeColor(String protocol) {
  switch (protocol.toUpperCase()) {
    case 'VLESS':
      return const Color(0xFF3E82F7);
    case 'VMESS':
      return const Color(0xFFAB47BC);
    case 'TROJAN':
      return const Color(0xFFFF7043);
    case 'SHADOWSOCKS':
      return const Color(0xFF26A69A);
    case 'SOCKS':
      return const Color(0xFFEC407A);
    default:
      return const Color(0xFF78909C);
  }
}

// ---------------------------------------------------------------------------
//  دکمه گرافیکی ویژه SHIN با امواج نئونی، چرخش هاله و افکت سایبری (مورد ۲)
// ---------------------------------------------------------------------------

class ShinCyberConnectButton extends StatefulWidget {
  final bool isConnected;
  final bool isConnecting;
  final Color activeColor;
  final VoidCallback onTap;

  const ShinCyberConnectButton({
    super.key,
    required this.isConnected,
    required this.isConnecting,
    required this.activeColor,
    required this.onTap,
  });

  @override
  State<ShinCyberConnectButton> createState() => _ShinCyberConnectButtonState();
}

class _ShinCyberConnectButtonState extends State<ShinCyberConnectButton>
    with TickerProviderStateMixin {
  late final AnimationController _waveCtrl;
  late final AnimationController _rotateCtrl;
  late final AnimationController _pressCtrl;

  @override
  void initState() {
    super.initState();
    _waveCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2400),
    )..repeat();

    _rotateCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 5),
    )..repeat();

    _pressCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 140),
      lowerBound: 0.0,
      upperBound: 0.08,
    );
  }

  @override
  void dispose() {
    _waveCtrl.dispose();
    _rotateCtrl.dispose();
    _pressCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final color = widget.activeColor;

    return GestureDetector(
      onTapDown: (_) => _pressCtrl.forward(),
      onTapUp: (_) {
        _pressCtrl.reverse();
        HapticFeedback.mediumImpact();
        widget.onTap();
      },
      onTapCancel: () => _pressCtrl.reverse(),
      child: AnimatedBuilder(
        animation: Listenable.merge([_waveCtrl, _rotateCtrl, _pressCtrl]),
        builder: (context, _) {
          final pressScale = 1.0 - _pressCtrl.value;
          return Transform.scale(
            scale: pressScale,
            child: SizedBox(
              width: 220,
              height: 220,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  // امواج راداری با محوشدن نرم هنگام قطع اتصال
                  AnimatedOpacity(
                    opacity: widget.isConnected || widget.isConnecting ? 1 : 0,
                    duration: const Duration(milliseconds: 520),
                    curve: Curves.easeOutCubic,
                    child: Stack(
                      alignment: Alignment.center,
                      children: List.generate(3, (index) {
                        final progress =
                            (_waveCtrl.value + (index * 0.333)) % 1.0;
                        final size = 128.0 + (progress * 88.0);
                        final opacity = (1.0 - progress).clamp(0.0, 1.0);
                        return Container(
                          width: size,
                          height: size,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: color.withOpacity(opacity * 0.65),
                              width: 2.5 * opacity + 0.5,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: color.withOpacity(opacity * 0.2),
                                blurRadius: 14,
                              ),
                            ],
                          ),
                        );
                      }),
                    ),
                  ),

                  // ۲. حلقه سایبری چرخان با گرادیان نوری
                  Transform.rotate(
                    angle: _rotateCtrl.value * 2 * pi,
                    child: Container(
                      width: 162,
                      height: 162,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: SweepGradient(
                          colors: [
                            color.withOpacity(0.05),
                            color.withOpacity(
                                widget.isConnected || widget.isConnecting
                                    ? 0.95
                                    : 0.45),
                            color.withOpacity(0.05),
                          ],
                        ),
                      ),
                    ),
                  ),

                  // ۳. لایه محافظ میانی
                  Container(
                    width: 152,
                    height: 152,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Theme.of(context).cardColor,
                    ),
                  ),

                  // ۴. هسته مرکزی درخشان دکمه
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 450),
                    curve: Curves.easeOutBack,
                    width: widget.isConnected ? 138 : 132,
                    height: widget.isConnected ? 138 : 132,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: RadialGradient(
                        center: const Alignment(-0.25, -0.25),
                        radius: 0.95,
                        colors: [
                          color,
                          Color.lerp(color, Colors.black, 0.45)!,
                        ],
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: color.withOpacity(
                              widget.isConnected ? 0.65 : 0.35),
                          blurRadius: widget.isConnected ? 34 : 18,
                          spreadRadius: widget.isConnected ? 6 : 1,
                        ),
                      ],
                    ),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        if (widget.isConnecting)
                          const SizedBox(
                            width: 42,
                            height: 42,
                            child: CircularProgressIndicator(
                              color: Colors.white,
                              strokeWidth: 3.2,
                            ),
                          )
                        else
                          Icon(
                            widget.isConnected
                                ? Icons.shield_rounded
                                : Icons.power_settings_new_rounded,
                            size: 52,
                            color: Colors.white,
                          ),
                        const SizedBox(height: 6),
                        Text(
                          widget.isConnected
                              ? 'متصل'
                              : widget.isConnecting
                                  ? 'در حال اتصال'
                                  : 'شروع اتصال',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ---------------------------------------------------------------------------
//  ریشه اپلیکیشن و مدیریت تم
// ---------------------------------------------------------------------------

class ShinVPNApp extends StatefulWidget {
  const ShinVPNApp({super.key});

  @override
  State<ShinVPNApp> createState() => _ShinVPNAppState();
}

class _ShinVPNAppState extends State<ShinVPNApp> {
  AppThemeModeSetting currentTheme = AppThemeModeSetting.midnight;

  @override
  void initState() {
    super.initState();
    loadSavedTheme();
  }

  Future<void> loadSavedTheme() async {
    final prefs = await SharedPreferences.getInstance();
    final themeIndex = prefs.getInt('saved_theme_mode') ?? 1;
    if (!mounted) return;
    setState(() {
      currentTheme = AppThemeModeSetting.values[
          themeIndex.clamp(0, AppThemeModeSetting.values.length - 1)];
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
          useMaterial3: true,
          brightness: Brightness.light,
          fontFamily: 'Vazirmatn',
          scaffoldBackgroundColor: const Color(0xFFF3F5F9),
          cardColor: const Color(0xFFFFFFFF),
          colorScheme: const ColorScheme.light(
            primary: Color(0xFF2563EB),
            secondary: Color(0xFF10B981),
            surface: Color(0xFFFFFFFF),
          ),
        );
        break;
      case AppThemeModeSetting.cream:
        baseTheme = ThemeData(
          useMaterial3: true,
          brightness: Brightness.light,
          fontFamily: 'Vazirmatn',
          scaffoldBackgroundColor: const Color(0xFFF7F4EE),
          cardColor: const Color(0xFFFFFFFF),
          colorScheme: const ColorScheme.light(
            primary: Color(0xFF8D6E63),
            secondary: Color(0xFF4CAF50),
            surface: Color(0xFFFFFFFF),
          ),
        );
        break;
      case AppThemeModeSetting.dark:
        baseTheme = ThemeData(
          useMaterial3: true,
          brightness: Brightness.dark,
          fontFamily: 'Vazirmatn',
          scaffoldBackgroundColor: const Color(0xFF050507),
          cardColor: const Color(0xFF131419),
          colorScheme: const ColorScheme.dark(
            primary: Color(0xFF3B82F6),
            secondary: Color(0xFF00E676),
            surface: Color(0xFF131419),
          ),
        );
        break;
      case AppThemeModeSetting.midnight:
        baseTheme = ThemeData(
          useMaterial3: true,
          brightness: Brightness.dark,
          fontFamily: 'Vazirmatn',
          scaffoldBackgroundColor: const Color(0xFF0B0F19),
          cardColor: const Color(0xFF151C2C),
          colorScheme: const ColorScheme.dark(
            primary: Color(0xFF6366F1),
            secondary: Color(0xFF10B981),
            surface: Color(0xFF151C2C),
          ),
        );
        break;
    }

    return baseTheme.copyWith(
      textTheme: baseTheme.textTheme.apply(fontFamily: 'Vazirmatn'),
      primaryTextTheme:
          baseTheme.primaryTextTheme.apply(fontFamily: 'Vazirmatn'),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'SHIN',
      theme: getThemeData(),
      home: MainShell(onThemeChanged: setTheme, currentTheme: currentTheme),
    );
  }
}

// ---------------------------------------------------------------------------
//  پوسته اصلی برنامه (MainShell)
// ---------------------------------------------------------------------------

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

  bool _subUpdateMutex = false;
  bool isCheckingUpdate = false;
  bool isRequestingFromCreator = false;

  bool isProxyOnly = false;
  bool bypassLan = true;
  bool bypassIran = true;
  bool enableMux = false;
  bool allowInsecureDefault = false;
  bool autoUpdateSubs = true;
  String selectedDns = '1.1.1.1';
  String hwid = '';
  String updateRepoUrl =
      'https://api.github.com/repos/Happ-proxy/happ-android/releases/latest';

  bool get isConnected => v2rayStatus.state == 'CONNECTED';
  bool get isConnecting => v2rayStatus.state == 'CONNECTING';

  @override
  void initState() {
    super.initState();

    kQuickControlsChannel.setMethodCallHandler((call) async {
      if (call.method == 'quickToggleVpn' && mounted) {
        await toggleVpn();
      }
    });
    flutterV2ray = FlutterV2ray(
      onStatusChanged: (status) {
        if (mounted) setState(() => v2rayStatus = status);
        unawaited(
          _syncNativeConnectionState(status.state == 'CONNECTED', status.state),
        );
      },
    );
    initEngineAndLoadData();
  }

  Future<void> initEngineAndLoadData() async {
    try {
      await flutterV2ray.initializeV2Ray();
    } catch (e) {
      if (mounted) showSnack('راه‌اندازی هسته Xray ناموفق بود: $e');
    }
    String ver = '';
    try {
      ver = await flutterV2ray.getCoreVersion();
    } catch (_) {}
    await loadPersistentData();
    if (!mounted) return;
    setState(() => coreVersion = ver.isEmpty ? 'Xray-core v26+' : ver);
    await _syncNativeConnectionState(isConnected, v2rayStatus.state);
    await _consumePendingQuickAction();
    _autoUpdateOldSubscriptions();
  }

  Future<void> _syncNativeConnectionState(bool connected, String status) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('bg_vpn_connected', connected);
      await kQuickControlsChannel.invokeMethod('setConnectionState', {
        'connected': connected,
        'status': status,
      });
    } catch (_) {}
  }

  Future<void> _consumePendingQuickAction() async {
    try {
      final action =
          await kQuickControlsChannel.invokeMethod('consumePendingAction');
      if (action == 'toggleVpn' && mounted) await toggleVpn();
    } catch (_) {}
  }

  // ------------------------------------------------------------------ دریافت سرور از سازنده (مورد ۳)

  void _showRequestServerFromCreatorDialog() {
    final userNoteCtrl = TextEditingController();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: Padding(
          padding: EdgeInsets.fromLTRB(
            18,
            0,
            18,
            MediaQuery.of(ctx).viewInsets.bottom + 20,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Row(
                children: [
                  Icon(Icons.support_agent_rounded,
                      color: Color(0xFF10B981), size: 28),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'دریافت سرور اختصاصی از سازنده SHIN',
                      style:
                          TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'با زدن دکمه زیر، درخواست به وب‌سرویس سازنده ارسال می‌شود. اگر وب‌سرویس در نسخه برنامه تنظیم نشده باشد، متن درخواست برای ارسال دستی کپی خواهد شد.',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
              const SizedBox(height: 12),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  color: Colors.black12,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'HWID: $hwid',
                      textDirection: TextDirection.ltr,
                      style: const TextStyle(
                          fontFamily: 'monospace', fontSize: 11),
                    ),
                    IconButton(
                      icon: const Icon(Icons.copy_rounded, size: 18),
                      tooltip: 'کپی شناسه',
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: hwid));
                        showSnack('شناسه دستگاه کپی شد');
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: userNoteCtrl,
                decoration: InputDecoration(
                  labelText: 'نام، آیدی تلگرام یا توضیحات شما (اختیاری)',
                  hintText: 'مثلاً: @username یا نام اینترنت همراه/ثابت',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
              ),
              const SizedBox(height: 14),
              FilledButton.icon(
                style: FilledButton.styleFrom(
                  backgroundColor: const Color(0xFF10B981),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
                icon: const Icon(Icons.send_rounded),
                label: const Text(
                  'ارسال درخواست سرور به سازنده',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                onPressed: () {
                  final note = userNoteCtrl.text.trim();
                  Navigator.pop(ctx);
                  _sendServerRequestToCreator(note);
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _sendServerRequestToCreator(String userNote) async {
    if (isRequestingFromCreator) return;
    setState(() => isRequestingFromCreator = true);
    showSnack('در حال ارسال درخواست سرور به سازنده...');

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 12);
    bool requestSent = false;
    bool subscriptionLoaded = false;

    final messageText = '🚀 درخواست سرور جدید در برنامه SHIN\n'
        '🔑 شناسه دستگاه (HWID): $hwid\n'
        '📝 پیام کاربر: ${userNote.isEmpty ? "بدون توضیح" : userNote}\n'
        '📱 نسخه برنامه: $kAppVersion\n'
        '🆔 شناسه درخواست: ${DateTime.now().microsecondsSinceEpoch}\n'
        '⏰ زمان: ${DateTime.now().toIso8601String()}';

    try {
      // درخواست فقط از طریق وب‌هوک HTTPS معتبرِ متعلق به سازنده ارسال می‌شود.
      // توکن ربات تلگرام نباید داخل APK قرار بگیرد؛ قابل استخراج است.
      if (Uri.tryParse(kCreatorWebhookUrl.trim())?.scheme == 'https') {
        final req = await client.postUrl(Uri.parse(kCreatorWebhookUrl.trim()));
        req.headers.set('Content-Type', 'application/json; charset=utf-8');
        req.add(utf8.encode(jsonEncode({
          'app': 'SHIN',
          'version': kAppVersion,
          'hwid': hwid,
          'note': userNote,
          'timestamp': DateTime.now().toIso8601String(),
        })));
        final resp = await req.close().timeout(const Duration(seconds: 12));
        if (resp.statusCode >= 200 && resp.statusCode < 300) {
          requestSent = true;
        }
      }

      // در صورت تعریف لینک اشتراک پیش‌فرض، پس از ثبت درخواست دریافت شود.
      if (kCreatorDefaultSubUrl.trim().startsWith('http')) {
        await processInput(
          kCreatorDefaultSubUrl.trim(),
          name: 'سرورهای اختصاصی SHIN',
        );
        subscriptionLoaded = true;
      }

      if (requestSent) {
        showSnack('درخواست شما با موفقیت برای سازنده ارسال شد! ✅');
      } else if (subscriptionLoaded) {
        showSnack('سرورهای پیش‌فرض SHIN دریافت شدند؛ وب‌هوک درخواست سازنده تنظیم نشده است.');
      } else {
        // کپی درخواست در صورت تنظیم‌نبودن وب‌هوک یا قطع بودن اینترنت
        await Clipboard.setData(ClipboardData(text: messageText));
        showSnack(
          'متن درخواست و شناسه HWID شما کپی شد؛ برای سازنده ارسال کنید 📩',
        );
      }
    } catch (_) {
      await Clipboard.setData(ClipboardData(text: messageText));
      showSnack(
        'خطا در ارتباط مستقیم؛ متن درخواست در کلیپ‌بورد کپی شد 📋',
      );
    } finally {
      client.close(force: true);
      if (mounted) setState(() => isRequestingFromCreator = false);
    }
  }

  // ------------------------------------------------------------------ ذخیره‌سازی

  Future<void> savePersistentData() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('selectedServerId', selectedServerId);
      await prefs.setBool('isProxyOnly', isProxyOnly);
      await prefs.setBool('bypassLan', bypassLan);
      await prefs.setBool('bypassIran', bypassIran);
      await prefs.setBool('enableMux', enableMux);
      await prefs.setBool('allowInsecureDefault', allowInsecureDefault);
      await prefs.setBool('autoUpdateSubs', autoUpdateSubs);
      await prefs.setString('selectedDns', selectedDns);
      await prefs.setString('pingMode', selectedPingMode.name);
      await prefs.setBool('sortByPing', sortByPing);
      await prefs.setString('hwid', hwid);
      await prefs.setString('updateRepoUrl', updateRepoUrl);

      final active = selectedServer;
      if (active != null) {
        await prefs.setString(
          'native_ready_config',
          buildCustomizedConfig(active.fullJsonConfig),
        );
        await prefs.setString('native_ready_remark', active.remark);
      } else {
        await prefs.remove('native_ready_config');
        await prefs.remove('native_ready_remark');
      }

      final serversJson = servers.map((e) => jsonEncode(e.toJson())).toList();
      await prefs.setStringList('saved_servers_list', serversJson);

      final subsJson =
          subscriptions.map((e) => jsonEncode(e.toJson())).toList();
      await prefs.setStringList('saved_subs_list', subsJson);
    } catch (_) {}
  }

  Future<void> loadPersistentData() async {
    try {
      final prefs = await SharedPreferences.getInstance();

      var savedHwid = prefs.getString('hwid') ?? '';
      if (savedHwid.isEmpty) {
        final rnd = Random.secure();
        savedHwid = List.generate(
          16,
          (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0'),
        ).join();
      }

      final loadedServers = <ServerItem>[];
      for (final e
          in prefs.getStringList('saved_servers_list') ?? <String>[]) {
        try {
          loadedServers.add(ServerItem.fromJson(JsonMap.from(jsonDecode(e))));
        } catch (_) {}
      }
      final loadedSubs = <SubscriptionItem>[];
      for (final e in prefs.getStringList('saved_subs_list') ?? <String>[]) {
        try {
          loadedSubs
              .add(SubscriptionItem.fromJson(JsonMap.from(jsonDecode(e))));
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
        allowInsecureDefault = prefs.getBool('allowInsecureDefault') ?? false;
        autoUpdateSubs = prefs.getBool('autoUpdateSubs') ?? true;
        selectedDns = prefs.getString('selectedDns') ?? '1.1.1.1';
        updateRepoUrl = prefs.getString('updateRepoUrl') ?? updateRepoUrl;
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

  // ------------------------------------------------------------------ ساخت کانفیگ

  String buildCustomizedConfig(String rawJson) {
    try {
      final JsonMap config = JsonMap.from(jsonDecode(rawJson));
      config['dns'] = {
        'servers': [selectedDns, '8.8.8.8', '1.1.1.1']
      };

      if (config['outbounds'] is List &&
          (config['outbounds'] as List).isNotEmpty) {
        final List outbounds = config['outbounds'];
        if (outbounds[0] is Map) {
          outbounds[0]['mux'] = {
            'enabled': enableMux,
            'concurrency': enableMux ? 8 : -1,
          };
          if (allowInsecureDefault &&
              outbounds[0]['streamSettings'] is Map &&
              outbounds[0]['streamSettings']['tlsSettings'] is Map) {
            outbounds[0]['streamSettings']['tlsSettings']['allowInsecure'] =
                true;
          }
        }
        final hasDirect =
            outbounds.any((o) => o is Map && o['tag'] == 'direct');
        if (!hasDirect) {
          outbounds
              .add({'tag': 'direct', 'protocol': 'freedom', 'settings': {}});
        }
      }

      final List<dynamic> rules = [];
      if (bypassLan) {
        rules.add({
          'type': 'field',
          'ip': [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
          ],
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
          'ip': [
            '2.144.0.0/14',
            '5.52.0.0/16',
            '31.2.128.0/17',
            '37.98.0.0/16',
            '78.38.0.0/15',
            '79.127.0.0/16'
          ],
          'outboundTag': 'direct'
        });
      }

      if (rules.isNotEmpty) {
        config['routing'] = {
          'domainStrategy': 'IPIfNonMatch',
          'rules': rules,
        };
        if (config['inbounds'] is List) {
          for (final inb in config['inbounds']) {
            if (inb is Map) {
              inb['sniffing'] = {
                'enabled': true,
                'destOverride': ['http', 'tls', 'quic'],
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

  String buildLightweightPingConfig(String rawJson) {
    try {
      final JsonMap config = JsonMap.from(jsonDecode(rawJson));
      config['log'] = {'loglevel': 'none'};
      config.remove('routing');
      config.remove('dns');
      if (config['inbounds'] is List) {
        for (final inb in config['inbounds']) {
          if (inb is Map) {
            inb.remove('sniffing');
          }
        }
      }
      if (allowInsecureDefault &&
          config['outbounds'] is List &&
          (config['outbounds'] as List).isNotEmpty) {
        final first = config['outbounds'][0];
        if (first is Map &&
            first['streamSettings'] is Map &&
            first['streamSettings']['tlsSettings'] is Map) {
          first['streamSettings']['tlsSettings']['allowInsecure'] = true;
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
    if (isConnected || isConnecting) {
      await flutterV2ray.stopV2Ray();
      await _syncNativeConnectionState(false, 'DISCONNECTED');
      return;
    }

    final target = selectedServer;
    if (target == null) {
      showSnack('لطفاً ابتدا یک سرور اضافه کنید یا از سازنده سرور بگیرید!');
      return;
    }

    if (!isProxyOnly && !await flutterV2ray.requestPermission()) {
      showSnack('مجوز ساخت تونل VPN توسط سیستم صادر نشد!');
      return;
    }

    await savePersistentData();
    final finalConfig = buildCustomizedConfig(target.fullJsonConfig);
    try {
      await flutterV2ray.startV2Ray(
        remark: target.remark,
        config: finalConfig,
        proxyOnly: isProxyOnly,
        bypassSubnets: null,
      );
    } catch (e) {
      showSnack('خطا در برقراری اتصال: $e');
    }
  }

  Future<void> reconnectIfNeeded() async {
    if (!isConnected && !isConnecting) return;
    await flutterV2ray.stopV2Ray();
    for (var i = 0; i <= 24 && v2rayStatus.state != 'DISCONNECTED'; i++) {
      await Future.delayed(const Duration(milliseconds: 120));
    }
    await toggleVpn();
  }

  // ------------------------------------------------------------------ سیستم پینگ

  Future<int> _measureTcpPing(ServerItem server) async {
    final endpoint = extractServerEndpoint(server.fullJsonConfig);
    if (endpoint == null) return -1;

    try {
      final addresses = await InternetAddress.lookup(endpoint.host)
          .timeout(const Duration(seconds: 3));
      if (addresses.isEmpty) return -1;
      final targetIp = addresses.first;

      final stopwatch = Stopwatch()..start();
      final socket = await Socket.connect(
        targetIp,
        endpoint.port,
        timeout: const Duration(seconds: 3),
      );
      stopwatch.stop();
      socket.destroy();
      return stopwatch.elapsedMilliseconds;
    } catch (_) {
      return -1;
    }
  }

  Future<int> _measureFastRealPing(ServerItem server) async {
    // RTT واقعی TCP: زمان handshake اتصال به endpoint سرور.
    // DNS خارج از زمان‌سنجی است و برای کاهش نوسان، میانهٔ ۳ نمونه ثبت می‌شود.
    final endpoint = extractServerEndpoint(server.fullJsonConfig);
    if (endpoint == null) return -1;

    try {
      final addresses = await InternetAddress.lookup(endpoint.host)
          .timeout(const Duration(seconds: 4));
      if (addresses.isEmpty) return -1;

      final samples = <int>[];
      for (var i = 0; i < 3; i++) {
        Socket? socket;
        try {
          final stopwatch = Stopwatch()..start();
          socket = await Socket.connect(
            addresses.first,
            endpoint.port,
            timeout: const Duration(seconds: 4),
          );
          stopwatch.stop();
          samples.add(stopwatch.elapsedMilliseconds);
        } catch (_) {
          // یک نمونه ناموفق، دو نمونهٔ دیگر را بی‌اعتبار نمی‌کند.
        } finally {
          socket?.destroy();
        }
        if (i < 2) {
          await Future.delayed(const Duration(milliseconds: 120));
        }
      }
      if (samples.isEmpty) return -1;
      samples.sort();
      return samples[samples.length ~/ 2];
    } catch (_) {
      return -1;
    }
  }

  Future<void> pingSingleServer(
    ServerItem server, {
    PingMode? mode,
    bool save = true,
  }) async {
    final testMode = mode ?? selectedPingMode;
    if (!mounted || server.isPinging) return;

    setState(() {
      if (testMode == PingMode.tcp) {
        server.isPingingTcp = true;
      } else {
        server.isPingingReal = true;
      }
    });

    var result = -1;
    try {
      if (testMode == PingMode.real) {
        result = await _measureFastRealPing(server);
      } else {
        result = await _measureTcpPing(server);
      }
    } catch (_) {
      result = -1;
    } finally {
      if (mounted) {
        setState(() {
          if (testMode == PingMode.tcp) {
            server.tcpPing = result;
            server.isPingingTcp = false;
          } else {
            server.realPing = result;
            server.isPingingReal = false;
          }
        });
      }
      if (save) await savePersistentData();
    }
  }

  Future<void> testAllPings() async {
    if (isTestingAll || servers.isEmpty) return;
    final mode = selectedPingMode;
    final list = List<ServerItem>.from(filteredServers);

    setState(() {
      isTestingAll = true;
      pingTestsCompleted = 0;
      pingTestsTotal = list.length;
    });

    try {
      const int batchSize = 4;
      for (var i = 0; i < list.length; i += batchSize) {
        if (!mounted) break;
        final end = min(i + batchSize, list.length);
        final batch = list.sublist(i, end);
        await Future.wait(
          batch.map((server) async {
            await pingSingleServer(server, mode: mode, save: false);
            if (mounted) {
              setState(() => pingTestsCompleted++);
            }
          }),
        );
      }
    } finally {
      if (mounted) setState(() => isTestingAll = false);
      await savePersistentData();
    }
  }

  // ------------------------------------------------------------------ بررسی بروزرسانی

  Future<void> checkForXrayCoreUpdate() async {
    if (isCheckingUpdate) return;
    setState(() => isCheckingUpdate = true);
    showSnack('در حال بررسی آخرین نسخه هسته Xray از گیت‌هاب...');

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 12);
    try {
      final req = await client.getUrl(
        Uri.parse(
            'https://api.github.com/repos/XTLS/Xray-core/releases/latest'),
      );
      req.headers.set('User-Agent', 'SHIN-Updater');
      final resp = await req.close().timeout(const Duration(seconds: 15));
      final body = await utf8.decoder.bind(resp).join();
      final data = jsonDecode(body);
      final latestTag = (data['tag_name'] ?? 'نامشخص').toString();
      final publishedAt =
          (data['published_at'] ?? '').toString().split('T').first;

      if (!mounted) return;
      showDialog(
        context: context,
        builder: (ctx) => Directionality(
          textDirection: TextDirection.rtl,
          child: AlertDialog(
            title: const Text('وضعیت هسته Xray 🛡️'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('نسخه فعلی روی برنامه شما:\n$coreVersion'),
                const SizedBox(height: 12),
                Text(
                    'آخرین نسخه رسمی منتشرشده در گیت‌هاب:\n$latestTag (تاریخ: $publishedAt)'),
                const SizedBox(height: 12),
                const Text(
                  'نکته: هسته Xray یک کتابخانه بومی است و هنگام بیلد جدید در گیت‌هاب اکشنز به صورت خودکار ارتقا می‌یابد.',
                  style: TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
            actions: [
              FilledButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('متوجه شدم'),
              ),
            ],
          ),
        ),
      );
    } catch (e) {
      showSnack('خطا در استعلام نسخه هسته: $e');
    } finally {
      client.close(force: true);
      if (mounted) setState(() => isCheckingUpdate = false);
    }
  }

  Future<void> checkForAppUpdate() async {
    if (isCheckingUpdate) return;
    setState(() => isCheckingUpdate = true);
    showSnack('در حال بررسی بروزرسانی برنامه...');

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 12);
    try {
      final req = await client.getUrl(Uri.parse(updateRepoUrl.trim()));
      req.headers.set('User-Agent', 'SHIN-Updater');
      final resp = await req.close().timeout(const Duration(seconds: 15));
      final body = await utf8.decoder.bind(resp).join();
      final data = jsonDecode(body);

      String latestVer = '';
      String downloadUrl = '';
      String changelog = '';

      if (data is Map) {
        if (data.containsKey('tag_name')) {
          latestVer = (data['tag_name'] ?? '').toString().replaceAll('v', '');
          changelog =
              (data['body'] ?? 'بروزرسانی جدید در دسترس است.').toString();
          final assets = data['assets'];
          if (assets is List && assets.isNotEmpty) {
            for (final a in assets) {
              if (a is Map && (a['name'] ?? '').toString().endsWith('.apk')) {
                downloadUrl = (a['browser_download_url'] ?? '').toString();
                break;
              }
            }
          }
        } else if (data.containsKey('data')) {
          latestVer = (data['data'] ?? '').toString();
          downloadUrl = (data['link'] ?? '').toString();
          changelog = (data['details'] ?? '').toString();
        }
      }

      if (!mounted) return;
      showDialog(
        context: context,
        builder: (ctx) => Directionality(
          textDirection: TextDirection.rtl,
          child: AlertDialog(
            title: const Text('بررسی بروزرسانی SHIN 🚀'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('نسخه فعلی برنامه: $kAppVersion'),
                  Text(
                      'آخرین نسخه منتشرشده: ${latestVer.isEmpty ? kAppVersion : latestVer}'),
                  if (changelog.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    const Text(
                      'تغییرات نسخه جدید:',
                      style:
                          TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                    ),
                    const SizedBox(height: 4),
                    Text(changelog, style: const TextStyle(fontSize: 12)),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('بستن'),
              ),
              if (downloadUrl.isNotEmpty)
                FilledButton.icon(
                  icon: const Icon(Icons.download_rounded),
                  label: const Text('کپی لینک دانلود مستقیم APK'),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: downloadUrl));
                    Navigator.pop(ctx);
                    showSnack(
                        'لینک دانلود مستقیم APK کپی شد؛ در مرورگر باز کنید 📥');
                  },
                ),
            ],
          ),
        ),
      );
    } catch (e) {
      showSnack('خطا در بررسی آپدیت: $e');
    } finally {
      client.close(force: true);
      if (mounted) setState(() => isCheckingUpdate = false);
    }
  }

  // ------------------------------------------------------------------ آپدیت سابسکریپشن

  Future<void> updateSubscription(
    SubscriptionItem sub, {
    bool silent = false,
  }) async {
    if (sub.isUpdating) return;
    while (_subUpdateMutex) {
      await Future.delayed(const Duration(milliseconds: 100));
    }
    _subUpdateMutex = true;

    try {
      if (!mounted) return;
      setState(() {
        sub.isUpdating = true;
        sub.lastError = null;
      });

      ImportReport? best;
      FetchResult? bestFetch;
      String? networkError;

      final candidateUrls =
          resolveSubscriptionCandidateUrls(sub.url, sub.fallbackUrl);

      outerLoop:
      for (final targetUrl in candidateUrls) {
        for (final ua in kUserAgents) {
          final res = await fetchSubscription(targetUrl, ua, hwid);
          if (res.error != null) {
            networkError = res.error;
            break;
          }
          if (res.status != 200) {
            best ??= ImportReport()..httpStatus = res.status;
            best.httpStatus = res.status;
            continue;
          }
          final report =
              buildImport(res.body, subId: sub.id, subName: sub.name);
          report.httpStatus = res.status;
          if (best == null ||
              report.added > best.added ||
              best.httpStatus != 200) {
            best = report;
            bestFetch = res;
          }
          if (report.added > 0 &&
              report.failed == 0 &&
              report.unsupported.isEmpty) {
            break outerLoop;
          }
        }
      }

      if (!mounted) return;

      if (networkError != null && (best == null || best.added == 0)) {
        setState(() {
          sub.isUpdating = false;
          sub.lastError = 'خطای شبکه یا عدم دسترسی به لینک';
        });
        if (!silent) showSnack('خطا در دریافت سابسکریپشن «${sub.name}» ❌');
        return;
      }

      final report = best ?? ImportReport();

      if (report.added > 0) {
        final prev = selectedServer;
        final prevWasInThisSub = prev != null && prev.subId == sub.id;
        final prevRawUrl = prev?.rawUrl;
        final prevRemark = prev?.remark;

        servers.removeWhere((s) => s.subId == sub.id);
        servers.addAll(report.servers);

        if (prevWasInThisSub) {
          ServerItem? matched;
          if (prevRawUrl != null && prevRawUrl.isNotEmpty) {
            for (final s in report.servers) {
              if (s.rawUrl == prevRawUrl) {
                matched = s;
                break;
              }
            }
          }
          if (matched == null && prevRemark != null) {
            for (final s in report.servers) {
              if (s.remark == prevRemark) {
                matched = s;
                break;
              }
            }
          }
          if (matched != null) {
            selectedServerId = matched.id;
          }
        }
        if (!servers.any((s) => s.id == selectedServerId) &&
            servers.isNotEmpty) {
          selectedServerId = servers.first.id;
        }
      } else {
        sub.lastError = report.httpStatus != 200 && report.httpStatus != 0
            ? 'کد وضعیت سرور: ${report.httpStatus}'
            : 'هیچ سروری در پاسخ یافت نشد';
      }

      if (bestFetch != null) {
        final fallbackHeader = bestFetch.headers['fallback-url'] ??
            bestFetch.headers['x-fallback-url'];
        if (fallbackHeader != null && fallbackHeader.startsWith('http')) {
          sub.fallbackUrl = fallbackHeader.trim();
        }

        final info = bestFetch.headers['subscription-userinfo'];
        if (info != null) {
          sub.usedBytes = 0;
          for (final part in info.split(';')) {
            final kv = part.trim().split('=');
            if (kv.length != 2) continue;
            final value = double.tryParse(kv[1].trim())?.toInt() ?? 0;
            switch (kv[0].trim().toLowerCase()) {
              case 'upload':
              case 'download':
                sub.usedBytes += value;
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
        showSnack(
            'اشتراک «${sub.name}» بروزرسانی شد (${report.added} سرور) ✅');
      }
    } finally {
      _subUpdateMutex = false;
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
    final cutoff =
        DateTime.now().subtract(const Duration(hours: 6)).millisecondsSinceEpoch;
    for (final sub in List<SubscriptionItem>.from(subscriptions)) {
      if (sub.updatedAt <= cutoff) {
        await updateSubscription(sub, silent: true);
      }
    }
  }

  // ------------------------------------------------------------------ ایمپورت

  Future<void> importFromClipboard() async {
    final ClipboardData? data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (text.isEmpty) {
      showSnack('کلیپ‌بورد خالی است! 📋');
      return;
    }
    await processInput(text);
  }

  Future<void> processInput(
    String input, {
    String? name,
    String? fallbackUrl,
  }) async {
    final text = input.trim();
    if (text.isEmpty) return;

    final isUrl =
        RegExp(r'^https?://\S+$', caseSensitive: false).hasMatch(text);
    if (isUrl) {
      final existing = subscriptions.where((s) => s.url == text);
      if (existing.isNotEmpty) {
        showSnack('این اشتراک قبلاً ثبت شده؛ در حال بروزرسانی...');
        await updateSubscription(existing.first);
        return;
      }

      var subName = (name ?? '').trim();
      var auto = false;
      if (subName.isEmpty) {
        final frag = Uri.tryParse(text)?.fragment ?? '';
        subName = frag.isNotEmpty
            ? LinkParser.safeDecode(frag)
            : 'اشتراک ${subscriptions.length + 1}';
        auto = frag.isEmpty;
      }

      final sub = SubscriptionItem(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        name: subName,
        url: text,
        fallbackUrl: (fallbackUrl ?? '').trim(),
        autoName: auto,
      );
      setState(() => subscriptions.add(sub));
      await savePersistentData();
      await updateSubscription(sub);
      return;
    }

    final report = buildImport(text, subId: 'manual', subName: 'دستی');
    final existingUrls = servers
        .where((s) => s.subId == 'manual')
        .map((s) => s.rawUrl)
        .toSet();
    final fresh = report.servers
        .where((s) => s.rawUrl.isEmpty || !existingUrls.contains(s.rawUrl))
        .toList();

    if (fresh.isNotEmpty) {
      setState(() {
        servers.addAll(fresh);
        if (selectedServerId.isEmpty) selectedServerId = fresh.first.id;
      });
      await savePersistentData();
    }

    if (report.failed > 0 ||
        report.unsupported.isNotEmpty ||
        report.added == 0) {
      _showReportDialog('افزودن دستی', report);
    } else if (fresh.isEmpty) {
      showSnack('این سرورها قبلاً در لیست وجود داشتند.');
    } else {
      showSnack('${fresh.length} سرور جدید با موفقیت اضافه شد! 🎉');
    }
  }

  void _showAddSheet() {
    final textCtrl = TextEditingController();
    final nameCtrl = TextEditingController();
    final fallbackCtrl = TextEditingController();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: Padding(
          padding: EdgeInsets.fromLTRB(
            16,
            0,
            16,
            MediaQuery.of(ctx).viewInsets.bottom + 16,
          ),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'افزودن سرور، کانفیگ JSON یا سابسکریپشن',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 6),
                const Text(
                  'پشتیبانی کامل از VLESS (Reality/XHTTP)، VMess، Trojan، Shadowsocks، SOCKS5 و JSON سفارشی.',
                  style: TextStyle(color: Colors.grey, fontSize: 12),
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: textCtrl,
                  minLines: 3,
                  maxLines: 6,
                  textDirection: TextDirection.ltr,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                    hintText:
                        'https://... | vless://... | socks://... | {"outbounds": [...]}',
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.content_paste_rounded),
                      tooltip: 'چسباندن از کلیپ‌بورد',
                      onPressed: () async {
                        final d = await Clipboard.getData(Clipboard.kTextPlain);
                        if (d?.text != null) textCtrl.text = d!.text!.trim();
                      },
                    ),
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: nameCtrl,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                    labelText: 'نام دلخواه اشتراک (اختیاری)',
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: fallbackCtrl,
                  textDirection: TextDirection.ltr,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                    labelText: 'لینک جایگزین / Fallback URL (اختیاری)',
                    hintText: 'https://backup-domain.com/sub/...',
                  ),
                ),
                const SizedBox(height: 14),
                FilledButton.icon(
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                  icon: const Icon(Icons.add_circle_outline_rounded),
                  label: const Text('افزودن و پردازش هوشمند'),
                  onPressed: () {
                    final t = textCtrl.text;
                    final n = nameCtrl.text;
                    final fb = fallbackCtrl.text;
                    if (t.trim().isEmpty) return;
                    Navigator.pop(ctx);
                    processInput(t, name: n, fallbackUrl: fb);
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ------------------------------------------------------------------ ویرایشگر JSON سرور

  void _showJsonEditorModal(ServerItem server) {
    String prettyJson = server.fullJsonConfig;
    try {
      final decoded = jsonDecode(server.fullJsonConfig);
      prettyJson = const JsonEncoder.withIndent('  ').convert(decoded);
    } catch (_) {}

    final jsonCtrl = TextEditingController(text: prettyJson);
    final remarkCtrl = TextEditingController(text: server.remark);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: Padding(
          padding: EdgeInsets.fromLTRB(
            16,
            0,
            16,
            MediaQuery.of(ctx).viewInsets.bottom + 16,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'ویرایشگر کانفیگ JSON (Xray Core)',
                style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: remarkCtrl,
                decoration: InputDecoration(
                  labelText: 'نام سرور (Remark)',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
              const SizedBox(height: 10),
              SizedBox(
                height: 260,
                child: TextField(
                  controller: jsonCtrl,
                  maxLines: null,
                  expands: true,
                  textDirection: TextDirection.ltr,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  decoration: InputDecoration(
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      icon: const Icon(Icons.copy_rounded),
                      label: const Text('کپی JSON'),
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: jsonCtrl.text));
                        showSnack('کانفیگ JSON کپی شد');
                      },
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: FilledButton.icon(
                      icon: const Icon(Icons.save_rounded),
                      label: const Text('ذخیره تغییرات'),
                      onPressed: () {
                        try {
                          final parsed = jsonDecode(jsonCtrl.text);
                          if (parsed is! Map) {
                            throw const FormatException(
                                'JSON باید یک شیء باشد');
                          }
                          setState(() {
                            server.remark = remarkCtrl.text.trim().isEmpty
                                ? server.remark
                                : remarkCtrl.text.trim();
                            server.fullJsonConfig = jsonEncode(parsed);
                          });
                          savePersistentData();
                          Navigator.pop(ctx);
                          showSnack('تغییرات کانفیگ ذخیره شد ✅');
                        } catch (e) {
                          showSnack('خطای سینتکس JSON: $e');
                        }
                      },
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ------------------------------------------------------------------ دیالوگ گزارش

  void _showReportDialog(String title, ImportReport r) {
    if (!mounted) return;
    final lines = <String>[];

    if (r.added > 0) lines.add('✅ ${r.added} سرور با موفقیت خوانده شد');
    if (r.failed > 0) {
      lines.add('⚠️ ${r.failed} لینک ناقص بود یا قابل پردازش نبود');
    }
    if (r.unsupported.isNotEmpty) {
      final parts = r.unsupported.entries
          .map((e) => '${e.key} (${e.value})')
          .join('، ');
      lines.add('🚫 پروتکل خارج از هسته Xray: $parts');
    }
    if (r.looksLikeHtml) {
      lines.add(
          '🌐 سرور یک صفحهٔ وب (HTML) برگرداند. لینک اشتباه است یا نیاز به ثبت HWID دارد.');
    }
    if (r.looksLikeClash) {
      lines.add(
          '📄 خروجی به فرمت Clash است. لطفاً لینک استاندارد V2Ray/Xray یا Base64 وارد کنید.');
    }
    if (r.httpStatus != 0 && r.httpStatus != 200 && r.added == 0) {
      lines.add('❌ کد پاسخ سرور: ${r.httpStatus}');
    }

    showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: Text('گزارش پردازش: $title'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final l in lines)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Text(l),
                  ),
                if (r.rawPreview.isNotEmpty && r.added == 0) ...[
                  const SizedBox(height: 6),
                  const Text(
                    'پیش‌نمایش پاسخ دریافتی:',
                    style: TextStyle(color: Colors.grey, fontSize: 12),
                  ),
                  const SizedBox(height: 4),
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.black26,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: SelectableText(
                      r.rawPreview,
                      textDirection: TextDirection.ltr,
                      style: const TextStyle(
                        fontSize: 11,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('متوجه شدم'),
            ),
          ],
        ),
      ),
    );
  }

  // ------------------------------------------------------------------ فیلتر و مرتب‌سازی سرورها

  List<ServerItem> get filteredServers {
    final list = servers.where((s) {
      final matchGroup =
          selectedGroupFilter == 'ALL' || s.subId == selectedGroupFilter;
      final matchSearch = searchQuery.isEmpty ||
          s.remark.toLowerCase().contains(searchQuery.toLowerCase()) ||
          s.protocol.toLowerCase().contains(searchQuery.toLowerCase());
      return matchGroup && matchSearch;
    }).toList();

    if (sortByPing) {
      int? value(ServerItem server) =>
          selectedPingMode == PingMode.tcp ? server.tcpPing : server.realPing;

      int rank(ServerItem server) {
        final ping = value(server);
        if (ping == null) return 1;
        if (ping <= 0) return 2;
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

  Future<void> editSubscriptionDialog(SubscriptionItem sub) async {
    final nameCtrl = TextEditingController(text: sub.name);
    final urlCtrl = TextEditingController(text: sub.url);
    final fbCtrl = TextEditingController(text: sub.fallbackUrl);

    final saved = await showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('ویرایش تنظیمات اشتراک'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: nameCtrl,
                  decoration: const InputDecoration(labelText: 'نام اشتراک'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: urlCtrl,
                  textDirection: TextDirection.ltr,
                  decoration:
                      const InputDecoration(labelText: 'لینک اصلی (URL)'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: fbCtrl,
                  textDirection: TextDirection.ltr,
                  decoration: const InputDecoration(
                    labelText: 'لینک جایگزین (Fallback URL)',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('لغو'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('ذخیره'),
            ),
          ],
        ),
      ),
    );

    if (saved == true) {
      setState(() {
        sub.name =
            nameCtrl.text.trim().isEmpty ? sub.name : nameCtrl.text.trim();
        sub.url = urlCtrl.text.trim().isEmpty ? sub.url : urlCtrl.text.trim();
        sub.fallbackUrl = fbCtrl.text.trim();
        sub.autoName = false;
        for (final s in servers.where((s) => s.subId == sub.id)) {
          s.subName = sub.name;
        }
      });
      await savePersistentData();
      showSnack('اشتراک بروزرسانی شد ✅');
    }
  }

  Future<void> deleteSubscription(SubscriptionItem sub) async {
    final ok = await showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('حذف اشتراک'),
          content: Text('اشتراک «${sub.name}» و تمام سرورهای آن حذف شوند؟'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('لغو'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('حذف'),
            ),
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
            const NavigationDestination(
              icon: Icon(Icons.shield_outlined),
              selectedIcon: Icon(Icons.shield_rounded),
              label: 'اتصال',
            ),
            NavigationDestination(
              icon: Badge(
                isLabelVisible: servers.isNotEmpty,
                label: Text('${servers.length}'),
                child: const Icon(Icons.dns_outlined),
              ),
              selectedIcon: const Icon(Icons.dns_rounded),
              label: 'سرورها',
            ),
            NavigationDestination(
              icon: Badge(
                isLabelVisible: subscriptions.isNotEmpty,
                label: Text('${subscriptions.length}'),
                child: const Icon(Icons.rss_feed_rounded),
              ),
              label: 'اشتراک‌ها',
            ),
            const NavigationDestination(
              icon: Icon(Icons.tune_rounded),
              label: 'تنظیمات',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHomeTab() {
    final activeServer = selectedServer;
    final primaryColor = Theme.of(context).colorScheme.primary;
    final activeColor = isConnected
        ? const Color(0xFF10B981)
        : isConnecting
            ? const Color(0xFFF59E0B)
            : primaryColor;

    final statusText = isConnected
        ? 'متصل و ایمن با هسته Xray'
        : isConnecting
            ? 'در حال مذاکره و اتصال...'
            : 'آماده برقراری اتصال';

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 12, 18, 24),
        child: Column(
          children: [
            // هدر برنامه با لوگوی سفید S و نام SHIN (موارد ۵ و ۶)
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(14),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.18),
                            blurRadius: 10,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: const Text(
                        'S',
                        style: TextStyle(
                          color: Color(0xFF0B0F19),
                          fontSize: 26,
                          fontWeight: FontWeight.w900,
                          height: 1.0,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'SHIN',
                          style: TextStyle(
                            fontSize: 21,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 1.2,
                          ),
                        ),
                        Text(
                          'Core: $coreVersion',
                          style: const TextStyle(
                            fontSize: 10,
                            color: Colors.grey,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
                Row(
                  children: [
                    IconButton.filledTonal(
                      icon: const Icon(Icons.support_agent_rounded),
                      tooltip: 'دریافت سرور از سازنده',
                      onPressed: _showRequestServerFromCreatorDialog,
                    ),
                    const SizedBox(width: 6),
                    IconButton.filledTonal(
                      icon: const Icon(Icons.content_paste_go_rounded),
                      tooltip: 'ایمپورت سریع از کلیپ‌بورد',
                      onPressed: importFromClipboard,
                    ),
                    const SizedBox(width: 6),
                    IconButton.filledTonal(
                      icon: const Icon(Icons.add_rounded),
                      tooltip: 'افزودن دستی یا اشتراک',
                      onPressed: _showAddSheet,
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 20),

            // کارت اصلی اتصال همراه با دکمه گرافیکی ویژه (مورد ۲)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 20),
              decoration: BoxDecoration(
                color: Theme.of(context).cardColor,
                borderRadius: BorderRadius.circular(32),
                border: Border.all(
                  color: activeColor.withOpacity(isConnected ? 0.45 : 0.15),
                  width: 1.5,
                ),
                boxShadow: [
                  BoxShadow(
                    color: activeColor.withOpacity(isConnected ? 0.18 : 0.05),
                    blurRadius: 30,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: Column(
                children: [
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                    decoration: BoxDecoration(
                      color: activeColor.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: BoxDecoration(
                            color: activeColor,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          statusText,
                          style: TextStyle(
                            color: activeColor,
                            fontWeight: FontWeight.w700,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),

                  // دکمه گرافیکی چندلایه با افکت ویژه
                  ShinCyberConnectButton(
                    isConnected: isConnected,
                    isConnecting: isConnecting,
                    activeColor: activeColor,
                    onTap: toggleVpn,
                  ),

                  const SizedBox(height: 14),
                  Text(
                    v2rayStatus.duration,
                    textDirection: TextDirection.ltr,
                    style: const TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.5,
                    ),
                  ),
                  const SizedBox(height: 18),
                  Row(
                    children: [
                      Expanded(
                        child: _buildTrafficCard(
                          title: 'سرعت دانلود',
                          speed: fmtBytes(v2rayStatus.downloadSpeed,
                              isSpeed: true),
                          total: fmtBytes(v2rayStatus.download),
                          icon: Icons.arrow_downward_rounded,
                          color: const Color(0xFF10B981),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: _buildTrafficCard(
                          title: 'سرعت آپلود',
                          speed:
                              fmtBytes(v2rayStatus.uploadSpeed, isSpeed: true),
                          total: fmtBytes(v2rayStatus.upload),
                          icon: Icons.arrow_upward_rounded,
                          color: const Color(0xFF3B82F6),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),

            // دکمه اختصاصی دریافت سرور از سازنده (مورد ۳)
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  padding:
                      const EdgeInsets.symmetric(vertical: 13, horizontal: 16),
                  side: BorderSide(color: primaryColor.withOpacity(0.45)),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18),
                  ),
                ),
                icon: isRequestingFromCreator
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.cloud_download_rounded),
                label: const Text(
                  'دریافت سرور از سازنده (ارسال درخواست فوری)',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                ),
                onPressed: isRequestingFromCreator
                    ? null
                    : _showRequestServerFromCreatorDialog,
              ),
            ),

            const SizedBox(height: 12),
            if (activeServer == null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Theme.of(context).cardColor,
                  borderRadius: BorderRadius.circular(24),
                ),
                child: Column(
                  children: [
                    const Icon(Icons.cloud_off_rounded,
                        size: 38, color: Colors.grey),
                    const SizedBox(height: 8),
                    const Text(
                      'هنوز هیچ سروری اضافه نکرده‌اید',
                      style: TextStyle(fontSize: 12),
                    ),
                    const SizedBox(height: 12),
                    FilledButton.icon(
                      onPressed: _showAddSheet,
                      icon: const Icon(Icons.add_link_rounded),
                      label: const Text('افزودن لینک سرور یا اشتراک'),
                    ),
                  ],
                ),
              )
            else
              InkWell(
                borderRadius: BorderRadius.circular(24),
                onTap: () => setState(() => currentTab = 1),
                child: Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: Theme.of(context).cardColor,
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: primaryColor.withOpacity(0.25),
                    ),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 6),
                        decoration: BoxDecoration(
                          color: protocolBadgeColor(activeServer.protocol)
                              .withOpacity(0.15),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Text(
                          activeServer.protocol,
                          style: TextStyle(
                            color: protocolBadgeColor(activeServer.protocol),
                            fontWeight: FontWeight.w800,
                            fontSize: 9, // دو سایز کوچک‌تر
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // کاهش ۲ سایزی فونت نام سرور (از 13 به 11) (مورد ۴)
                            Text(
                              activeServer.remark,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 11,
                              ),
                            ),
                            const SizedBox(height: 2),
                            // کاهش ۲ سایزی زیرعنوان (از 11 به 9)
                            Text(
                              'اشتراک: ${activeServer.subName} • تغییر سرور',
                              style: const TextStyle(
                                fontSize: 9,
                                color: Colors.grey,
                              ),
                            ),
                          ],
                        ),
                      ),
                      _pingSummary(activeServer),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildTrafficCard({
    required String title,
    required String speed,
    required String total,
    required IconData icon,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 6),
              Text(
                title,
                style: const TextStyle(fontSize: 11, color: Colors.grey),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            speed,
            textDirection: TextDirection.ltr,
            style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15),
          ),
          const SizedBox(height: 2),
          Text(
            'مجموع: $total',
            style: const TextStyle(fontSize: 10, color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _pingChip(ServerItem server, PingMode mode) {
    final isTcp = mode == PingMode.tcp;
    final ping = isTcp ? server.tcpPing : server.realPing;
    final isBusy = isTcp ? server.isPingingTcp : server.isPingingReal;
    final label = isTcp ? 'TCP' : 'RTT';
    final value = isBusy
        ? null
        : ping == null
            ? '—'
            : ping <= 0
                ? 'خطا'
                : '$ping ms';
    final color = ping == null ? Colors.grey : pingColor(ping);

    return InkWell(
      borderRadius: BorderRadius.circular(10),
      onTap:
          server.isPinging ? null : () => pingSingleServer(server, mode: mode),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.12),
          borderRadius: BorderRadius.circular(9),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 8.5,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(width: 3),
            if (isBusy)
              SizedBox(
                width: 10,
                height: 10,
                child: CircularProgressIndicator(
                  strokeWidth: 1.4,
                  color: color,
                ),
              )
            else
              Text(
                value!,
                textDirection: TextDirection.ltr,
                style: TextStyle(
                  color: color,
                  fontSize: 9,
                  fontWeight: FontWeight.bold,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _pingSummary(ServerItem server) {
    return Wrap(
      spacing: 4,
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
          IconButton(
            icon: const Icon(Icons.support_agent_rounded),
            tooltip: 'دریافت سرور از سازنده',
            onPressed: _showRequestServerFromCreatorDialog,
          ),
          isTestingAll
              ? const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 14),
                  child: SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                )
              : IconButton(
                  icon: const Icon(Icons.bolt_rounded),
                  tooltip: 'تست سریع پینگ همه سرورها',
                  onPressed: testAllPings,
                ),
          IconButton(
            icon: Icon(
              sortByPing ? Icons.sort_rounded : Icons.sort_by_alpha_rounded,
            ),
            tooltip: 'مرتب‌سازی بر اساس کمترین پینگ',
            onPressed: () {
              setState(() => sortByPing = !sortByPing);
              savePersistentData();
            },
          ),
          IconButton(
            icon: const Icon(Icons.add_rounded),
            tooltip: 'افزودن سرور',
            onPressed: _showAddSheet,
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 6, 16, 0),
            child: SegmentedButton<PingMode>(
              segments: const [
                ButtonSegment(
                  value: PingMode.real,
                  label: Text('RTT واقعی (TCP)',
                      style: TextStyle(fontSize: 11)),
                  icon: Icon(Icons.bolt_rounded, size: 15),
                ),
                ButtonSegment(
                  value: PingMode.tcp,
                  label: Text('TCP تک‌نمونه', style: TextStyle(fontSize: 11)),
                  icon: Icon(Icons.compare_arrows_rounded, size: 15),
                ),
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
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: Align(
              alignment: Alignment.centerRight,
              child: Text(
                'RTT: میانهٔ ۳ اتصال TCP به سرور؛ بدون زمان DNS',
                style: TextStyle(fontSize: 9, color: Colors.grey),
              ),
            ),
          ),
          if (isTestingAll)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: LinearProgressIndicator(
                value: pingTestsTotal == 0
                    ? null
                    : pingTestsCompleted / pingTestsTotal,
                borderRadius: BorderRadius.circular(6),
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: TextField(
              onChanged: (v) => setState(() => searchQuery = v),
              style: const TextStyle(fontSize: 12),
              decoration: InputDecoration(
                hintText: 'جستجو در نام سرور یا پروتکل (VLESS, SOCKS, ...)',
                hintStyle: const TextStyle(fontSize: 11),
                prefixIcon: const Icon(Icons.search_rounded, size: 20),
                isDense: true,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(16),
                ),
              ),
            ),
          ),
          if (subscriptions.isNotEmpty || hasManual)
            SizedBox(
              height: 44,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                children: [
                  _groupChip('ALL', 'همه (${servers.length})'),
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
                        const Icon(Icons.dns_outlined,
                            size: 48, color: Colors.grey),
                        const SizedBox(height: 8),
                        Text(servers.isEmpty
                            ? 'هیچ سروری موجود نیست'
                            : 'سروری با این عبارت پیدا نشد'),
                        const SizedBox(height: 12),
                        FilledButton.icon(
                          onPressed: _showRequestServerFromCreatorDialog,
                          icon: const Icon(Icons.support_agent_rounded),
                          label: const Text('دریافت سرور از سازنده'),
                        ),
                      ],
                    ),
                  )
                : ListView.separated(
                    padding: const EdgeInsets.all(12),
                    itemCount: list.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 6),
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
        label: Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(fontSize: 11),
        ),
        selected: selectedGroupFilter == id,
        onSelected: (_) => setState(() => selectedGroupFilter = id),
      ),
    );
  }

  // آیتم سرور با فونت ۲ سایز کوچک‌تر (مورد ۴)
  Widget _serverTile(ServerItem server) {
    final isSelected = server.id == selectedServerId;
    final pColor = protocolBadgeColor(server.protocol);

    return Dismissible(
      key: ValueKey(server.id),
      direction: DismissDirection.endToStart,
      background: Container(
        decoration: BoxDecoration(
          color: Colors.redAccent,
          borderRadius: BorderRadius.circular(16),
        ),
        alignment: Alignment.centerLeft,
        padding: const EdgeInsets.symmetric(horizontal: 20),
        child: const Icon(Icons.delete_rounded, color: Colors.white),
      ),
      onDismissed: (_) => deleteServer(server),
      child: Container(
        decoration: BoxDecoration(
          color: Theme.of(context).cardColor,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isSelected
                ? Theme.of(context).colorScheme.primary
                : Colors.transparent,
            width: 1.5,
          ),
        ),
        child: ListTile(
          dense: true,
          visualDensity: const VisualDensity(horizontal: 0, vertical: -2),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          leading: Container(
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 5),
            decoration: BoxDecoration(
              color: pColor.withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              server.protocol,
              style: TextStyle(
                color: pColor,
                fontWeight: FontWeight.w800,
                fontSize: 8.5, // ۲ سایز کوچک‌تر (از 10 به 8.5)
              ),
            ),
          ),
          // ۲ سایز کوچک‌تر شدن نوشته سرور (از 13 به 11)
          title: Text(
            server.remark,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 11,
              fontWeight: isSelected ? FontWeight.w800 : FontWeight.w600,
            ),
          ),
          // ۲ سایز کوچک‌تر شدن زیرعنوان اشتراک (از 10 به 8.5)
          subtitle: Text(
            server.subName,
            style: const TextStyle(fontSize: 8.5, color: Colors.grey),
          ),
          trailing: _pingSummary(server),
          onLongPress: () => _showServerSheet(server),
          onTap: () async {
            setState(() => selectedServerId = server.id);
            await savePersistentData();
            await reconnectIfNeeded();
          },
        ),
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
                title: Text(
                  server.remark,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12, // ۲ سایز کوچک‌تر (از 14 به 12)
                  ),
                ),
                subtitle: Text(
                  '${server.protocol} • ${server.subName}',
                  style: const TextStyle(fontSize: 10),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.edit_note_rounded),
                title: const Text('مشاهده و ویرایش کانفیگ JSON'),
                onTap: () {
                  Navigator.pop(ctx);
                  _showJsonEditorModal(server);
                },
              ),
              if (server.rawUrl.isNotEmpty)
                ListTile(
                  leading: const Icon(Icons.link_rounded),
                  title: const Text('کپی لینک اشتراک‌گذاری سرور'),
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: server.rawUrl));
                    Navigator.pop(ctx);
                    showSnack('لینک سرور کپی شد');
                  },
                ),
              ListTile(
                leading: const Icon(Icons.speed_rounded),
                title: const Text('تست پینگ این سرور'),
                onTap: () {
                  Navigator.pop(ctx);
                  pingSingleServer(server);
                },
              ),
              ListTile(
                leading:
                    const Icon(Icons.delete_outline_rounded, color: Colors.red),
                title: const Text(
                  'حذف سرور',
                  style: TextStyle(color: Colors.red),
                ),
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
        title: const Text('مدیریت اشتراک‌ها (Subscriptions)'),
        actions: [
          IconButton(
            icon: const Icon(Icons.sync_rounded),
            tooltip: 'بروزرسانی همه اشتراک‌ها',
            onPressed: updateAllSubscriptions,
          ),
          IconButton(
            icon: const Icon(Icons.add_rounded),
            tooltip: 'افزودن اشتراک',
            onPressed: _showAddSheet,
          ),
        ],
      ),
      body: subscriptions.isEmpty
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.rss_feed_rounded,
                      size: 48, color: Colors.grey),
                  const SizedBox(height: 8),
                  const Text('هیچ سابسکریپشنی ثبت نشده است'),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _showAddSheet,
                    icon: const Icon(Icons.add_rounded),
                    label: const Text('افزودن لینک سابسکریپشن'),
                  ),
                ],
              ),
            )
          : ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: subscriptions.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (context, index) =>
                  _subscriptionTile(subscriptions[index]),
            ),
    );
  }

  Widget _subscriptionTile(SubscriptionItem sub) {
    final details = <String>[
      '${sub.serverCount} سرور',
      'بروزرسانی: ${fmtAgo(sub.updatedAt)}',
    ];
    if (sub.expireSec > 0) {
      final days = DateTime.fromMillisecondsSinceEpoch(sub.expireSec * 1000)
          .difference(DateTime.now())
          .inDays;
      details.add(days >= 0 ? '$days روز باقی‌مانده' : 'منقضی شده');
    }
    final hasUsage = sub.totalBytes > 0;
    final usage =
        hasUsage ? (sub.usedBytes / sub.totalBytes).clamp(0.0, 1.0) : 0.0;

    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(20),
      ),
      padding: const EdgeInsets.fromLTRB(16, 14, 12, 14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  sub.name,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
              ),
              if (sub.isUpdating)
                const Padding(
                  padding: EdgeInsets.all(12),
                  child: SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                )
              else
                IconButton(
                  icon: const Icon(Icons.refresh_rounded),
                  onPressed: () => updateSubscription(sub),
                ),
              PopupMenuButton<String>(
                onSelected: (v) {
                  if (v == 'edit') editSubscriptionDialog(sub);
                  if (v == 'copy') {
                    Clipboard.setData(ClipboardData(text: sub.url));
                    showSnack('لینک اشتراک کپی شد');
                  }
                  if (v == 'delete') deleteSubscription(sub);
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(
                    value: 'edit',
                    child: Text('ویرایش نام، لینک و Fallback'),
                  ),
                  PopupMenuItem(value: 'copy', child: Text('کپی لینک اشتراک')),
                  PopupMenuItem(
                    value: 'delete',
                    child: Text('حذف اشتراک',
                        style: TextStyle(color: Colors.red)),
                  ),
                ],
              ),
            ],
          ),
          Text(
            details.join(' • '),
            style: const TextStyle(color: Colors.grey, fontSize: 11),
          ),
          if (sub.fallbackUrl.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                'Fallback فعال: ${sub.fallbackUrl}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(color: Colors.blueAccent, fontSize: 11),
              ),
            ),
          if (hasUsage) ...[
            const SizedBox(height: 10),
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: LinearProgressIndicator(value: usage, minHeight: 7),
            ),
            const SizedBox(height: 5),
            Text(
              'مصرف‌شده: ${fmtBytes(sub.usedBytes)} از ${fmtBytes(sub.totalBytes)}',
              style: const TextStyle(color: Colors.grey, fontSize: 11),
            ),
          ],
          if (sub.lastError != null) ...[
            const SizedBox(height: 6),
            Text(
              '⚠️ ${sub.lastError}',
              style: const TextStyle(color: Colors.orangeAccent, fontSize: 11),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildSettingsTab() {
    return Scaffold(
      appBar: AppBar(title: const Text('تنظیمات هسته و ظاهر SHIN')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text(
            'پوسته‌ها و تم گرافیکی 🎨',
            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 8),
          SegmentedButton<AppThemeModeSetting>(
            segments: const [
              ButtonSegment(
                value: AppThemeModeSetting.midnight,
                label: Text('نئون'),
                icon: Icon(Icons.nights_stay_rounded),
              ),
              ButtonSegment(
                value: AppThemeModeSetting.dark,
                label: Text('تیره'),
                icon: Icon(Icons.dark_mode),
              ),
              ButtonSegment(
                value: AppThemeModeSetting.light,
                label: Text('روشن'),
                icon: Icon(Icons.light_mode),
              ),
              ButtonSegment(
                value: AppThemeModeSetting.cream,
                label: Text('کرم'),
                icon: Icon(Icons.color_lens),
              ),
            ],
            selected: {widget.currentTheme},
            onSelectionChanged: (val) => widget.onThemeChanged(val.first),
          ),
          const SizedBox(height: 22),
          const Text(
            'مسیردهی هوشمند و هسته Xray ⚙️',
            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 6),
          SwitchListTile(
            title: const Text('بای‌پاس ترافیک و بانک‌های ایران 🇮🇷'),
            subtitle: const Text(
                'دامنه‌های .ir و آی‌پی‌های داخل کشور مستقیم باز می‌شوند'),
            value: bypassIran,
            onChanged: (val) {
              setState(() => bypassIran = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('بای‌پاس شبکه محلی (LAN)'),
            value: bypassLan,
            onChanged: (val) {
              setState(() => bypassLan = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('تجمیع اتصال (Mux)'),
            subtitle: const Text('برای سرورهای Reality و XHTTP خاموش باشد'),
            value: enableMux,
            onChanged: (val) {
              setState(() => enableMux = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('اجازه به گواهی‌های TLS نامعتبر (Allow Insecure)'),
            value: allowInsecureDefault,
            onChanged: (val) {
              setState(() => allowInsecureDefault = val);
              savePersistentData();
            },
          ),
          SwitchListTile(
            title: const Text('حالت پروکسی محلی (SOCKS5 10808 بدون VPN)'),
            value: isProxyOnly,
            onChanged: (val) {
              setState(() => isProxyOnly = val);
              savePersistentData();
            },
          ),
          const SizedBox(height: 12),
          const Text(
            'سرور DNS ترجیحی',
            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey),
          ),
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
          const SizedBox(height: 22),
          const Text(
            'پشتیبانی، بروزرسانی و اطلاعات هسته 🔄',
            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 6),
          ListTile(
            leading: const Icon(Icons.support_agent_rounded,
                color: Color(0xFF10B981)),
            title: const Text('دریافت سرور از سازنده'),
            subtitle: const Text('ارسال درخواست مستقیم به سازنده SHIN'),
            trailing: const Icon(Icons.send_rounded),
            onTap: _showRequestServerFromCreatorDialog,
          ),
          ListTile(
            leading: const Icon(Icons.system_update_rounded,
                color: Colors.blueAccent),
            title: const Text('بررسی بروزرسانی برنامه'),
            subtitle: const Text('نسخه فعلی: $kAppVersion • دریافت آخرین APK'),
            trailing: isCheckingUpdate
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.chevron_left_rounded),
            onTap: checkForAppUpdate,
          ),
          ListTile(
            leading:
                const Icon(Icons.memory_rounded, color: Colors.greenAccent),
            title: const Text('بررسی بروزرسانی هسته Xray'),
            subtitle: Text(coreVersion, textDirection: TextDirection.ltr),
            trailing: const Icon(Icons.sync_rounded),
            onTap: checkForXrayCoreUpdate,
          ),
          ListTile(
            leading: const Icon(Icons.fingerprint_rounded),
            title: const Text('شناسه سخت‌افزاری دستگاه (x-hwid)'),
            subtitle: Text(hwid, textDirection: TextDirection.ltr),
            trailing: IconButton(
              icon: const Icon(Icons.copy_rounded),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: hwid));
                showSnack('شناسه HWID کپی شد');
              },
            ),
          ),
          ListTile(
            leading: const Icon(Icons.delete_sweep_rounded, color: Colors.red),
            title: const Text(
              'پاکسازی کامل سرورها و اشتراک‌ها',
              style: TextStyle(color: Colors.red),
            ),
            onTap: _confirmClearAll,
          ),
        ],
      ),
    );
  }

  Future<void> _confirmClearAll() async {
    final ok = await showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: TextDirection.rtl,
        child: AlertDialog(
          title: const Text('پاک کردن کل اطلاعات؟'),
          content: const Text('تمام سرورها و اشتراک‌ها حذف خواهند شد.'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('لغو'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('حذف همه'),
            ),
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
}