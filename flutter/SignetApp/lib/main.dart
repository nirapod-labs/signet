// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:signet/signet.dart';

void main() => runApp(const SignetApp());

// ---- palette (violet-free: ink graphite + brass seal + secure emerald) ----
const _ink = Color(0xFF24262C);
const _brass = Color(0xFFB08636);
const _brassContainer = Color(0xFFF1E9D6);
const _brassOn = Color(0xFF4A3712);
const _emerald = Color(0xFF1E7A54);
const _emeraldContainer = Color(0xFFDCF1E5);
const _emeraldOn = Color(0xFF0F5537);
const _parch = Color(0xFFEFE8D6);
const _page = Color(0xFFFBFAF6);
const _line = Color(0xFFE6E2D8);
const _muted = Color(0xFF5C5A53);
const _faint = Color(0xFF9A978E);
const _danger = Color(0xFFB23A3A);
const _fieldBg = Color(0xFFF6F4EE);

class SignetApp extends StatelessWidget {
  const SignetApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: _ink,
      brightness: Brightness.light,
    ).copyWith(
      primary: _ink,
      onPrimary: Colors.white,
      primaryContainer: _brassContainer,
      onPrimaryContainer: _brassOn,
      secondary: _emerald,
      onSecondary: Colors.white,
      secondaryContainer: _emeraldContainer,
      onSecondaryContainer: _emeraldOn,
      tertiary: _brass,
      onTertiary: Colors.white,
      tertiaryContainer: _brassContainer,
      onTertiaryContainer: _brassOn,
      surface: _page,
      onSurface: _ink,
      surfaceContainerLowest: Colors.white,
      surfaceContainerLow: const Color(0xFFF6F3ED),
      surfaceContainer: const Color(0xFFF1EDE5),
      surfaceContainerHigh: const Color(0xFFEBE7DE),
      surfaceContainerHighest: const Color(0xFFE5E1D7),
      onSurfaceVariant: _muted,
      outline: const Color(0xFFCFCBBF),
      outlineVariant: _line,
      error: _danger,
      onError: Colors.white,
    );
    final text = GoogleFonts.manropeTextTheme(Typography.blackMountainView)
        .apply(bodyColor: _ink, displayColor: _ink);

    return MaterialApp(
      title: 'Signet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: scheme,
        scaffoldBackgroundColor: scheme.surface,
        textTheme: text,
        dividerTheme: const DividerThemeData(color: _line, thickness: 1, space: 1),
        navigationRailTheme: NavigationRailThemeData(
          backgroundColor: Colors.white,
          indicatorColor: _brassContainer,
          selectedIconTheme: const IconThemeData(color: _ink),
          unselectedIconTheme: const IconThemeData(color: _muted),
          selectedLabelTextStyle: GoogleFonts.manrope(
              fontWeight: FontWeight.w600, fontSize: 12, color: _ink),
          unselectedLabelTextStyle:
              GoogleFonts.manrope(fontSize: 12, color: _muted),
        ),
        navigationBarTheme: NavigationBarThemeData(
          backgroundColor: Colors.white,
          indicatorColor: _brassContainer,
          elevation: 0,
          labelTextStyle: WidgetStateProperty.resolveWith(
            (s) => GoogleFonts.manrope(
                fontSize: 11.5,
                fontWeight: s.contains(WidgetState.selected)
                    ? FontWeight.w600
                    : FontWeight.w400,
                color: s.contains(WidgetState.selected) ? _ink : _muted),
          ),
        ),
      ),
      home: const AppShell(),
    );
  }
}

// ---- controller ----

enum LogKind { ok, key, sign, attest, info, error }

class LogEvent {
  LogEvent(this.time, this.kind, this.title, this.detail);
  final DateTime time;
  final LogKind kind;
  final String title;
  final String? detail;
}

class SignetController extends ChangeNotifier {
  final Signet _signet = Signet();
  static const alias = 'signet.demo.key';
  static final Uint8List digest =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xFF));

  // configuration (the full generateKey surface)
  TierPolicy policy = const Strongest();
  AuthRequirement authReq = AuthRequirement.none;
  int authValidity = 0; // seconds; 0 == per-use
  bool invalidateOnEnrollment = true;
  String challenge = 'signet-demo';
  PublicKeyFormat pkFormat = PublicKeyFormat.rawX962;
  SignEncoding encoding = SignEncoding.der;
  String promptTitle = 'Approve signature';
  String promptSubtitle = 'Authenticate to sign the demo digest';

  // state
  KeyHandle? handle;
  SecurityTierReport? report;
  AuthRequirement? keyAuthReq;
  PublicKey? publicKey;
  AttestationResult? attestation;
  Uint8List? signature;
  bool? aliasExists;
  bool busy = false;
  final List<LogEvent> events = <LogEvent>[];

  void setPolicy(TierPolicy p) => _set(() => policy = p);
  void setAuthReq(AuthRequirement r) => _set(() => authReq = r);
  void setValidity(int s) => _set(() => authValidity = s);
  void setInvalidate(bool v) => _set(() => invalidateOnEnrollment = v);
  void setChallenge(String s) => challenge = s;
  void setEncoding(SignEncoding e) => _set(() => encoding = e);
  void setPromptTitle(String s) => promptTitle = s;
  void setPromptSubtitle(String s) => promptSubtitle = s;

  Future<void> setPkFormat(PublicKeyFormat f) => _guard(() async {
        pkFormat = f;
        final h = handle;
        if (h != null) publicKey = await _signet.getPublicKey(h, format: f);
      });

  Future<void> bootstrap() => _guard(() async {
        // silent key: bootstrap must not prompt
        await _generateKey(authReqOverride: AuthRequirement.none);
      });

  Future<void> generate() => _guard(() => _generateKey());

  Future<void> sign() => _guard(() async {
        final h = handle;
        if (h == null) {
          _log(LogKind.info, 'No key', 'generate a key in Keys first');
          return;
        }
        // the presence check is fixed at generation: a gated key cannot sign silently
        final req = keyAuthReq ?? AuthRequirement.none;
        if (req == AuthRequirement.none) {
          final sig = await _signet.sign(h, digest,
              options: SignOptions(encoding: encoding));
          signature = sig;
          _log(LogKind.sign, 'Digest signed',
              'silent · ${_encName(encoding)} · ${sig.length} bytes');
        } else {
          _log(LogKind.info, 'Awaiting authentication',
              'the key requires ${_authName(req).toLowerCase()}');
          final sig = await _signet.sign(h, digest,
              options: SignOptions(encoding: encoding),
              prompt: AuthPrompt(
                  title: promptTitle,
                  subtitle: promptSubtitle,
                  authRequirement: req));
          signature = sig;
          _log(LogKind.sign, 'Signed with authentication',
              '${_authName(req)} · ${_encName(encoding)} · ${sig.length} bytes');
        }
      });

  Future<void> _generateKey({AuthRequirement? authReqOverride}) async {
    final req = authReqOverride ?? authReq;
    await _signet.delete(alias);
    signature = null;
    final (h, r) = await _signet.generateKey(
      alias: alias,
      tierPolicy: policy,
      authRequirement: req,
      authValiditySeconds: authValidity == 0 ? null : authValidity,
      invalidateOnBiometricEnrollment: invalidateOnEnrollment,
      attestationChallenge: challenge.trim().isEmpty
          ? null
          : Uint8List.fromList(utf8.encode(challenge.trim())),
    );
    handle = h;
    report = r;
    keyAuthReq = req;
    aliasExists = true;
    publicKey = await _signet.getPublicKey(h, format: pkFormat);
    attestation = await _signet.getAttestation(h);
    _log(LogKind.key, 'Key generated',
        '${_tierName(r.achieved)} · auth ${_authName(req).toLowerCase()} · ${_policyName(policy)}');
  }

  Future<void> rereadTier() => _guard(() async {
        final h = handle;
        if (h == null) return;
        report = await _signet.getSecurityTier(h);
        _log(LogKind.ok, 'Tier re-read',
            '${_tierName(report!.achieved)} · authEnforced ${report!.authEnforced?.name ?? 'unobservable'}');
      });

  Future<void> checkExists() => _guard(() async {
        aliasExists = await _signet.exists(alias);
        _log(LogKind.info, 'Exists check', '$aliasExists for "$alias"');
      });

  Future<void> deleteKey() => _guard(() async {
        await _signet.delete(alias);
        handle = null;
        report = null;
        keyAuthReq = null;
        publicKey = null;
        signature = null;
        attestation = null;
        aliasExists = false;
        _log(LogKind.info, 'Key deleted', 'alias "$alias" removed');
      });

  void _set(void Function() f) {
    f();
    notifyListeners();
  }

  void _log(LogKind kind, String title, [String? detail]) {
    debugPrint('[signet] ${kind.name} $title${detail == null ? '' : ' :: $detail'}');
    events.insert(0, LogEvent(DateTime.now(), kind, title, detail));
  }

  Future<void> _guard(Future<void> Function() body) async {
    busy = true;
    notifyListeners();
    try {
      await body();
    } on SignetException catch (e) {
      _log(LogKind.error, 'Signet error', e.code.name);
    } catch (e) {
      _log(LogKind.error, 'Error', '$e');
    } finally {
      busy = false;
      notifyListeners();
    }
  }
}

String _tierName(SecurityLevel l) => switch (l) {
      SecurityLevel.secureEnclave => 'Secure Enclave',
      SecurityLevel.strongBox => 'StrongBox',
      SecurityLevel.tee => 'Trusted environment',
    };

String _tierShort(SecurityLevel l) => switch (l) {
      SecurityLevel.secureEnclave => 'SE',
      SecurityLevel.strongBox => 'StrongBox',
      SecurityLevel.tee => 'TEE',
    };

String _policyName(TierPolicy p) => switch (p) {
      Strongest() => 'strongest',
      AtLeast(:final floor) => 'at least ${floor.name}',
    };

String _authName(AuthRequirement r) => switch (r) {
      AuthRequirement.none => 'Silent',
      AuthRequirement.biometricOnly => 'Biometric',
      AuthRequirement.biometricOrDeviceCredential => 'Biometric or passcode',
    };

IconData _authIcon(AuthRequirement r) => switch (r) {
      AuthRequirement.none => Icons.bolt,
      AuthRequirement.biometricOnly => Icons.fingerprint,
      AuthRequirement.biometricOrDeviceCredential => Icons.password,
    };

String _encName(SignEncoding e) => e == SignEncoding.der ? 'DER' : 'raw r‖s';

bool _isSecure(SecurityLevel? l) =>
    l == SecurityLevel.secureEnclave || l == SecurityLevel.strongBox;

String _hex(Uint8List b, {int max = 22}) {
  final head = b.take(max).map((x) => x.toRadixString(16).padLeft(2, '0'));
  final tail = b.length > max ? ' … ${b.length} bytes' : '';
  return '${head.join(' ')}$tail';
}

TextStyle _mono({double size = 12.5, Color color = _ink, FontWeight? weight}) =>
    GoogleFonts.jetBrainsMono(
        fontSize: size,
        color: color,
        height: 1.55,
        letterSpacing: 0.2,
        fontWeight: weight);

// ---- shell ----

class AppShell extends StatefulWidget {
  const AppShell({super.key});
  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  final SignetController c = SignetController();
  int index = 0;

  static const _dests = [
    (Icons.dashboard_outlined, Icons.dashboard, 'Overview'),
    (Icons.key_outlined, Icons.key, 'Keys'),
    (Icons.draw_outlined, Icons.draw, 'Sign'),
    (Icons.verified_user_outlined, Icons.verified_user, 'Attest'),
    (Icons.receipt_long_outlined, Icons.receipt_long, 'Activity'),
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => c.bootstrap());
  }

  @override
  void dispose() {
    c.dispose();
    super.dispose();
  }

  Widget _screen() => switch (index) {
        1 => KeysScreen(c),
        2 => SignScreen(c, onOpenKeys: () => setState(() => index = 1)),
        3 => AttestScreen(c),
        4 => ActivityScreen(c),
        _ => OverviewScreen(c, onGoTo: (i) => setState(() => index = i)),
      };

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, box) {
      final wide = box.maxWidth >= 720;
      final body = AnimatedBuilder(animation: c, builder: (_, _) => _screen());
      if (wide) {
        return Scaffold(
          body: Row(children: [
            _rail(),
            const VerticalDivider(width: 1),
            Expanded(
              child: Column(children: [
                _desktopBar(),
                const Divider(height: 1),
                Expanded(child: body),
              ]),
            ),
          ]),
        );
      }
      return Scaffold(
        appBar: _mobileBar(),
        body: body,
        floatingActionButton: AnimatedBuilder(
          animation: c,
          builder: (_, _) => FloatingActionButton(
            onPressed: c.busy ? null : () => setState(() => index = 2),
            backgroundColor: _ink,
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18),
                side: const BorderSide(color: _brass, width: 1.4)),
            child: const Icon(Icons.draw_outlined),
          ),
        ),
        bottomNavigationBar: NavigationBar(
          selectedIndex: index,
          onDestinationSelected: (i) => setState(() => index = i),
          height: 66,
          destinations: [
            for (final d in _dests)
              NavigationDestination(
                  icon: Icon(d.$1), selectedIcon: Icon(d.$2), label: d.$3),
          ],
        ),
      );
    });
  }

  Widget _rail() {
    return NavigationRail(
      selectedIndex: index,
      onDestinationSelected: (i) => setState(() => index = i),
      labelType: NavigationRailLabelType.all,
      leading: const Padding(
        padding: EdgeInsets.only(top: 8, bottom: 10),
        child: SealEmblem(size: 34),
      ),
      destinations: [
        for (final d in _dests)
          NavigationRailDestination(
              icon: Icon(d.$1), selectedIcon: Icon(d.$2), label: Text(d.$3)),
      ],
    );
  }

  Widget _desktopBar() {
    const titles = ['Overview', 'Keys', 'Sign', 'Attestation', 'Activity'];
    return Container(
      color: Colors.white,
      padding: const EdgeInsets.fromLTRB(24, 16, 20, 16),
      child: Row(children: [
        Text(titles[index],
            style: GoogleFonts.manrope(fontSize: 19, fontWeight: FontWeight.w600)),
        const Spacer(),
        AnimatedBuilder(animation: c, builder: (_, _) => TierPill(c.report)),
        const SizedBox(width: 14),
        const CircleAvatar(
            radius: 16,
            backgroundColor: _brassContainer,
            child: Icon(Icons.key, size: 16, color: _brassOn)),
      ]),
    );
  }

  PreferredSizeWidget _mobileBar() {
    return AppBar(
      backgroundColor: Colors.white,
      surfaceTintColor: Colors.white,
      elevation: 0,
      titleSpacing: 16,
      title: Row(children: [
        const SealEmblem(size: 26),
        const SizedBox(width: 9),
        Text('Signet',
            style: GoogleFonts.manrope(fontSize: 17, fontWeight: FontWeight.w600)),
      ]),
      actions: [
        AnimatedBuilder(
            animation: c,
            builder: (_, _) => Padding(
                padding: const EdgeInsets.only(right: 12),
                child: TierPill(c.report, compact: true))),
      ],
      bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: _line)),
    );
  }
}

// ---- screens ----

class OverviewScreen extends StatelessWidget {
  const OverviewScreen(this.c, {super.key, required this.onGoTo});
  final SignetController c;
  final void Function(int) onGoTo;

  @override
  Widget build(BuildContext context) {
    return _ScreenScroll(children: [
      TierHero(c.report, busy: c.busy),
      const SizedBox(height: 16),
      LayoutBuilder(builder: (context, box) {
        final key = KeyCard(c);
        final sign = QuickSignCard(c, onOpen: () => onGoTo(2));
        if (box.maxWidth >= 620) {
          return Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: key),
            const SizedBox(width: 16),
            Expanded(child: sign),
          ]);
        }
        return Column(children: [key, const SizedBox(height: 16), sign]);
      }),
      const SizedBox(height: 16),
      ActivityCard(c, limit: 5, onSeeAll: () => onGoTo(4)),
    ]);
  }
}

class KeysScreen extends StatefulWidget {
  const KeysScreen(this.c, {super.key});
  final SignetController c;
  @override
  State<KeysScreen> createState() => _KeysScreenState();
}

class _KeysScreenState extends State<KeysScreen> {
  late final TextEditingController _challenge =
      TextEditingController(text: widget.c.challenge);

  @override
  void dispose() {
    _challenge.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.c;
    return _ScreenScroll(children: [
      AppCard(
        title: 'Generate a key',
        trailing: const _Hint('non-exportable P-256'),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const _Label('Tier policy'),
          const SizedBox(height: 8),
          Wrap(spacing: 8, runSpacing: 8, children: [
            _Choice('Strongest', selected: c.policy is Strongest,
                onTap: () => c.setPolicy(const Strongest())),
            _Choice('At least discrete-secure',
                selected: c.policy is AtLeast &&
                    (c.policy as AtLeast).floor == HardwareClass.discreteSecure,
                onTap: () => c.setPolicy(
                    const AtLeast(HardwareClass.discreteSecure))),
            _Choice('At least trusted-env',
                selected: c.policy is AtLeast &&
                    (c.policy as AtLeast).floor ==
                        HardwareClass.trustedEnvironment,
                onTap: () => c.setPolicy(
                    const AtLeast(HardwareClass.trustedEnvironment))),
          ]),
          const SizedBox(height: 18),
          const _Label('Presence check (auth requirement)'),
          const SizedBox(height: 8),
          AuthChips(c),
          const SizedBox(height: 18),
          const _Label('Auth reuse window'),
          const SizedBox(height: 8),
          Wrap(spacing: 8, runSpacing: 8, children: [
            for (final s in const [0, 10, 30, 60])
              _Choice(s == 0 ? 'Per use' : '${s}s',
                  selected: c.authValidity == s, onTap: () => c.setValidity(s)),
          ]),
          const SizedBox(height: 6),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            activeThumbColor: _emerald,
            title: const Text('Invalidate on biometric enrollment',
                style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w500)),
            subtitle: const Text('a later fingerprint or face enrollment voids the key',
                style: TextStyle(fontSize: 12, color: _muted)),
            value: c.invalidateOnEnrollment,
            onChanged: c.setInvalidate,
          ),
          const SizedBox(height: 10),
          const _Label('Attestation challenge'),
          const SizedBox(height: 6),
          _Field(
            controller: _challenge,
            hint: 'bound into the key at generation',
            onChanged: c.setChallenge,
          ),
          const SizedBox(height: 18),
          Row(children: [
            FilledButton.icon(
              onPressed: c.busy ? null : c.generate,
              style: FilledButton.styleFrom(backgroundColor: _ink),
              icon: const Icon(Icons.add, size: 18),
              label: const Text('Generate key'),
            ),
            const SizedBox(width: 10),
            OutlinedButton.icon(
              onPressed: c.busy ? null : c.checkExists,
              style: OutlinedButton.styleFrom(
                  foregroundColor: _ink, side: const BorderSide(color: _line)),
              icon: const Icon(Icons.search, size: 18),
              label: const Text('Exists?'),
            ),
          ]),
        ]),
      ),
      const SizedBox(height: 16),
      KeyCard(c, showFormatToggle: true),
      if (c.report != null) ...[
        const SizedBox(height: 16),
        ReportCard(c.report!),
      ],
    ]);
  }
}

class SignScreen extends StatefulWidget {
  const SignScreen(this.c, {super.key, required this.onOpenKeys});
  final SignetController c;
  final VoidCallback onOpenKeys;
  @override
  State<SignScreen> createState() => _SignScreenState();
}

class _SignScreenState extends State<SignScreen> {
  late final TextEditingController _title =
      TextEditingController(text: widget.c.promptTitle);
  late final TextEditingController _subtitle =
      TextEditingController(text: widget.c.promptSubtitle);

  @override
  void dispose() {
    _title.dispose();
    _subtitle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.c;
    final keyReq = c.keyAuthReq ?? AuthRequirement.none;
    final gated = keyReq != AuthRequirement.none;
    final hasKey = c.handle != null;
    final sig = c.signature;
    return _ScreenScroll(children: [
      AppCard(
        title: 'Sign a digest',
        trailing: _StatusPill(
            c.report == null ? 'no key' : _tierName(c.report!.achieved),
            _isSecure(c.report?.achieved)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            padding: const EdgeInsets.all(13),
            decoration: BoxDecoration(
                color: _fieldBg,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: _line)),
            child: Row(children: [
              Icon(_authIcon(keyReq), size: 19, color: gated ? _brassOn : _muted),
              const SizedBox(width: 11),
              Expanded(
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                          hasKey
                              ? 'Presence check: ${_authName(keyReq)}'
                              : 'No active key',
                          style: GoogleFonts.manrope(
                              fontSize: 13.5, fontWeight: FontWeight.w600)),
                      const SizedBox(height: 2),
                      Text(
                          !hasKey
                              ? 'Generate a key in the Keys tab.'
                              : !gated
                                  ? 'This key signs with no prompt. A silent key cannot later be made to require biometrics.'
                                  : _isSecure(c.report?.achieved)
                                      ? 'Bound at generation and enforced in secure hardware. Every signature authenticates; this key cannot sign silently.'
                                      : 'Bound at generation. Every signature authenticates; this key cannot sign silently.',
                          style: const TextStyle(
                              color: _muted, fontSize: 12, height: 1.45)),
                    ]),
              ),
            ]),
          ),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: widget.onOpenKeys,
              style: TextButton.styleFrom(
                  foregroundColor: _muted,
                  padding: const EdgeInsets.symmetric(horizontal: 4)),
              icon: const Icon(Icons.tune, size: 16),
              label: const Text('Set the presence check in Keys'),
            ),
          ),
          const SizedBox(height: 8),
          const _Label('Encoding'),
          const SizedBox(height: 8),
          Wrap(spacing: 8, children: [
            _Choice('DER',
                selected: c.encoding == SignEncoding.der,
                onTap: () => c.setEncoding(SignEncoding.der)),
            _Choice('raw r‖s',
                selected: c.encoding == SignEncoding.rawRS,
                onTap: () => c.setEncoding(SignEncoding.rawRS)),
          ]),
          if (gated) ...[
            const SizedBox(height: 16),
            const _Label('Prompt title'),
            const SizedBox(height: 6),
            _Field(controller: _title, onChanged: c.setPromptTitle),
            const SizedBox(height: 10),
            const _Label('Prompt subtitle'),
            const SizedBox(height: 6),
            _Field(controller: _subtitle, onChanged: c.setPromptSubtitle),
          ],
          const SizedBox(height: 18),
          FilledButton.icon(
            onPressed: c.busy || !hasKey ? null : c.sign,
            style: FilledButton.styleFrom(
                backgroundColor: _ink,
                padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 14)),
            icon: Icon(gated ? _authIcon(keyReq) : Icons.draw_outlined, size: 18),
            label: Text(gated ? 'Authenticate and sign' : 'Sign'),
          ),
          if (sig != null) ...[
            const SizedBox(height: 18),
            const _Label('Signature'),
            const SizedBox(height: 6),
            HexBlock(sig,
                caption:
                    '${sig.length} bytes · ${_encName(c.encoding)} · signed in ${_tierName(c.report!.achieved)}'),
          ],
        ]),
      ),
    ]);
  }
}

class AttestScreen extends StatelessWidget {
  const AttestScreen(this.c, {super.key});
  final SignetController c;

  @override
  Widget build(BuildContext context) {
    final a = c.attestation;
    return _ScreenScroll(children: [
      AppCard(
        title: 'Attestation',
        trailing: _StatusPill(a == null ? 'none' : a.format.name,
            a?.format == AttestationFormat.androidKeyChain),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(
            a == null
                ? 'Generate a key to read its attestation.'
                : a.format == AttestationFormat.none
                    ? 'Format none. The Apple Secure Enclave exposes no per-key attestation; on Android this returns the androidKeyChain certificate chain, challenge-bound at generation. Produced, never verified, by the library.'
                    : '${a.chain?.length ?? 0} certificate(s) in the chain.',
            style: const TextStyle(color: _muted, height: 1.55, fontSize: 14),
          ),
          if (a != null && (a.chain?.isNotEmpty ?? false)) ...[
            const SizedBox(height: 12),
            for (var i = 0; i < a.chain!.length; i++)
              HexBlock(a.chain![i], label: 'cert $i'),
          ],
        ]),
      ),
      const SizedBox(height: 16),
      const AppCard(title: 'Hardware tier ladder', child: TierLadder()),
    ]);
  }
}

class ActivityScreen extends StatelessWidget {
  const ActivityScreen(this.c, {super.key});
  final SignetController c;
  @override
  Widget build(BuildContext context) =>
      _ScreenScroll(children: [ActivityCard(c, limit: 100)]);
}

// ---- shared widgets ----

class _ScreenScroll extends StatelessWidget {
  const _ScreenScroll({required this.children});
  final List<Widget> children;
  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, box) {
      final pad = box.maxWidth >= 720 ? 24.0 : 16.0;
      return SingleChildScrollView(
        padding: EdgeInsets.fromLTRB(pad, pad, pad, pad + 28),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 1000),
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch, children: children),
          ),
        ),
      );
    });
  }
}

class AuthChips extends StatelessWidget {
  const AuthChips(this.c, {super.key});
  final SignetController c;
  @override
  Widget build(BuildContext context) {
    return Wrap(spacing: 8, runSpacing: 8, children: [
      for (final r in AuthRequirement.values)
        _Choice(_authName(r),
            icon: _authIcon(r),
            selected: c.authReq == r,
            onTap: c.busy ? null : () => c.setAuthReq(r)),
    ]);
  }
}

class _Choice extends StatelessWidget {
  const _Choice(this.label, {this.icon, required this.selected, this.onTap});
  final String label;
  final IconData? icon;
  final bool selected;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) {
    return Material(
      color: selected ? _brassContainer : Colors.white,
      shape: StadiumBorder(
          side: BorderSide(color: selected ? _brass : _line, width: selected ? 1.2 : 1)),
      child: InkWell(
        onTap: onTap,
        customBorder: const StadiumBorder(),
        child: Padding(
          padding: EdgeInsets.fromLTRB(icon == null ? 14 : 11, 8, 14, 8),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            if (icon != null) ...[
              Icon(icon, size: 15, color: selected ? _brassOn : _muted),
              const SizedBox(width: 6),
            ],
            Text(label,
                style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                    color: selected ? _brassOn : _ink)),
          ]),
        ),
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({required this.controller, this.hint, this.onChanged});
  final TextEditingController controller;
  final String? hint;
  final ValueChanged<String>? onChanged;
  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      onChanged: onChanged,
      style: _mono(size: 13),
      cursorColor: _ink,
      decoration: InputDecoration(
        isDense: true,
        filled: true,
        fillColor: _fieldBg,
        hintText: hint,
        hintStyle: const TextStyle(color: _faint, fontSize: 13),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
        enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _line)),
        focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _brass, width: 1.4)),
      ),
    );
  }
}

class SealEmblem extends StatelessWidget {
  const SealEmblem({super.key, this.size = 72, this.inner = _ink});
  final double size;
  final Color inner;
  @override
  Widget build(BuildContext context) => SizedBox(
      width: size, height: size, child: CustomPaint(painter: _SealPainter(inner)));
}

class _SealPainter extends CustomPainter {
  _SealPainter(this.inner);
  final Color inner;
  @override
  void paint(Canvas canvas, Size s) {
    final r = s.width / 2;
    final ctr = Offset(r, r);
    canvas.drawCircle(ctr, r, Paint()..color = inner);
    canvas.drawCircle(
        ctr,
        r - s.width * 0.03,
        Paint()
          ..color = _brass
          ..style = PaintingStyle.stroke
          ..strokeWidth = s.width * 0.045);
    canvas.drawCircle(
        ctr,
        r * 0.80,
        Paint()
          ..color = _brass.withValues(alpha: 0.4)
          ..style = PaintingStyle.stroke
          ..strokeWidth = s.width * 0.012);
    final kh = Paint()..color = _parch;
    canvas.drawCircle(Offset(r, r * 0.85), r * 0.20, kh);
    final w = r * 0.14;
    final path = Path()
      ..moveTo(r - w, r * 0.98)
      ..lineTo(r + w, r * 0.98)
      ..lineTo(r + w * 1.8, r * 1.42)
      ..lineTo(r - w * 1.8, r * 1.42)
      ..close();
    canvas.drawPath(path, kh);
  }

  @override
  bool shouldRepaint(covariant _SealPainter old) => old.inner != inner;
}

class AppCard extends StatelessWidget {
  const AppCard({super.key, this.title, this.trailing, required this.child});
  final String? title;
  final Widget? trailing;
  final Widget child;
  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: _line),
        boxShadow: const [
          BoxShadow(color: Color(0x0F24262C), blurRadius: 16, offset: Offset(0, 6)),
        ],
      ),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 18),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        if (title != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 14),
            child: Row(children: [
              Expanded(
                child: Text(title!,
                    style: GoogleFonts.manrope(
                        fontSize: 15.5, fontWeight: FontWeight.w600)),
              ),
              ?trailing,
            ]),
          ),
        child,
      ]),
    );
  }
}

class TierHero extends StatelessWidget {
  const TierHero(this.report, {super.key, required this.busy});
  final SecurityTierReport? report;
  final bool busy;
  @override
  Widget build(BuildContext context) {
    final r = report;
    final name = r == null ? 'Detecting…' : _tierName(r.achieved);
    return Container(
      decoration: BoxDecoration(
        color: _ink,
        borderRadius: BorderRadius.circular(24),
        boxShadow: const [
          BoxShadow(color: Color(0x3324262C), blurRadius: 28, offset: Offset(0, 12)),
        ],
      ),
      padding: const EdgeInsets.all(22),
      child: Row(children: [
        const SealEmblem(size: 82, inner: Color(0xFF1C1E24)),
        const SizedBox(width: 20),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Text('Hardware tier',
                  style: GoogleFonts.manrope(
                      color: _brass,
                      fontSize: 11.5,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.4)),
              if (busy) ...[
                const SizedBox(width: 10),
                const SizedBox(
                    width: 12,
                    height: 12,
                    child: CircularProgressIndicator(strokeWidth: 2, color: _brass)),
              ],
            ]),
            const SizedBox(height: 6),
            Text(name,
                style: GoogleFonts.manrope(
                    color: Colors.white, fontSize: 25, fontWeight: FontWeight.w600)),
            const SizedBox(height: 7),
            Text(
                r == null
                    ? 'Reading the key store'
                    : 'P-256 · non-exportable · evidence: ${r.evidence.name}',
                style: const TextStyle(color: Color(0xFFC7C4BB), fontSize: 13)),
            if (r != null) ...[
              const SizedBox(height: 14),
              Wrap(spacing: 8, runSpacing: 8, children: [
                _HeroChip('auth', r.authEnforced?.name ?? 'none'),
                _HeroChip('schema', 'v${r.schemaVersion}'),
              ]),
            ],
          ]),
        ),
      ]),
    );
  }
}

class _HeroChip extends StatelessWidget {
  const _HeroChip(this.label, this.value);
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 6),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.09),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: Colors.white.withValues(alpha: 0.16)),
      ),
      child: Text.rich(TextSpan(children: [
        TextSpan(
            text: '$label ',
            style: const TextStyle(color: Color(0xFFBFBCB3), fontSize: 12)),
        TextSpan(
            text: value,
            style: const TextStyle(
                color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600)),
      ])),
    );
  }
}

class TierPill extends StatelessWidget {
  const TierPill(this.report, {super.key, this.compact = false});
  final SecurityTierReport? report;
  final bool compact;
  @override
  Widget build(BuildContext context) {
    final r = report;
    final secure = _isSecure(r?.achieved);
    final bg = r == null
        ? const Color(0xFFEDEAE2)
        : secure
            ? _emeraldContainer
            : const Color(0xFFF6E8CE);
    final fg = r == null
        ? _muted
        : secure
            ? _emeraldOn
            : const Color(0xFF8A5A12);
    final label = r == null
        ? 'probing'
        : compact
            ? _tierShort(r.achieved)
            : _tierName(r.achieved);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 6),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(999)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(secure ? Icons.verified : Icons.memory, size: 14, color: fg),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(color: fg, fontSize: 12, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}

class KeyCard extends StatelessWidget {
  const KeyCard(this.c, {super.key, this.showFormatToggle = false});
  final SignetController c;
  final bool showFormatToggle;
  @override
  Widget build(BuildContext context) {
    final pk = c.publicKey;
    return AppCard(
      title: 'Active key',
      trailing: _StatusPill(
          c.report == null ? 'none' : _tierName(c.report!.achieved),
          _isSecure(c.report?.achieved)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const _Label('Alias'),
        const SizedBox(height: 5),
        HexBlock.text(c.handle?.id ?? '-'),
        const SizedBox(height: 12),
        Row(children: [
          Text('Public key · ${c.pkFormat == PublicKeyFormat.rawX962 ? 'X9.63' : 'SPKI'}',
              style: const TextStyle(fontSize: 12, color: _muted)),
          const Spacer(),
          if (showFormatToggle)
            _MiniToggle(
              left: 'X9.63',
              right: 'SPKI',
              rightSelected: c.pkFormat == PublicKeyFormat.spki,
              onLeft: () => c.setPkFormat(PublicKeyFormat.rawX962),
              onRight: () => c.setPkFormat(PublicKeyFormat.spki),
            ),
        ]),
        const SizedBox(height: 5),
        if (pk != null)
          HexBlock(pk.bytes,
              caption:
                  '${pk.bytes.length} bytes · ${c.pkFormat == PublicKeyFormat.rawX962 ? 'uncompressed point' : 'SubjectPublicKeyInfo'}')
        else
          HexBlock.text('-'),
        const SizedBox(height: 16),
        Wrap(spacing: 10, runSpacing: 8, children: [
          FilledButton.tonal(
            onPressed: c.busy ? null : c.generate,
            style: FilledButton.styleFrom(
                backgroundColor: _brassContainer, foregroundColor: _brassOn),
            child: const Text('Regenerate'),
          ),
          OutlinedButton(
            onPressed: c.busy ? null : c.rereadTier,
            style: OutlinedButton.styleFrom(
                foregroundColor: _ink, side: const BorderSide(color: _line)),
            child: const Text('Re-read tier'),
          ),
          TextButton(
            onPressed: c.busy ? null : c.deleteKey,
            style: TextButton.styleFrom(foregroundColor: _danger),
            child: const Text('Delete'),
          ),
        ]),
      ]),
    );
  }
}

class QuickSignCard extends StatelessWidget {
  const QuickSignCard(this.c, {super.key, required this.onOpen});
  final SignetController c;
  final VoidCallback onOpen;
  @override
  Widget build(BuildContext context) {
    final sig = c.signature;
    final keyReq = c.keyAuthReq ?? AuthRequirement.none;
    final gated = keyReq != AuthRequirement.none;
    final hasKey = c.handle != null;
    return AppCard(
      title: 'Sign',
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(_authIcon(keyReq), size: 14, color: _muted),
        const SizedBox(width: 5),
        Text(_authName(keyReq),
            style: const TextStyle(
                fontSize: 12, color: _muted, fontWeight: FontWeight.w600)),
      ]),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Wrap(spacing: 8, children: [
          _Choice('DER',
              selected: c.encoding == SignEncoding.der,
              onTap: () => c.setEncoding(SignEncoding.der)),
          _Choice('raw r‖s',
              selected: c.encoding == SignEncoding.rawRS,
              onTap: () => c.setEncoding(SignEncoding.rawRS)),
        ]),
        const SizedBox(height: 12),
        if (sig != null)
          HexBlock(sig, caption: '${sig.length} bytes · ${_encName(c.encoding)}')
        else
          Text('demo digest · 32 bytes', style: _mono(size: 12, color: _muted)),
        const SizedBox(height: 14),
        Row(children: [
          FilledButton.icon(
            onPressed: c.busy || !hasKey ? null : c.sign,
            style: FilledButton.styleFrom(backgroundColor: _ink),
            icon: Icon(gated ? _authIcon(keyReq) : Icons.draw_outlined, size: 18),
            label: Text(gated ? 'Authenticate and sign' : 'Sign'),
          ),
          const SizedBox(width: 10),
          TextButton(
              onPressed: onOpen,
              style: TextButton.styleFrom(foregroundColor: _muted),
              child: const Text('Details')),
        ]),
      ]),
    );
  }
}

class ReportCard extends StatelessWidget {
  const ReportCard(this.r, {super.key});
  final SecurityTierReport r;
  @override
  Widget build(BuildContext context) {
    return AppCard(
      title: 'Security tier report',
      trailing: const _Hint('read from the created key'),
      child: Column(children: [
        _row('achieved', _tierName(r.achieved)),
        _row('requested', r.requested == null ? 'null' : _policyName(r.requested!)),
        _row('evidence', r.evidence.name),
        _row('auth enforced', r.authEnforced?.name ?? 'unobservable'),
        _row('invalidated', '${r.invalidated}',
            color: r.invalidated ? _danger : null),
        _row('schema', 'v${r.schemaVersion}', last: true),
      ]),
    );
  }

  Widget _row(String k, String v, {Color? color, bool last = false}) => Container(
        decoration: BoxDecoration(
            border: last ? null : const Border(bottom: BorderSide(color: _line))),
        padding: const EdgeInsets.symmetric(vertical: 10),
        child: Row(children: [
          Text(k, style: const TextStyle(color: _muted, fontSize: 13)),
          const Spacer(),
          Text(v, style: _mono(size: 12.5, color: color ?? _ink, weight: FontWeight.w500)),
        ]),
      );
}

class _MiniToggle extends StatelessWidget {
  const _MiniToggle(
      {required this.left,
      required this.right,
      required this.rightSelected,
      required this.onLeft,
      required this.onRight});
  final String left;
  final String right;
  final bool rightSelected;
  final VoidCallback onLeft;
  final VoidCallback onRight;
  @override
  Widget build(BuildContext context) {
    Widget seg(String t, bool sel, VoidCallback tap) => InkWell(
          onTap: tap,
          borderRadius: BorderRadius.circular(999),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 5),
            decoration: BoxDecoration(
                color: sel ? Colors.white : Colors.transparent,
                borderRadius: BorderRadius.circular(999),
                border: sel ? Border.all(color: _line) : null),
            child: Text(t,
                style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w600,
                    color: sel ? _ink : _muted)),
          ),
        );
    return Container(
      padding: const EdgeInsets.all(3),
      decoration: BoxDecoration(
          color: _fieldBg, borderRadius: BorderRadius.circular(999)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        seg(left, !rightSelected, onLeft),
        seg(right, rightSelected, onRight),
      ]),
    );
  }
}

class ActivityCard extends StatelessWidget {
  const ActivityCard(this.c, {super.key, this.limit = 5, this.onSeeAll});
  final SignetController c;
  final int limit;
  final VoidCallback? onSeeAll;
  @override
  Widget build(BuildContext context) {
    final items = c.events.take(limit).toList();
    return AppCard(
      title: 'Activity',
      trailing: onSeeAll != null && c.events.length > limit
          ? TextButton(
              onPressed: onSeeAll,
              style: TextButton.styleFrom(foregroundColor: _muted),
              child: const Text('See all'))
          : const _Hint('today'),
      child: items.isEmpty
          ? const Padding(
              padding: EdgeInsets.symmetric(vertical: 14),
              child: Text('No operations yet.',
                  style: TextStyle(color: _muted, fontSize: 13)))
          : Column(children: [
              for (var i = 0; i < items.length; i++)
                _ActRow(items[i], first: i == 0),
            ]),
    );
  }
}

class _ActRow extends StatelessWidget {
  const _ActRow(this.e, {required this.first});
  final LogEvent e;
  final bool first;
  @override
  Widget build(BuildContext context) {
    final (icon, bg, fg) = switch (e.kind) {
      LogKind.ok => (Icons.check, _emeraldContainer, _emeraldOn),
      LogKind.key => (Icons.key_outlined, _brassContainer, _brassOn),
      LogKind.sign => (Icons.draw_outlined, const Color(0xFFEDEAE2), _ink),
      LogKind.attest => (Icons.verified_user_outlined, _brassContainer, _brassOn),
      LogKind.error => (Icons.error_outline, const Color(0xFFF6DEDE), _danger),
      LogKind.info => (Icons.info_outline, const Color(0xFFEDEAE2), _muted),
    };
    return Container(
      decoration: BoxDecoration(
          border: first ? null : const Border(top: BorderSide(color: _line))),
      padding: const EdgeInsets.symmetric(vertical: 11),
      child: Row(children: [
        Container(
          width: 34,
          height: 34,
          decoration: BoxDecoration(color: bg, shape: BoxShape.circle),
          child: Icon(icon, size: 17, color: fg),
        ),
        const SizedBox(width: 13),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(e.title,
                style: GoogleFonts.manrope(
                    fontSize: 13.5, fontWeight: FontWeight.w600)),
            if (e.detail != null)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(e.detail!,
                    style: const TextStyle(color: _muted, fontSize: 12)),
              ),
          ]),
        ),
        const SizedBox(width: 10),
        Text(_hhmmss(e.time), style: _mono(size: 11.5, color: _faint)),
      ]),
    );
  }
}

class HexBlock extends StatelessWidget {
  const HexBlock(this.bytes, {super.key, this.caption, this.label}) : text = null;
  const HexBlock.text(this.text, {super.key})
      : bytes = null,
        caption = null,
        label = null;
  final Uint8List? bytes;
  final String? text;
  final String? caption;
  final String? label;

  @override
  Widget build(BuildContext context) {
    final content = text ?? _hex(bytes!);
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      if (label != null)
        Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Text(label!, style: const TextStyle(fontSize: 11.5, color: _muted))),
      Container(
        width: double.infinity,
        padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
        decoration: BoxDecoration(
            color: _fieldBg,
            border: Border.all(color: _line),
            borderRadius: BorderRadius.circular(12)),
        child: Row(children: [
          Expanded(child: Text(content, style: _mono())),
          InkWell(
            onTap: () async {
              await Clipboard.setData(ClipboardData(text: content));
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                    content: Text('Copied'),
                    duration: Duration(milliseconds: 900)));
              }
            },
            child: const Padding(
                padding: EdgeInsets.all(4),
                child: Icon(Icons.copy_outlined, size: 15, color: _muted)),
          ),
        ]),
      ),
      if (caption != null)
        Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Text(caption!,
                style: const TextStyle(fontSize: 11.5, color: _faint))),
    ]);
  }
}

class TierLadder extends StatelessWidget {
  const TierLadder({super.key});
  @override
  Widget build(BuildContext context) {
    Widget rung(String name, String note, Color dot) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 7),
          child: Row(children: [
            Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(color: dot, shape: BoxShape.circle)),
            const SizedBox(width: 12),
            Text(name,
                style: GoogleFonts.manrope(
                    fontWeight: FontWeight.w600, fontSize: 13.5)),
            const SizedBox(width: 8),
            Expanded(
                child: Text(note,
                    style: const TextStyle(color: _muted, fontSize: 12.5))),
          ]),
        );
    return Column(children: [
      rung('Secure Enclave / StrongBox', 'discrete secure element', _emerald),
      const Divider(),
      rung('Trusted environment', 'TEE, on the main SoC', _brass),
    ]);
  }
}

class _StatusPill extends StatelessWidget {
  const _StatusPill(this.label, this.secure);
  final String label;
  final bool secure;
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
          color: secure ? _emeraldContainer : const Color(0xFFEDEAE2),
          borderRadius: BorderRadius.circular(999)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(secure ? Icons.check : Icons.remove,
            size: 13, color: secure ? _emeraldOn : _muted),
        const SizedBox(width: 5),
        Text(label,
            style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: secure ? _emeraldOn : _muted)),
      ]),
    );
  }
}

class _Label extends StatelessWidget {
  const _Label(this.text);
  final String text;
  @override
  Widget build(BuildContext context) =>
      Text(text, style: const TextStyle(fontSize: 12, color: _muted));
}

class _Hint extends StatelessWidget {
  const _Hint(this.text);
  final String text;
  @override
  Widget build(BuildContext context) =>
      Text(text, style: const TextStyle(fontSize: 12, color: _faint));
}

String _hhmmss(DateTime t) {
  String p(int n) => n.toString().padLeft(2, '0');
  return '${p(t.hour)}:${p(t.minute)}:${p(t.second)}';
}
