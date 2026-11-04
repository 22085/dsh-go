import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../l10n/l10n.dart';
import '../common/brief_notice.dart';
import '../shell/page_frame.dart';
import 'settings_widgets.dart';

/// Certificate generator: a self-signed PKCS12 certificate made on this phone,
/// through the native `dsh/cert` channel (the same pure-Java generator as the
/// standalone certificate tool, no third-party crypto). The file lands in the
/// Downloads folder; the password only protects the keystore and is never
/// stored, and only the fingerprints are shown back.
class CertGenPage extends StatefulWidget {
  const CertGenPage({super.key});

  @override
  State<CertGenPage> createState() => _CertGenPageState();
}

class _CertGenPageState extends State<CertGenPage> {
  static const _channel = MethodChannel('dsh/cert');

  final _alias = TextEditingController(text: 'mykey');
  final _password = TextEditingController();
  final _cn = TextEditingController(text: 'MyApp');
  final _org = TextEditingController();
  int _years = 25;
  int _keySize = 2048;
  bool _generating = false;
  bool _showPassword = false;
  Map<String, Object?>? _result;
  String? _error;

  @override
  void dispose() {
    _alias.dispose();
    _password.dispose();
    _cn.dispose();
    _org.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    final l10n = context.l10n;
    if (_password.text.length < 6) {
      setState(() => _error = l10n.certGenPasswordTooShort);
      return;
    }
    setState(() {
      _generating = true;
      _error = null;
      _result = null;
    });
    try {
      final raw = await _channel.invokeMethod<Map<Object?, Object?>>('generate', {
        'alias': _alias.text,
        'password': _password.text,
        'cn': _cn.text,
        'o': _org.text,
        'years': _years,
        'keySize': _keySize,
      });
      if (!mounted) return;
      setState(() => _result = raw?.map((k, v) => MapEntry(k.toString(), v)));
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message ?? l10n.certGenFailed);
    } finally {
      if (mounted) setState(() => _generating = false);
    }
  }

  void _randomPassword() {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
    final rnd = Random.secure();
    _password.text = String.fromCharCodes(
      List.generate(16, (_) => chars.codeUnitAt(rnd.nextInt(chars.length))),
    );
  }

  Future<void> _copy(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (mounted) showBriefNotice(context, context.l10n.certGenCopied);
  }

  String _expiry(Object? millis) {
    if (millis is! int) return '—';
    final d = DateTime.fromMillisecondsSinceEpoch(millis).toLocal();
    return '${d.year}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final result = _result;
    return AppPage.list(
      title: l10n.certGenTitle,
      subtitle: Text(l10n.certGenDescription),
      children: [
        SettingsSection(
          title: l10n.certGenTitle,
          children: [
            _field(_alias, l10n.certGenAlias),
            _passwordField(l10n),
            _field(_cn, l10n.certGenCommonName),
            _field(_org, l10n.certGenOrganization),
            _choice<int>(
              label: l10n.certGenValidityYears,
              value: _years,
              items: const [10, 25, 50],
              onChanged: (v) => setState(() => _years = v ?? 25),
            ),
            _choice<int>(
              label: l10n.certGenKeySize,
              value: _keySize,
              items: const [2048, 4096],
              onChanged: (v) => setState(() => _keySize = v ?? 2048),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: SettingsMetrics.inset,
                vertical: 8,
              ),
              child: FilledButton(
                onPressed: _generating ? null : _generate,
                child: Text(_generating ? l10n.certGenGenerating : l10n.certGenGenerate),
              ),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: SettingsMetrics.inset,
                  vertical: 4,
                ),
                child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ),
          ],
        ),
        if (result != null)
          SettingsSection(
            title: l10n.certGenResult,
            children: [
              InfoRow(label: l10n.certGenFilename, value: '${result['filename']}', mono: true),
              InfoRow(label: l10n.certGenExpiry, value: _expiry(result['notAfter']), mono: true),
              InfoRow(label: l10n.certGenSha1, value: '${result['sha1']}', mono: true),
              InfoRow(label: l10n.certGenSha256, value: '${result['sha256']}', mono: true),
              Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: SettingsMetrics.inset,
                  vertical: 8,
                ),
                child: Row(
                  children: [
                    OutlinedButton(
                      onPressed: () => _copy('${result['sha1']}'),
                      child: Text(l10n.certGenCopySha1),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton(
                      onPressed: () => _copy('${result['sha256']}'),
                      child: Text(l10n.certGenCopySha256),
                    ),
                  ],
                ),
              ),
            ],
          ),
      ],
    );
  }

  Widget _field(TextEditingController controller, String label) {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: SettingsMetrics.inset,
        vertical: 4,
      ),
      child: TextField(
        controller: controller,
        decoration: InputDecoration(labelText: label),
      ),
    );
  }

  Widget _passwordField(L10n l10n) {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: SettingsMetrics.inset,
        vertical: 4,
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _password,
              obscureText: !_showPassword,
              decoration: InputDecoration(
                labelText: l10n.certGenPassword,
                helperText: l10n.certGenPasswordHint,
              ),
            ),
          ),
          IconButton(
            icon: Icon(_showPassword ? Icons.visibility_off : Icons.visibility),
            onPressed: () => setState(() => _showPassword = !_showPassword),
          ),
          TextButton(onPressed: _randomPassword, child: Text(l10n.certGenRandomPassword)),
        ],
      ),
    );
  }

  Widget _choice<T>({
    required String label,
    required T value,
    required List<T> items,
    required ValueChanged<T?> onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: SettingsMetrics.inset,
        vertical: 4,
      ),
      child: Row(
        children: [
          Expanded(child: Text(label)),
          DropdownButton<T>(
            value: value,
            items: items
                .map((v) => DropdownMenuItem<T>(value: v, child: Text('$v')))
                .toList(),
            onChanged: onChanged,
          ),
        ],
      ),
    );
  }
}
