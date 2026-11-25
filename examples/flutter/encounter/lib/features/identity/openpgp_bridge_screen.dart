import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';
import '../../services/openpgp_codec.dart';

/// Slice 8: OpenPGP Interoperability Bridge & Cross-Certification screen.
class OpenPgpBridgeScreen extends StatefulWidget {
  final IdentityController controller;

  const OpenPgpBridgeScreen({super.key, required this.controller});

  @override
  State<OpenPgpBridgeScreen> createState() => _OpenPgpBridgeScreenState();
}

enum _OpenPgpErrorSection {
  inspect,
  export,
  peerImport,
  revocation,
  ownedImport,
}

class _OpenPgpBridgeScreenState extends State<OpenPgpBridgeScreen> {
  final TextEditingController _inspectController = TextEditingController();
  final TextEditingController _exportUidController = TextEditingController();
  final TextEditingController _exportDocController = TextEditingController(
    text: 'Mesh identity statement',
  );
  final TextEditingController _exportPeerCertController =
      TextEditingController();
  final TextEditingController _exportPeerUidController =
      TextEditingController();

  final TextEditingController _peerCertController = TextEditingController();
  final TextEditingController _peerKeyController = TextEditingController();
  final TextEditingController _peerUidController = TextEditingController();
  final TextEditingController _revocationController = TextEditingController();

  final TextEditingController _ownedCertController = TextEditingController();
  final TextEditingController _ownedKeyController = TextEditingController();
  final TextEditingController _ownedUidController = TextEditingController();
  final TextEditingController _ownedPassphraseController =
      TextEditingController();

  OpenPgpProfile _selectedProfile = OpenPgpProfile.v4;
  OpenPgpProfile _issuedProfile = OpenPgpProfile.v4;
  OpenPgpCertificate? _inspectedCert;
  OpenPgpExportPreview? _activePreview;
  OpenPgpArtifacts? _issuedArtifacts;
  OpenPgpProvenance? _peerProvenance;
  OpenPgpProvenance? _ownedProvenance;

  bool _isBusy = false;
  String? _errorMessage;
  _OpenPgpErrorSection _errorSection = _OpenPgpErrorSection.inspect;
  String? _statusMessage;

  @override
  void dispose() {
    _disposeActivePreview();
    _ownedCertController.clear();
    _ownedPassphraseController.clear();
    _inspectController.dispose();
    _exportUidController.dispose();
    _exportDocController.dispose();
    _exportPeerCertController.dispose();
    _exportPeerUidController.dispose();
    _peerCertController.dispose();
    _peerKeyController.dispose();
    _peerUidController.dispose();
    _revocationController.dispose();
    _ownedCertController.dispose();
    _ownedKeyController.dispose();
    _ownedUidController.dispose();
    _ownedPassphraseController.dispose();
    super.dispose();
  }

  void _disposeActivePreview() {
    final preview = _activePreview;
    _activePreview = null;
    if (preview != null && !preview.isDisposed) {
      preview.dispose();
    }
  }

  void _invalidatePreviewIfActive() {
    if (_activePreview != null) {
      setState(_disposeActivePreview);
    }
  }

  void _inspectCertificate() {
    setState(() {
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final bytes = decodeOpenPgpInput(
        _inspectController.text,
        label: 'OpenPGP certificate',
      );
      final cert = widget.controller.inspectOpenPgpCertificate(bytes);
      setState(() {
        _inspectedCert = cert;
        _statusMessage = 'Certificate parsed (unauthenticated).';
      });
    } on FormatException catch (e) {
      setState(() {
        _errorSection = _OpenPgpErrorSection.inspect;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      setState(() {
        _errorSection = _OpenPgpErrorSection.inspect;
        _errorMessage = e.message;
      });
    } catch (e) {
      setState(() {
        _errorSection = _OpenPgpErrorSection.inspect;
        _errorMessage = 'Failed to inspect certificate: $e';
      });
    }
  }

  Future<void> _previewExport() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final uid = _exportUidController.text.trim();
      if (uid.isEmpty) {
        throw const FormatException('Enter a User ID for the certificate.');
      }
      final docBytes = Uint8List.fromList(
        utf8.encode(_exportDocController.text),
      );
      Uint8List? peerCertBytes;
      String? peerUid;
      if (_exportPeerCertController.text.trim().isNotEmpty) {
        peerCertBytes = decodeOpenPgpInput(
          _exportPeerCertController.text,
          label: 'Peer OpenPGP certificate',
        );
        peerUid = _exportPeerUidController.text.trim();
        if (peerUid.isEmpty) {
          throw const FormatException(
            'Enter the Peer User ID to cross-certify.',
          );
        }
      }

      _disposeActivePreview();
      final preview = await widget.controller.createOpenPgpPreview(
        profile: _selectedProfile,
        userId: uid,
        document: docBytes,
        peerCertificate: peerCertBytes,
        peerUserId: peerUid,
      );
      if (!mounted) {
        if (!preview.isDisposed) preview.dispose();
        return;
      }
      setState(() {
        _activePreview = preview;
        _issuedArtifacts = null;
      });
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.export;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.export;
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.export;
        _errorMessage = 'Failed to create export preview: $e';
      });
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _confirmExport() async {
    final preview = _activePreview;
    if (preview == null) return;
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final artifacts = await widget.controller.confirmOpenPgpPreview(preview);
      if (!mounted) return;
      setState(() {
        _issuedProfile = preview.profile;
        _activePreview = null;
        _issuedArtifacts = artifacts;
        _statusMessage = 'OpenPGP artifacts issued.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _activePreview = null;
        _errorSection = _OpenPgpErrorSection.export;
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _activePreview = null;
        _errorSection = _OpenPgpErrorSection.export;
        _errorMessage = 'Failed to confirm OpenPGP export: $e';
      });
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _importPeer() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final certBytes = decodeOpenPgpInput(
        _peerCertController.text,
        label: 'Peer certificate',
      );
      final expectedKey = parseHexPublicKey(_peerKeyController.text);
      final uid = _peerUidController.text.trim();
      if (uid.isEmpty) {
        throw const FormatException('Enter the expected peer User ID.');
      }

      final provenance = await widget.controller.importOpenPgpPeer(
        certificate: certBytes,
        expectedPublicKey: expectedKey,
        userId: uid,
      );
      if (!mounted) return;
      setState(() {
        _peerProvenance = provenance;
        _statusMessage = 'Peer OpenPGP contact imported (unverified).';
      });
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.peerImport;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.peerImport;
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.peerImport;
        _errorMessage = 'Failed to import peer certificate: $e';
      });
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _rememberRevocations() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final revBytes = decodeOpenPgpInput(
        _revocationController.text,
        label: 'Revocation certificate',
      );
      await widget.controller.rememberOpenPgpRevocations(revBytes);
      if (!mounted) return;
      _revocationController.clear();
      setState(() {
        _statusMessage = 'OpenPGP revocation recorded.';
      });
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.revocation;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.revocation;
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.revocation;
        _errorMessage = 'Failed to record revocation: $e';
      });
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _importOwned() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    Uint8List? secretBytes;
    try {
      secretBytes = decodeOpenPgpInput(
        _ownedCertController.text,
        label: 'Owned secret key certificate',
      );
      final expectedKey = parseHexPublicKey(_ownedKeyController.text);
      final uid = _ownedUidController.text.trim();
      if (uid.isEmpty) {
        throw const FormatException('Enter the User ID on the secret key.');
      }
      // Dart Strings are immutable and cannot be zeroized; passphrase is
      // cleared from the TextEditingController immediately after import/dispose.
      final passphrase = _ownedPassphraseController.text;

      final provenance = await widget.controller.importOpenPgpOwned(
        secretKeyCertificate: secretBytes,
        expectedPublicKey: expectedKey,
        userId: uid,
        passphrase: passphrase.isEmpty ? null : passphrase,
      );
      if (!mounted) return;
      _ownedCertController.clear();
      _ownedPassphraseController.clear();
      setState(() {
        _ownedProvenance = provenance;
        _statusMessage =
            'Owned OpenPGP key imported and seed saved to keyring.';
      });
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.ownedImport;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.ownedImport;
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorSection = _OpenPgpErrorSection.ownedImport;
        _errorMessage = 'Failed to import owned secret key: $e';
      });
    } finally {
      secretBytes?.fillRange(0, secretBytes.length, 0);
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _copyArmor(
    String label,
    Uint8List bytes, {
    required String blockType,
  }) async {
    final armored = encodeOpenPgpArmor(
      bytes,
      blockType: blockType,
      includeCrc24: _issuedProfile == OpenPgpProfile.v4,
    );
    await Clipboard.setData(ClipboardData(text: armored));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('Copied $label (ASCII armor)')));
  }

  Widget _buildInlineErrorBanner(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Container(
        key: const Key('openpgp_error_banner'),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: theme.colorScheme.errorContainer,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(
          _errorMessage!,
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onErrorContainer,
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('OpenPGP Interoperability Bridge')),
      body: ListenableBuilder(
        listenable: widget.controller,
        builder: (context, _) {
          final theme = Theme.of(context);
          final encounterActive = widget.controller.hasActiveEncounter;
          final actionsDisabled =
              _isBusy || encounterActive || !widget.controller.isReady;

          return Align(
            alignment: Alignment.topCenter,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 720),
              child: ListView(
                key: const Key('openpgp_scroll_view'),
                padding: const EdgeInsets.all(20),
                children: [
                  if (encounterActive) ...[
                    Card(
                      key: const Key('openpgp_encounter_active_banner'),
                      color: theme.colorScheme.secondaryContainer,
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Text(
                          'OpenPGP operations are paused while an in-person '
                          'Encounter ceremony is active.',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSecondaryContainer,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                  ],
                  if (_statusMessage != null) ...[
                    Card(
                      key: const Key('openpgp_status_banner'),
                      color: theme.colorScheme.primaryContainer,
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Text(
                          _statusMessage!,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onPrimaryContainer,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                  ],
                  _buildInspectSection(context, actionsDisabled),
                  const SizedBox(height: 16),
                  _buildExportSection(context, actionsDisabled),
                  const SizedBox(height: 16),
                  _buildImportPeerSection(context, actionsDisabled),
                  const SizedBox(height: 16),
                  _buildImportOwnedSection(context, actionsDisabled),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildInspectSection(BuildContext context, bool actionsDisabled) {
    final theme = Theme.of(context);
    final cert = _inspectedCert;
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Inspect OpenPGP Certificate',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('openpgp_inspect_field'),
              controller: _inspectController,
              enabled: !_isBusy,
              minLines: 2,
              maxLines: 4,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Certificate (ASCII armor or base64)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.tonal(
                key: const Key('openpgp_inspect_button'),
                onPressed: _isBusy ? null : _inspectCertificate,
                child: const Text('Inspect'),
              ),
            ),
            if (_errorMessage != null &&
                _errorSection == _OpenPgpErrorSection.inspect)
              _buildInlineErrorBanner(theme),
            if (cert != null) ...[
              const SizedBox(height: 12),
              Container(
                key: const Key('openpgp_inspect_result'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Unauthenticated — certificate details have not been '
                      'verified against or bound to any Mesh identity.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.error,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text('Version: v${cert.version} (${cert.algorithm})'),
                    Text(
                      'Fingerprint: ${formatOpenPgpFingerprint(cert.fingerprint)}',
                      style: AppTheme.monospaceStyle(context)
                          .copyWith(fontSize: 12),
                    ),
                    Text('User IDs: ${cert.userIds.join(', ')}'),
                    Text('Subkeys: ${cert.subkeys.length}'),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildExportSection(BuildContext context, bool actionsDisabled) {
    final theme = Theme.of(context);
    final preview = _activePreview;
    final artifacts = _issuedArtifacts;
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Export & Cross-Certify Active Persona',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            Container(
              key: const Key('openpgp_upfront_privacy_note'),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                'Privacy notice: Exporting embeds your User ID and public key '
                'into a portable OpenPGP certificate.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 10),
            SegmentedButton<OpenPgpProfile>(
              segments: const [
                ButtonSegment(
                  value: OpenPgpProfile.v4,
                  label: Text('v4 (Classic)', maxLines: 1, softWrap: false),
                ),
                ButtonSegment(
                  value: OpenPgpProfile.v6,
                  label: Text('v6 (Modern)', maxLines: 1, softWrap: false),
                ),
              ],
              selected: {_selectedProfile},
              onSelectionChanged: actionsDisabled
                  ? null
                  : (s) => setState(() {
                      _selectedProfile = s.first;
                      _disposeActivePreview();
                    }),
            ),
            const SizedBox(height: 6),
            Text(
              _selectedProfile == OpenPgpProfile.v4
                  ? 'v4 (Classic): Best compatibility with GnuPG and existing PGP tools.'
                  : 'v6 (Modern): Newer RFC 9580 format for modern OpenPGP clients.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_export_uid_field'),
              controller: _exportUidController,
              enabled: !actionsDisabled,
              onChanged: (_) => _invalidatePreviewIfActive(),
              decoration: const InputDecoration(
                labelText: 'User ID (e.g. Alice <alice@example.org>)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_export_doc_field'),
              controller: _exportDocController,
              enabled: !actionsDisabled,
              onChanged: (_) => _invalidatePreviewIfActive(),
              decoration: const InputDecoration(
                labelText: 'Text to Sign (optional)',
                helperText:
                    'Creates a separate signature file so others can verify '
                    'this text came from your key.',
                helperMaxLines: 2,
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_export_peer_cert_field'),
              controller: _exportPeerCertController,
              enabled: !actionsDisabled,
              onChanged: (_) => _invalidatePreviewIfActive(),
              minLines: 1,
              maxLines: 3,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Peer Certificate to Cross-Certify (optional)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_export_peer_uid_field'),
              controller: _exportPeerUidController,
              enabled: !actionsDisabled,
              onChanged: (_) => _invalidatePreviewIfActive(),
              decoration: const InputDecoration(
                labelText: 'Peer User ID (required if peer cert provided)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton(
                key: const Key('openpgp_preview_button'),
                onPressed: actionsDisabled ? null : _previewExport,
                child: const Text('Preview Export'),
              ),
            ),
            if (_errorMessage != null &&
                _errorSection == _OpenPgpErrorSection.export)
              _buildInlineErrorBanner(theme),
            if (preview != null) ...[
              const SizedBox(height: 12),
              Card(
                key: const Key('openpgp_preview_card'),
                color: theme.colorScheme.tertiaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Privacy Disclosure',
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: theme.colorScheme.onTertiaryContainer,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        preview.warning,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onTertiaryContainer,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Profile: ${preview.profile.name} • '
                        'User ID: ${preview.userId} • '
                        'Document: ${preview.document.length} B',
                        style: theme.textTheme.bodySmall,
                      ),
                      if (preview.peerCertificationFingerprint != null)
                        Text(
                          'Cross-certifying peer: '
                          '${preview.peerCertificationFingerprint}',
                          style: AppTheme.monospaceStyle(context)
                              .copyWith(fontSize: 11),
                        ),
                      const SizedBox(height: 10),
                      Wrap(
                        spacing: 8,
                        children: [
                          TextButton(
                            onPressed: _isBusy
                                ? null
                                : () => setState(_disposeActivePreview),
                            child: const Text('Cancel'),
                          ),
                          FilledButton(
                            key: const Key('openpgp_confirm_export_button'),
                            onPressed: actionsDisabled ? null : _confirmExport,
                            child: const Text('Confirm & Issue Artifacts'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ],
            if (artifacts != null) ...[
              const SizedBox(height: 12),
              Container(
                key: const Key('openpgp_artifacts_card'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    OutlinedButton.icon(
                      key: const Key('copy_openpgp_cert_button'),
                      onPressed: () => _copyArmor(
                        'Certificate',
                        artifacts.certificate,
                        blockType: 'PGP PUBLIC KEY BLOCK',
                      ),
                      icon: const Icon(Icons.copy, size: 16),
                      label: Text(
                        'Copy Armored Certificate (${artifacts.certificate.length} B)',
                      ),
                    ),
                    OutlinedButton.icon(
                      key: const Key('copy_openpgp_sig_button'),
                      onPressed: () => _copyArmor(
                        'Detached Signature',
                        artifacts.detachedSignature,
                        blockType: 'PGP SIGNATURE',
                      ),
                      icon: const Icon(Icons.copy, size: 16),
                      label: Text(
                        'Copy Armored Signature (${artifacts.detachedSignature.length} B)',
                      ),
                    ),
                    ...artifacts.peerSignatures.map(
                      (ps) => OutlinedButton.icon(
                        onPressed: () => _copyArmor(
                          ps.label,
                          ps.bytes,
                          blockType: 'PGP SIGNATURE',
                        ),
                        icon: const Icon(Icons.copy, size: 16),
                        label: Text('Copy ${ps.label}'),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildImportPeerSection(BuildContext context, bool actionsDisabled) {
    final theme = Theme.of(context);
    final prov = _peerProvenance;
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Import Peer Certificate & Revocations',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('openpgp_peer_cert_field'),
              controller: _peerCertController,
              enabled: !actionsDisabled,
              minLines: 2,
              maxLines: 3,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Peer Certificate (ASCII armor or base64)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_peer_key_field'),
              controller: _peerKeyController,
              enabled: !actionsDisabled,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText:
                    'Expected Mesh Public Key (64 hex chars, out-of-band)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_peer_uid_field'),
              controller: _peerUidController,
              enabled: !actionsDisabled,
              decoration: const InputDecoration(
                labelText: 'Expected User ID',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.tonal(
                key: const Key('openpgp_import_peer_button'),
                onPressed: actionsDisabled ? null : _importPeer,
                child: const Text('Import Peer Contact'),
              ),
            ),
            if (_errorMessage != null &&
                _errorSection == _OpenPgpErrorSection.peerImport)
              _buildInlineErrorBanner(theme),
            if (prov != null) ...[
              const SizedBox(height: 8),
              Text(
                'Imported peer: ${prov.userId} (${formatOpenPgpFingerprint(prov.signingKeyFingerprint)})',
                key: const Key('openpgp_peer_provenance_card'),
                style: theme.textTheme.bodySmall,
              ),
            ],
            const Divider(height: 24),
            TextField(
              key: const Key('openpgp_revocation_field'),
              controller: _revocationController,
              enabled: !actionsDisabled,
              minLines: 1,
              maxLines: 3,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText:
                    'Peer Revocation Certificate (ASCII armor or base64)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: OutlinedButton(
                key: const Key('openpgp_remember_revocations_button'),
                onPressed: actionsDisabled ? null : _rememberRevocations,
                child: const Text('Remember Revocations'),
              ),
            ),
            if (_errorMessage != null &&
                _errorSection == _OpenPgpErrorSection.revocation)
              _buildInlineErrorBanner(theme),
          ],
        ),
      ),
    );
  }

  Widget _buildImportOwnedSection(BuildContext context, bool actionsDisabled) {
    final theme = Theme.of(context);
    final prov = _ownedProvenance;
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Import Owned OpenPGP Secret Key',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 4),
            Text(
              'Warning: Pasting a secret key uses your OS clipboard; clear '
              'clipboard history afterward. Imported secret material is cleared '
              'from this form after import.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('openpgp_owned_cert_field'),
              controller: _ownedCertController,
              enabled: !actionsDisabled,
              enableSuggestions: false,
              autocorrect: false,
              minLines: 2,
              maxLines: 3,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText:
                    'Owned Secret Key Certificate (ASCII armor or base64)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_owned_key_field'),
              controller: _ownedKeyController,
              enabled: !actionsDisabled,
              enableSuggestions: false,
              autocorrect: false,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Expected Ed25519 Public Key (64 hex chars)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_owned_uid_field'),
              controller: _ownedUidController,
              enabled: !actionsDisabled,
              decoration: const InputDecoration(
                labelText: 'User ID',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('openpgp_owned_passphrase_field'),
              controller: _ownedPassphraseController,
              enabled: !actionsDisabled,
              enableSuggestions: false,
              autocorrect: false,
              obscureText: true,
              maxLines: 1,
              decoration: const InputDecoration(
                labelText: 'Secret Key Passphrase (optional)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.tonal(
                key: const Key('openpgp_import_owned_button'),
                onPressed: actionsDisabled ? null : _importOwned,
                child: const Text('Import Owned Key'),
              ),
            ),
            if (_errorMessage != null &&
                _errorSection == _OpenPgpErrorSection.ownedImport)
              _buildInlineErrorBanner(theme),
            if (prov != null) ...[
              const SizedBox(height: 8),
              Text(
                'Bound persona: ${prov.userId} (${formatOpenPgpFingerprint(prov.signingKeyFingerprint)})',
                key: const Key('openpgp_owned_provenance_card'),
                style: theme.textTheme.bodySmall,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
