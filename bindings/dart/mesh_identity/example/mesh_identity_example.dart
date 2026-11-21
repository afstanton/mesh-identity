// ignore_for_file: avoid_print

import 'package:mesh_identity/mesh_identity.dart';

void main() {
  // Generate a cryptographically secure 32-byte signing seed
  final seed = MeshInstallation.generateSeed();

  // Create an installation with an initial root persona
  final installation = MeshInstallation(seed: seed);
  print('Selected identity: ${installation.selectedIdentity}');

  // Save durable snapshot
  final snapshot = installation.save();
  print('Saved snapshot: ${snapshot.length} bytes');

  // Verify restoration using snapshot and the known seed
  final restored = MeshInstallation.restore(
    snapshotBytes: snapshot,
    signingKeySeeds: [seed],
  );
  print('Restored identity: ${restored.selectedIdentity}');

  installation.dispose();
  restored.dispose();
}
