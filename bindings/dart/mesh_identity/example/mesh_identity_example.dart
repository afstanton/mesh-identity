// ignore_for_file: avoid_print

import 'package:mesh_identity/mesh_identity.dart';

void main() {
  // Create an installation with an initial root persona
  final installation = MeshInstallation.create();
  print('Selected identity: ${installation.selectedIdentity}');

  // Save durable snapshot
  final snapshot = installation.save();
  print('Saved snapshot: ${snapshot.length} bytes');

  installation.dispose();
}
