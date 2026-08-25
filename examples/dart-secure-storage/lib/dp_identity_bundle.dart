/// In-memory bundle loaded from [DpSecretStore] — feed into 2key-core-sdk / agent, do not log.
class DpIdentityBundle {
  const DpIdentityBundle({
    required this.ski,
    required this.privateJwk,
    required this.credential,
    this.publicJwk,
    this.fqhn,
  });

  final String ski;
  final Map<String, dynamic> privateJwk;
  final Map<String, dynamic> credential;
  final Map<String, dynamic>? publicJwk;
  final String? fqhn;
}
