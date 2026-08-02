import 'package:dp_secure_storage_example/dp_secret_store.dart';
import 'package:dp_secure_storage_example/kv_adapters.dart';
import 'package:test/test.dart';

void main() {
  test('save and load identity roundtrip', () async {
    final store = DpSecretStore(
      store: MemoryKvStore(),
      prefix: 'test.dp',
    );

    await store.saveIdentity(
      ski: 'abc123',
      privateJwk: {'kty': 'OKP', 'crv': 'Ed25519', 'd': 'd', 'x': 'x'},
      publicJwk: {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'x'},
      credential: {
        'version': 1,
        'kind': 'machine',
        'ski': 'abc123',
        'entityId': 'acme.example',
      },
      fqhn: 'cam1--acme.example',
    );

    final loaded = await store.loadIdentity();
    expect(loaded, isNotNull);
    expect(loaded!.ski, 'abc123');
    expect(loaded.fqhn, 'cam1--acme.example');
    expect(loaded.privateJwk['d'], 'd');
    expect(loaded.credential['kind'], 'machine');

    await store.clearIdentity();
    expect(await store.loadIdentity(), isNull);
  });
}
