# Example: Dart DP secret store (`flutter_secure_storage`)

App-owned persistence for Delegate Permissions machine identity. **Not** part of the published `dp-sdk` packages.

Core in `lib/` is **pure Dart** (inject any [StringKvStore]). Production Flutter apps wrap [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage) — same idea as `billing_dart_sdk`.

## Flutter host adapter

Add dependency:

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_secure_storage: ^9.2.4
```

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
// copy StringKvStore + DpSecretStore from this example

class FlutterSecureKvStore implements StringKvStore {
  FlutterSecureKvStore([FlutterSecureStorage? storage])
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

final store = DpSecretStore(
  store: FlutterSecureKvStore(),
  prefix: 'idr.dp',
);

await store.saveIdentity(
  ski: identity.ski,
  privateJwk: identity.privateJwk,
  credential: identity.credential,
  fqhn: 'cam1.acme.idr.to',
);

final bundle = await store.loadIdentity();
// Pass into agent / FFI — never log privateJwk.
```

## Tests (no Flutter)

```bash
cd examples/dart-secure-storage
dart pub get
dart test
```

Uses `MemoryKvStore`.

## Process boundaries

Flutter secure storage is **not** shared with a separate Rust service. Embed the agent, or use an OS keyring in the service host (outside `dp-sdk`).

See [docs/SECRET_STORAGE.md](../../docs/SECRET_STORAGE.md).
