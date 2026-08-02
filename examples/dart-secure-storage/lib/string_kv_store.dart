/// Minimal string KV used by [DpSecretStore] — app supplies Flutter or memory.
abstract class StringKvStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}
