## 0.1.0-dev

* Initial development release. Hardware-backed P-256 signing over the Apple Secure
  Enclave and the Android StrongBox or TEE-backed Keystore, exposed to Dart through
  a Pigeon channel. Key generation fails closed when no secure hardware is
  reachable.
