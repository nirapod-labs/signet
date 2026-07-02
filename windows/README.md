# windows/ (SignetWindowsCore)

The Windows native core: a C++/CMake library over CNG (`NCryptCreatePersistedKey`, Microsoft Platform Crypto Provider) for non-exportable TPM-backed P-256 keys, `NCryptSignHash`, and Windows Hello gating via `NCRYPT_UI_POLICY`. Tier `tpm`.

The EC-key attestation path over CNG and the TPM is still under investigation. Until it is proven, a Windows `tpm` tier reports `evidence = selfReportUnverified`, never `attested`.

## Status

Scaffold: the CMake library builds a placeholder surface with no CNG or key code yet. The behavior above is the design that the key code implements and proves in tests.

## Build

```
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
