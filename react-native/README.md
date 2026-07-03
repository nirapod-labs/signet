# react-native/ (react-native-signet)

The React Native binding for Signet: a Nitro module (JSI, Nitrogen codegen) that exposes the Signet contract to TypeScript and forwards to the native cores. It serves iOS, Android, and macOS through Nitro.

## Layout

- `react-native-signet/` is the published npm package.
- `SignetApp/` is the Expo example app.

Only `jsi::Runtime` and `CallInvoker` cross the native boundary, never key material.
