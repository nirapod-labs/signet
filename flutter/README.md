# flutter/ (signet)

The Flutter binding: a Pigeon-generated typed platform-channel plugin exposing the Signet contract to Dart, forwarding to the native cores (`../apple`, `../android`, and a C++ plugin over `../windows`).

Layout: `pubspec.yaml`, `pigeons/signet.dart`, `lib/` (public Dart API), `analysis_options.yaml`, `ios/ macos/ android/ windows/`, `example/`. Zero policy, zero key material across the channel.
