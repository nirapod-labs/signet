import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'signet_method_channel.dart';

abstract class SignetPlatform extends PlatformInterface {
  /// Constructs a SignetPlatform.
  SignetPlatform() : super(token: _token);

  static final Object _token = Object();

  static SignetPlatform _instance = MethodChannelSignet();

  /// The default instance of [SignetPlatform] to use.
  ///
  /// Defaults to [MethodChannelSignet].
  static SignetPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SignetPlatform] when
  /// they register themselves.
  static set instance(SignetPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
