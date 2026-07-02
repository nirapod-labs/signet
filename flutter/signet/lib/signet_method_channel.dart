import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'signet_platform_interface.dart';

/// An implementation of [SignetPlatform] that uses method channels.
class MethodChannelSignet extends SignetPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('signet');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>(
      'getPlatformVersion',
    );
    return version;
  }
}
