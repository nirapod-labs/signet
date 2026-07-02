import 'package:flutter_test/flutter_test.dart';
import 'package:signet/signet.dart';
import 'package:signet/signet_platform_interface.dart';
import 'package:signet/signet_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockSignetPlatform
    with MockPlatformInterfaceMixin
    implements SignetPlatform {
  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final SignetPlatform initialPlatform = SignetPlatform.instance;

  test('$MethodChannelSignet is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSignet>());
  });

  test('getPlatformVersion', () async {
    Signet signetPlugin = Signet();
    MockSignetPlatform fakePlatform = MockSignetPlatform();
    SignetPlatform.instance = fakePlatform;

    expect(await signetPlugin.getPlatformVersion(), '42');
  });
}
