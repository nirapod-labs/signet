import Flutter
import XCTest

@testable import signet

class RunnerTests: XCTestCase {

  /// Smoke test that the plugin type is constructible. The security-bearing
  /// behavior lives in the SignetCore unit tests and the device-lane
  /// integration_test, not in this example-app target.
  func testPluginInstantiates() {
    let plugin: SignetPlugin? = SignetPlugin()
    XCTAssertNotNil(plugin)
  }

}
