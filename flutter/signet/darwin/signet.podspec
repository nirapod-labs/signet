# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# One Darwin pod for iOS and macOS (sharedDarwinSource). Run
# `pod lib lint signet.podspec` to validate before publishing.
Pod::Spec.new do |s|
  s.name             = 'signet'
  s.version          = '0.1.0-dev'
  s.summary          = 'Hardware-backed P-256 signing keys via the Apple Secure Enclave and Android Keystore (StrongBox/TEE).'
  s.description      = <<-DESC
Hardware-backed P-256 signing keys via the Apple Secure Enclave and Android Keystore (StrongBox/TEE).
                       DESC
  s.homepage         = 'https://github.com/nirapod-labs/signet'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'athexweb3' => 'athexweb3@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*.swift'
  # The apple/ core, consumed as a local pod. The example Podfiles (and a consumer
  # Podfile) point SignetAppleCore at apple/ by relative path until the core is
  # published as a versioned pod; apple/ stays the single source of truth.
  s.dependency 'SignetAppleCore'
  s.ios.dependency 'Flutter'
  s.osx.dependency 'FlutterMacOS'
  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '12.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  # Flutter.framework does not contain an i386 slice.
  s.ios.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # If a privacy manifest is required (for example a required-reason API), point
  # this at Resources/PrivacyInfo.xcprivacy and uncomment it.
  # s.resource_bundles = {'signet_privacy' => ['Resources/PrivacyInfo.xcprivacy']}
end
