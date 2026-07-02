# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint signet.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'signet'
  s.version          = '0.1.0-dev'
  s.summary          = 'Hardware-backed P-256 signing keys via Secure Enclave, StrongBox/TEE, and TPM.'
  s.description      = <<-DESC
Hardware-backed P-256 signing keys via Secure Enclave, StrongBox/TEE, and TPM.
                       DESC
  s.homepage         = 'https://github.com/nirapod-labs/signet'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'athexweb3' => 'athexweb3@users.noreply.github.com' }
  s.source           = { :path => '.' }
  s.source_files = 'signet/Sources/signet/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # If your plugin requires a privacy manifest, for example if it uses any
  # required reason APIs, update the PrivacyInfo.xcprivacy file to describe your
  # plugin's privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'signet_privacy' => ['signet/Sources/signet/PrivacyInfo.xcprivacy']}
end
