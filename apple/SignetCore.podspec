# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# The Secure Enclave P-256 core, packaged as a pod so the Apple bindings can
# depend on it as a normal module. Consumed by relative path in development (see
# each binding's example Podfile); published as a versioned pod before release.
Pod::Spec.new do |s|
  s.name             = 'SignetCore'
  s.version          = '0.1.0-dev'
  s.summary          = 'Secure Enclave-backed P-256 key store for Signet.'
  s.description      = <<-DESC
The Secure Enclave-backed P-256 key store that Signet's Apple bindings call.
There is no export path for private keys.
                       DESC
  s.homepage         = 'https://github.com/nirapod-labs/signet'
  s.license          = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author           = { 'athexweb3' => 'athexweb3@gmail.com' }
  s.source           = { :git => 'https://github.com/nirapod-labs/signet.git', :tag => s.version.to_s }
  s.source_files          = 'Sources/SignetCore/**/*.swift'
  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '12.0'
  s.swift_version         = '6.0'
end
