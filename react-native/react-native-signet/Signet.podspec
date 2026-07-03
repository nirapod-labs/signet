# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "Signet"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported, :osx => 12.0 }
  s.source       = { :git => "https://github.com/nirapod-labs/signet.git", :tag => "#{s.version}" }

  s.source_files = [
    # Implementation (Swift), shared by iOS and macOS under apple/.
    "apple/**/*.{swift}",
    # Bridging header and any Objective-C++ registration.
    "apple/**/*.{h,m,mm}",
  ]

  load 'nitrogen/generated/ios/Signet+autolinking.rb'
  add_nitrogen_files(s)

  # The shared Apple core. Linked dev-local by the consumer Podfile
  # (pod 'SignetAppleCore', :path => '../../apple') until it is a published pod;
  # see VERIFICATION.md.
  s.dependency 'SignetAppleCore'
  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  install_modules_dependencies(s)
end
