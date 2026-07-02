#ifndef FLUTTER_PLUGIN_SIGNET_PLUGIN_H_
#define FLUTTER_PLUGIN_SIGNET_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace signet {

class SignetPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  SignetPlugin();

  virtual ~SignetPlugin();

  // Disallow copy and assign.
  SignetPlugin(const SignetPlugin&) = delete;
  SignetPlugin& operator=(const SignetPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace signet

#endif  // FLUTTER_PLUGIN_SIGNET_PLUGIN_H_
