#include "include/signet/signet_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "signet_plugin.h"

void SignetPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  signet::SignetPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
