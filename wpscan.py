#!/usr/bin/python3

from core import plugin, model

class _wpscan(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("wpscanUrlFresh","_wpscanFresh","_action","plugins.wpscan.models.action")
        model.registerModel("wpscanUrlCached", "_wpscanCached", "_action", "plugins.wpscan.models.action")
        model.registerModel("wpscanUrlRetrieve", "_wpscanRetrieve", "_action", "plugins.wpscan.models.action")
        model.registerModel("wpscan", "_wpscan", "_document", "plugins.wpscan.models.wpscan")
        return True


    def uninstall(self):
        # deregister models
        model.deregisterModel("wpscanUrlFresh","_wpscanFresh","_action","plugins.wpscan.models.action")
        model.deregisterModel("wpscanUrlCached", "_wpscanCached", "_action", "plugins.wpscan.models.action")
        model.deregisterModel("wpscanUrlRetrieve", "_wpscanRetrieve", "_action", "plugins.wpscan.models.action")
        model.deregisterModel("wpscanUrlRetrieve", "_wpscanRetrieve", "_action", "plugins.wpscan.models.action")
        model.deregisterModel("wpscan", "_wpscan", "_document", "plugins.wpscan.models.wpscan")
        return True

    def upgrade(self, LatestPluginVersion):
        pass
