from Plugin import PluginManager



@PluginManager.registerTo("Site")
class SitePlugin(object):
    def __init__(self, *args, **kwargs):
        res = super(SitePlugin, self).__init__(*args, **kwargs)
        self.p2p_received = []
        self.p2p_result = {}
        self.p2p_to = {}
        self.p2p_unread = []
        self.p2p_last_recv = {}

        return res