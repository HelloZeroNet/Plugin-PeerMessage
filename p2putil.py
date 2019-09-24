try:
    from MergerSite import MergerSitePlugin
    has_merger_plugin = True
except ImportError:
    has_merger_plugin = False

from . import BackgroundPeerMessage


def getWebsockets(site):
    # First, site's own websockets
    websockets = site.websockets[:]

    # Now merger site
    if has_merger_plugin:
        merger_sites = MergerSitePlugin.merged_to_merger.get(site.address, [])
        for merger_site in merger_sites:
            if merger_site.address == site.address:
                continue
            websockets += merger_site.websockets

    # Filter out sites not supporting P2P
    # (e.g. ZeroHello, which joins all channels automatically)
    return [ws for ws in websockets if "peerReceive" in ws.channels]
