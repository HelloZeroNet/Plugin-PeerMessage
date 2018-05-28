def getWebsockets(site):
    websockets = [ws for ws in site.websockets if "peerReceive" in ws.channels]
    return websockets