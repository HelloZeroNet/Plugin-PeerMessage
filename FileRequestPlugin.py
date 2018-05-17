from Plugin import PluginManager
from util import SafeRe
import json



@PluginManager.registerTo("FileRequest")
class FileRequestPlugin(object):
    # Re-broadcast to neighbour peers
    def actionPeerBroadcast(self, params):
        # Check whether P2P messages are supported
        site = self.sites.get(params["site"])
        content_json = site.storage.loadJson("content.json")
        if "message_filter" not in content_json:
            self.connection.log("Site %s doesn't support P2P messages" % params["site"])
            self.connection.badAction(5)
            return

        # Was the message received yet?
        if params["hash"] in site.p2p_received:
            return
        site.p2p_received.append(params["hash"])

        # Check whether the message matches passive filter
        if not SafeRe.match(content_json["message_filter"], json.dumps(params["message"])):
            self.connection.log("Invalid message for site %s: %s" % (params["site"], params["message"]))
            self.connection.badAction(5)
            return

        # Send to WebSocket
        for ws in site.websockets:
            ws.cmd("peerReceive", {
                "ip": "%s:%s" % (self.connection.ip, self.connection.port),
                "hash": params["hash"],
                "message": params["message"]
            })

        # Maybe active filter will reply?
        if site.websockets:
            # Wait for p2p_result
            result = gevent.spawn(self.p2pWaitMessage, site, params["hash"]).join()
            del site.p2p_result[params["hash"]]
            if not result:
                self.connection.badAction(10)
                return

        # Save to cache
        if not site.websockets and params["immediate"]:
            self.p2p_unread.append({
                "ip": "%s:%s" % (self.connection.ip, self.connection.port),
                "hash": params["hash"],
                "message": params["message"]
            })


        # Now send to neighbour peers
        if params["broadcast"]:
            # Get peer list
            peers = site.getConnectedPeers()
            if len(peers) < params["peer_count"]:  # Add more, non-connected peers if necessary
                peers += site.getRecentPeers(params["peer_count"] - len(peers))

            # Send message to peers
            for peer in peers:
                gevent.spawn(peer.connection.request, "peerBroadcast", params)


    def p2pWaitMessage(self, site, hash):
        while hash not in site.p2p_result:
            gevent.sleep(0.5)

        return site.p2p_result[hash]