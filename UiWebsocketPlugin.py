from Plugin import PluginManager
from util import SafeRe
import hashlib
import random
import json



@PluginManager.registerTo("UiWebsocket")
class UiWebsocketPlugin(object):
    def __init__(self, *args, **kwargs):
        res = super(UiWebsocketPlugin, self).__init__(*args, **kwargs)

        # Flush immediate messages
        for message in self.site.p2p_unread:
            self.cmd("peerReceive", message)
        self.site.p2p_unread = []

        return res


    # Broadcast message to other peers
    def actionPeerBroadcast(self, to, message, peer_count=5, broadcast=True, immediate=False, timeout=60):
        # Check whether P2P messages are supported
        content_json = self.site.storage.loadJson("content.json")
        if "p2p_filter" not in content_json:
            self.response(to, {"error": "Site %s doesn't support P2P messages" % self.site.address})
            return

        # Check whether the message matches passive filter
        if not SafeRe.match(content_json["p2p_filter"], json.dumps(message)):
            self.response(to, {"error": "Invalid message for site %s: %s" % (self.site.address, message)})
            return


        nonce = str(random.randint(0, 1000000000))
        msg_hash = hashlib.md5("%s,%s" % (nonce, json.dumps(message))).hexdigest()

        peers = self.site.getConnectedPeers()
        if len(peers) < peer_count:  # Add more, non-connected peers if necessary
            peers += self.site.getRecentPeers(peer_count - len(peers))

        # Send message to peers
        jobs = []
        for peer in peers:
            jobs.append(gevent.spawn(self.p2pBroadcast, peer, {
                "message": message,
                "hash": msg_hash,
                "peer_count": peer_count,
                "broadcast": broadcast,
                "immediate": immediate,
                "site": self.site.address
            }))

        if not broadcast:
            # Makes sense to return result
            res = gevent.joinall(jobs, timeout)
            self.response(to, res)
            return

        # Reply
        self.response(to, {
            "sent": True
        })


    def p2pBroadcast(self, peer, data):
        reply = peer.request("peerBroadcast", data)
        return {
            "ip": "%s:%s" % (peer.ip, peer.port)
            "reply": reply
        }


    def actionPeerInvalid(self, hash):
        self.p2p_result[hash] = False
    def actionPeerValid(self, hash):
        self.p2p_result[hash] = True