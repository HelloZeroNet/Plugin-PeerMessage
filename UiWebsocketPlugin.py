from Plugin import PluginManager
from util import SafeRe
import hashlib
import random
import json
import time
import gevent



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
    def actionPeerBroadcast(self, to, message, privatekey=None, peer_count=5, broadcast=True, immediate=False, timeout=60):
        # Check whether P2P messages are supported
        content_json = self.site.storage.loadJson("content.json")
        if "p2p_filter" not in content_json:
            self.response(to, {"error": "Site %s doesn't support P2P messages" % self.site.address})
            return

        # Check whether the message matches passive filter
        if not SafeRe.match(content_json["p2p_filter"], json.dumps(message)):
            self.response(to, {"error": "Invalid message for site %s: %s" % (self.site.address, message)})
            return

        # Not so fast
        if "p2p_freq_limit" in content_json and time.time() - self.site.p2p_last_recv.get("self", 0) < content_json["p2p_freq_limit"]:
            self.response(to, {"error": "Too fast messages"})
            return
        self.site.p2p_last_recv["self"] = time.time()

        # Not so much
        if "p2p_size_limit" in content_json and len(json.dumps(message)) > content_json["p2p_size_limit"]:
            self.response(to, {"error": "Too big message"})
            return


        # Generate message and sign it
        all_message = {
            "message": message,
            "peer_count": peer_count,
            "broadcast": broadcast,
            "immediate": immediate,
            "site": self.site.address
        }

        nonce = str(random.randint(0, 1000000000))
        msg_hash = hashlib.md5("%s,%s" % (nonce, json.dumps(all_message))).hexdigest()
        all_message["signature"] = self.p2pGetSignature(msg_hash, json.dumps(all_message), privatekey)
        all_message["hash"] = msg_hash

        peers = self.site.getConnectedPeers()
        if len(peers) < peer_count:  # Add more, non-connected peers if necessary
            peers += self.site.getRecentPeers(peer_count - len(peers))

        # Send message to peers
        jobs = []
        for peer in peers:
            jobs.append(gevent.spawn(self.p2pBroadcast, peer, all_message))

        if not broadcast:
            # Makes sense to return result
            res = gevent.joinall(jobs, timeout)
            self.response(to, res)
            return

        # Reply
        self.response(to, {
            "sent": True
        })

        # Send message to myself
        self.site.p2p_received.append(msg_hash)
        self.cmd("peerReceive", {
            "ip": "self",
            "hash": msg_hash,
            "message": message,
            "signed_by": all_message["signature"].split("|")[0] if all_message["signature"] else ""
        })


    def p2pBroadcast(self, peer, data):
        reply = peer.request("peerBroadcast", data)
        return {
            "ip": "%s:%s" % (peer.ip, peer.port),
            "reply": reply
        }

    def p2pGetSignature(self, hash, data, privatekey):
        # Get private key
        if privatekey == "stored":
            # Using site privatekey
            privatekey = self.user.getSiteData(self.site.address).get("privatekey")
        elif not privatekey and privatekey is not None:
            # Using user privatekey
            privatekey = self.user.getAuthPrivatekey(self.site.address)

        # Generate signature
        if privatekey:
            from Crypt import CryptBitcoin
            address = CryptBitcoin.privatekeyToAddress(privatekey)
            return "%s|%s" % (address, CryptBitcoin.sign("%s|%s|%s" % (address, hash, data), privatekey))
        else:
            return ""


    def actionPeerInvalid(self, hash):
        self.p2p_result[hash] = False
    def actionPeerValid(self, hash):
        self.p2p_result[hash] = True