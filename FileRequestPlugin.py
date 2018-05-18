from Plugin import PluginManager
from util import SafeRe
import json
import time



@PluginManager.registerTo("FileRequest")
class FileRequestPlugin(object):
    # Re-broadcast to neighbour peers
    def actionPeerBroadcast(self, params):
        ip = "%s:%s" % (self.connection.ip, self.connection.port)

        # Check whether P2P messages are supported
        site = self.sites.get(params["site"])
        content_json = site.storage.loadJson("content.json")
        if "p2p_filter" not in content_json:
            self.connection.log("Site %s doesn't support P2P messages" % params["site"])
            self.connection.badAction(5)
            return

        # Was the message received yet?
        if params["hash"] in site.p2p_received:
            return
        site.p2p_received.append(params["hash"])


        # Check whether the message matches passive filter
        if not SafeRe.match(content_json["p2p_filter"], json.dumps(params["message"])):
            self.connection.log("Invalid message for site %s: %s" % (params["site"], params["message"]))
            self.connection.badAction(5)
            return

        # Not so fast
        if "p2p_freq_limit" in content_json and time.time() - site.p2p_last_recv.get(ip, 0) < content_json["p2p_freq_limit"]:
            self.connection.log("Too fast messages from %s" % params["site"])
            self.connection.badAction(2)
            return
        site.p2p_last_recv[ip] = time.time()

        # Not so much
        if "p2p_size_limit" in content_json and len(json.dumps(params["message"])) > content_json["p2p_size_limit"]:
            self.connection.log("Too big message from %s" % params["site"])
            self.connection.badAction(7)
            return

        # Verify signature
        if params["signature"]:
            message = dict(**params)
            del message["signature"]
            del message["hash"]
            message = json.dumps(message)

            signature_address, signature = params["signature"].split("|")
            what = "%s|%s|%s" % (signature_address, params["hash"], message)
            if not CryptBitcoin.verify(what, signature_address, signature):
                self.connection.log("Invalid signature")
                self.connection.badAction(7)
        else:
            signature_address = ""


        # Send to WebSocket
        for ws in site.websockets:
            ws.cmd("peerReceive", {
                "ip": ip,
                "hash": params["hash"],
                "message": params["message"],
                "signed_by": signature_address
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