from Plugin import PluginManager
from util import SafeRe
import json
import time
import gevent
import hashlib



@PluginManager.registerTo("FileRequest")
class FileRequestPlugin(object):
    # Re-broadcast to neighbour peers
    def actionPeerBroadcast(self, params):
        gevent.spawn(self.handlePeerBroadcast, params)
    def handlePeerBroadcast(self, params):
        ip = "%s:%s" % (self.connection.ip, self.connection.port)

        raw = json.loads(params["raw"])

        res, signature_address, msg_hash = self.peerCheckMessage(raw, params, ip)
        if not res:
            return

        self.response({
            "ok": "thx"
        })


        site = self.sites.get(raw["site"])
        websockets = [ws for ws in site.websockets if "peerReceive" in ws.channels]
        if websockets:
            # Wait for result (valid/invalid)
            site.p2p_result[msg_hash] = gevent.event.AsyncResult()

        # Send to WebSocket
        for ws in websockets:
            ws.cmd("peerReceive", {
                "ip": ip,
                "hash": msg_hash,
                "message": raw["message"],
                "signed_by": signature_address,
                "broadcast": True
            })


        # Maybe active filter will reply?
        if websockets:
            # Wait for p2p_result
            result = site.p2p_result[msg_hash].get()
            del site.p2p_result[msg_hash]
            if not result:
                self.connection.badAction(10)
                return

        # Save to cache
        if not websockets and raw["immediate"]:
            site.p2p_unread.append({
                "ip": "%s:%s" % (self.connection.ip, self.connection.port),
                "hash": msg_hash,
                "message": raw["message"],
                "signed_by": signature_address
            })


        # Now send to neighbour peers
        if raw["broadcast"]:
            # Get peer list
            peers = site.getConnectedPeers()
            if len(peers) < raw["peer_count"]:  # Add more, non-connected peers if necessary
                peers += site.getRecentPeers(raw["peer_count"] - len(peers))

            # Send message to peers
            for peer in peers:
                gevent.spawn(peer.request, "peerBroadcast", params)


    # Receive by-ip messages
    def actionPeerSend(self, params):
        gevent.spawn(self.handlePeerSend, params)
    def handlePeerSend(self, params):
        ip = "%s:%s" % (self.connection.ip, self.connection.port)
        raw = json.loads(params["raw"])


        res, signature_address, msg_hash = self.peerCheckMessage(raw, params, ip)
        if not res:
            return

        self.response({
            "ok": "thx"
        })

        site = self.sites.get(raw["site"])
        if "to" in raw:
            # This is a reply to peerSend
            site.p2p_to[raw["to"]].set({
                "hash": msg_hash,
                "message": raw["message"],
                "signed_by": signature_address
            })
        else:
            # Broadcast
            websockets = [ws for ws in site.websockets if "peerReceive" in ws.channels]
            if websockets:
                # Wait for result (valid/invalid)
                site.p2p_result[msg_hash] = gevent.event.AsyncResult()

            for ws in websockets:
                ws.cmd("peerReceive", {
                    "ip": ip,
                    "hash": msg_hash,
                    "message": raw["message"],
                    "signed_by": signature_address,
                    "broadcast": False
                })

            # Maybe active filter will reply?
            if websockets:
                # Wait for p2p_result
                result = site.p2p_result[msg_hash].get()
                del site.p2p_result[msg_hash]
                if not result:
                    self.connection.badAction(10)


    def peerCheckMessage(self, raw, params, ip):
        # Calculate hash from nonce
        msg_hash = hashlib.sha256("%s,%s" % (params["nonce"], params["raw"])).hexdigest()

        # Check whether P2P messages are supported
        site = self.sites.get(raw["site"])
        content_json = site.storage.loadJson("content.json")
        if "p2p_filter" not in content_json:
            self.connection.log("Site %s doesn't support P2P messages" % raw["site"])
            self.connection.badAction(5)
            self.response({
                "error": "Site %s doesn't support P2P messages" % raw["site"]
            })
            return False, "", msg_hash

        # Was the message received yet?
        if msg_hash in site.p2p_received:
            self.response({
                "warning": "Already received, thanks"
            })
            return False, "", msg_hash
        site.p2p_received.append(msg_hash)

        # Check whether the message matches passive filter
        if not SafeRe.match(content_json["p2p_filter"], json.dumps(raw["message"])):
            self.connection.log("Invalid message for site %s: %s" % (raw["site"], raw["message"]))
            self.connection.badAction(5)
            self.response({
                "error": "Invalid message for site %s: %s" % (raw["site"], raw["message"])
            })
            return False, "", msg_hash

        # Not so fast
        if "p2p_freq_limit" in content_json and time.time() - site.p2p_last_recv.get(ip, 0) < content_json["p2p_freq_limit"]:
            self.connection.log("Too fast messages from %s" % raw["site"])
            self.connection.badAction(2)
            self.response({
                "error": "Too fast messages from %s" % raw["site"]
            })
            return False, "", msg_hash
        site.p2p_last_recv[ip] = time.time()

        # Not so much
        if "p2p_size_limit" in content_json and len(json.dumps(raw["message"])) > content_json["p2p_size_limit"]:
            self.connection.log("Too big message from %s" % raw["site"])
            self.connection.badAction(7)
            self.response({
                "error": "Too big message from %s" % raw["site"]
            })
            return False, "", msg_hash

        # Verify signature
        if params["signature"]:
            signature_address, signature = params["signature"].split("|")
            what = "%s|%s|%s" % (signature_address, msg_hash, params["raw"])
            from Crypt import CryptBitcoin
            if not CryptBitcoin.verify(what, signature_address, signature):
                self.connection.log("Invalid signature")
                self.connection.badAction(7)
                self.response({
                    "error": "Invalid signature"
                })
                return False, "", msg_hash
        else:
            signature_address = ""

        # Check that the signature address is correct
        if "p2p_signed_only" in content_json:
            valid = content_json["p2p_signed_only"]
            if valid is True and not signature_address:
                self.connection.log("Not signed message")
                self.connection.badAction(5)
                self.response({
                    "error": "Not signed message"
                })
                return False, "", msg_hash
            elif isinstance(valid, str) and signature_address != valid:
                self.connection.log("Message signature is invalid: %s not in [%r]" % (signature_address, valid))
                self.connection.badAction(5)
                self.response({
                    "error": "Message signature is invalid: %s not in [%r]" % (signature_address, valid)
                })
                return False, "", msg_hash
            elif isinstance(valid, list) and signature_address not in valid:
                self.connection.log("Message signature is invalid: %s not in %r" % (signature_address, valid))
                self.connection.badAction(5)
                self.response({
                    "error": "Message signature is invalid: %s not in %r" % (signature_address, valid)
                })
                return False, "", msg_hash

        return True, signature_address, msg_hash