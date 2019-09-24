from Plugin import PluginManager
from Config import config
from util import SafeRe
import json
import time
import gevent
import hashlib
from .p2putil import getWebsockets

try:
    from Crypt import Crypt
except ImportError:
    from Crypt import CryptBitcoin as Crypt


@PluginManager.registerTo("FileRequest")
class FileRequestPlugin(object):
    # Re-broadcast to neighbour peers
    def actionPeerBroadcast(self, params):
        gevent.spawn(self.handlePeerBroadcast, params)
    def handlePeerBroadcast(self, params):
        ip = "%s:%s" % (self.connection.ip, self.connection.port)

        if "trace" in params:
            params["trace"].append(ip)

        raw = json.loads(params["raw"])

        res, signature_address, cert, msg_hash = self.peerCheckMessage(raw, params, ip)
        if not res:
            return

        self.response({
            "ok": "thx"
        })


        site = self.sites.get(raw["site"])
        websockets = getWebsockets(site)
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
                "cert": cert,
                "site": raw["site"],
                "broadcast": True,
                "trace": params.get("trace"),
                "timestamp": raw.get("timestamp")
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
                "signed_by": signature_address,
                "cert": cert,
                "site": raw["site"],
                "broadcast": True,
                "trace": params.get("trace"),
                "timestamp": raw.get("timestamp")
            })


        # Get peer list
        peers = site.getConnectedPeers()
        if len(peers) < raw["peer_count"]:  # Add more, non-connected peers if necessary
            peers += site.getRecentPeers(raw["peer_count"] - len(peers))

        # Send message to neighbour peers
        for peer in peers:
            gevent.spawn(peer.request, "peerBroadcast", params)


    # Receive by-ip messages
    def actionPeerSend(self, params):
        gevent.spawn(self.handlePeerSend, params)
    def handlePeerSend(self, params):
        ip = "%s:%s" % (self.connection.ip, self.connection.port)
        raw = json.loads(params["raw"])


        res, signature_address, cert, msg_hash = self.peerCheckMessage(raw, params, ip)
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
                "signed_by": signature_address,
                "cert": cert,
                "timestamp": raw.get("timestamp")
            })
        else:
            # Broadcast
            websockets = getWebsockets(site)
            if websockets:
                # Wait for result (valid/invalid)
                site.p2p_result[msg_hash] = gevent.event.AsyncResult()

            for ws in websockets:
                ws.cmd("peerReceive", {
                    "ip": ip,
                    "hash": msg_hash,
                    "message": raw["message"],
                    "signed_by": signature_address,
                    "cert": cert,
                    "site": raw["site"],
                    "broadcast": False,
                    "timestamp": raw.get("timestamp")
                })

            # Maybe active filter will reply?
            if websockets:
                # Wait for p2p_result
                result = site.p2p_result[msg_hash].get()
                del site.p2p_result[msg_hash]
                if not result:
                    self.connection.badAction(10)

            # Save to cache
            if not websockets and raw["immediate"]:
                site.p2p_unread.append({
                    "ip": ip,
                    "hash": msg_hash,
                    "message": raw["message"],
                    "signed_by": signature_address,
                    "cert": cert,
                    "site": raw["site"],
                    "broadcast": False,
                    "timestamp": raw.get("timestamp")
                })


    def peerCheckMessage(self, raw, params, ip):
        # Calculate hash from nonce
        msg_hash = hashlib.sha256(("%s,%s" % (params["nonce"], params["raw"])).encode("ascii")).hexdigest()

        # Check that p2p.json exists
        site = self.sites.get(raw["site"])
        if not site.storage.isFile("p2p.json"):
            self.connection.log("Site %s doesn't support P2P messages" % raw["site"])
            self.connection.badAction(5)
            self.response({
                "error": "Site %s doesn't support P2P messages" % raw["site"]
            })
            return False, "", None, msg_hash

        # Check whether P2P messages are supported
        p2p_json = site.storage.loadJson("p2p.json")
        if "filter" not in p2p_json:
            self.connection.log("Site %s doesn't support P2P messages" % raw["site"])
            self.connection.badAction(5)
            self.response({
                "error": "Site %s doesn't support P2P messages" % raw["site"]
            })
            return False, "", None, msg_hash

        # Was the message received yet?
        if msg_hash in site.p2p_received:
            self.response({
                "warning": "Already received, thanks"
            })
            return False, "", None, msg_hash
        site.p2p_received.append(msg_hash)

        # Check whether the message matches passive filter
        if not SafeRe.match(p2p_json["filter"], json.dumps(raw["message"])):
            self.connection.log("Invalid message for site %s: %s" % (raw["site"], raw["message"]))
            self.connection.badAction(5)
            self.response({
                "error": "Invalid message for site %s: %s" % (raw["site"], raw["message"])
            })
            return False, "", None, msg_hash

        # Not so fast
        if "freq_limit" in p2p_json and time.time() - site.p2p_last_recv.get(ip, 0) < p2p_json["freq_limit"]:
            self.connection.log("Too fast messages from %s" % raw["site"])
            self.connection.badAction(2)
            self.response({
                "error": "Too fast messages from %s" % raw["site"]
            })
            return False, "", None, msg_hash
        site.p2p_last_recv[ip] = time.time()

        # Not so much
        if "size_limit" in p2p_json and len(json.dumps(raw["message"])) > p2p_json["size_limit"]:
            self.connection.log("Too big message from %s" % raw["site"])
            self.connection.badAction(7)
            self.response({
                "error": "Too big message from %s" % raw["site"]
            })
            return False, "", None, msg_hash

        # Verify signature
        if params["signature"]:
            signature_address, signature = params["signature"].split("|")
            what = "%s|%s|%s" % (signature_address, msg_hash, params["raw"])
            if not Crypt.verify(what, signature_address, signature):
                self.connection.log("Invalid signature")
                self.connection.badAction(7)
                self.response({
                    "error": "Invalid signature"
                })
                return False, "", None, msg_hash

            # Now check auth providers
            if params.get("cert"):
                # Read all info
                cert_auth_type, cert_auth_user_name, cert_issuer, cert_sign = map(
                    lambda b: b.decode("ascii") if isinstance(b, bytes) else b,
                    params["cert"]
                )
                # This is what certificate issuer signs
                cert_subject = "%s#%s/%s" % (signature_address, cert_auth_type, cert_auth_user_name)
                # Now get cert issuer address
                cert_signers = p2p_json.get("cert_signers", {})
                cert_addresses = cert_signers.get(cert_issuer, [])
                # And verify it
                if not Crypt.verify(cert_subject, cert_addresses, cert_sign):
                    self.connection.log("Invalid signature certificate")
                    self.connection.badAction(7)
                    self.response({
                        "error": "Invalid signature certificate"
                    })
                    return False, "", None, msg_hash
                # And save the ID
                cert = "%s/%s@%s" % (cert_auth_type, cert_auth_user_name, cert_issuer)
            else:
                # Old-style sign
                cert = ""
        else:
            signature_address = ""
            cert = ""

        # Check that the signature address is correct
        if "signed_only" in p2p_json:
            valid = p2p_json["signed_only"]
            if valid is True and not signature_address:
                self.connection.log("Not signed message")
                self.connection.badAction(5)
                self.response({
                    "error": "Not signed message"
                })
                return False, "", None, msg_hash
            elif isinstance(valid, str) and signature_address != valid:
                self.connection.log("Message signature is invalid: %s not in [%r]" % (signature_address, valid))
                self.connection.badAction(5)
                self.response({
                    "error": "Message signature is invalid: %s not in [%r]" % (signature_address, valid)
                })
                return False, "", None, msg_hash
            elif isinstance(valid, list) and signature_address not in valid:
                self.connection.log("Message signature is invalid: %s not in %r" % (signature_address, valid))
                self.connection.badAction(5)
                self.response({
                    "error": "Message signature is invalid: %s not in %r" % (signature_address, valid)
                })
                return False, "", None, msg_hash

        return True, signature_address, cert, msg_hash