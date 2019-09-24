from Plugin import PluginManager
from util import SafeRe
from Config import config
import hashlib
import random
import json
import time
import gevent
from .p2putil import getWebsockets

try:
    from Crypt import Crypt
except ImportError:
    from Crypt import CryptBitcoin as Crypt


@PluginManager.registerTo("UiWebsocket")
class UiWebsocketPlugin(object):
    def __init__(self, *args, **kwargs):
        res = super(UiWebsocketPlugin, self).__init__(*args, **kwargs)

        # Automatically join peerReceive and peerSend
        if self.site.storage.isFile("p2p.json"):
            self.channels.append("peerReceive")
            self.channels.append("peerSend")

            p2p_json = self.site.storage.loadJson("p2p.json")
            if "filter" in p2p_json:
                # Flush immediate messages
                for message in self.site.p2p_unread:
                    self.cmd("peerReceive", message)
                self.site.p2p_unread = []

        return res


    # Allow to broadcast to any site
    def hasSitePermission(self, address, cmd=None):
        if super(UiWebsocketPlugin, self).hasSitePermission(address, cmd=cmd):
            return True

        return cmd in ("peerBroadcast", "peerSend")


    # Broadcast message to other peers
    def actionPeerBroadcast(self, *args, **kwargs):
        gevent.spawn(self.handlePeerBroadcast, *args, **kwargs)
    def handlePeerBroadcast(self, to, message, privatekey=None, peer_count=5, immediate=False, trace=True, timestamp=False):
        # Check message
        if not self.peerCheckMessage(to, message):
            return

        # Generate message and sign it
        all_message = {
            "message": message,
            "peer_count": peer_count,
            "broadcast": True, # backward compatibility
            "immediate": immediate,
            "site": self.site.address
        }
        if timestamp:
            import main
            all_message["timestamp"] = time.time() + main.file_server.timecorrection

        all_message, msg_hash, cert = self.peerGenerateMessage(all_message, privatekey)

        peers = self.site.getConnectedPeers()
        if len(peers) < peer_count:  # Add more, non-connected peers if necessary
            peers += self.site.getRecentPeers(peer_count - len(peers))

        # Send message to peers
        for peer in peers:
            gevent.spawn(self.p2pBroadcast, peer, all_message, trace)

        # Send message to myself
        self.site.p2p_received.append(msg_hash)

        websockets = getWebsockets(self.site)
        for ws in websockets:
            ws.cmd("peerReceive", {
                "ip": "self",
                "hash": msg_hash,
                "message": message,
                "signed_by": all_message["signature"].split("|")[0] if all_message["signature"] else "",
                "cert": cert,
                "site": self.site.address,
                "broadcast": True,
                "timestamp": all_message.get("timestamp")
            })

        if not websockets and immediate:
            self.site.p2p_unread.append({
                "ip": "self",
                "hash": msg_hash,
                "message": message,
                "signed_by": all_message["signature"].split("|")[0] if all_message["signature"] else "",
                "cert": cert,
                "site": self.site.address,
                "broadcast": True,
                "timestamp": all_message.get("timestamp")
            })


        # Reply
        self.response(to, {
            "sent": True
        })

        # Also send the message to myself
        data = {
            "hash": msg_hash,
            "message": message,
            "signed_by": all_message["signature"].split("|")[0] if all_message["signature"] else "",
            "cert": cert,
            "site": self.site.address,
            "broadcast": True,
            "timestamp": all_message.get("timestamp")
        }
        for ws in getWebsockets(self.site):
            ws.cmd("peerSend", data)

    def p2pBroadcast(self, peer, data, trace=True):
        data = data.copy()
        if trace:
            data["trace"] = []

        reply = peer.request("peerBroadcast", data)
        if reply is None:
            return {
                "ip": "%s:%s" % (peer.ip, peer.port),
                "reply": {
                    "error": "Connection error"
                }
            }

        return {
            "ip": "%s:%s" % (peer.ip, peer.port),
            "reply": reply
        }

    # Send a message to IP
    def actionPeerSend(self, *args, **kwargs):
        gevent.spawn(self.handlePeerSend, *args, **kwargs)
    def handlePeerSend(self, to_, ip, message, privatekey=None, to=None, immediate=False, timestamp=False):
        # Check message
        if not self.peerCheckMessage(to_, message):
            return


        # Get peer or connect to it if it isn't cached
        if ip != "self":
            peer = self.site.peers.get(ip)
            if not peer:
                mip, mport = ip.rsplit(":", 1)
                peer = self.site.addPeer(mip, mport, source="peerSend")
            if not peer:
                # Couldn't connect to this IP
                self.response(to_, {
                    "error": "Could not find peer %s" % ip
                })
                return

        # Generate hash
        all_message = {
            "message": message,
            "immediate": immediate,
            "site": self.site.address
        }
        if to:
            all_message["to"] = to
        if timestamp:
            import main
            all_message["timestamp"] = time.time() + main.file_server.timecorrection

        all_message, msg_hash, cert = self.peerGenerateMessage(all_message, privatekey)

        # Send message
        self.site.p2p_to[msg_hash] = gevent.event.AsyncResult()
        if ip == "self":
            self.handlePeerSendSelf(all_message, to, msg_hash, message, cert, immediate)
        else:
            peer.request("peerSend", all_message)

        # Get reply
        reply = self.site.p2p_to[msg_hash].get()
        self.response(to_, reply)

        # Also send the message to myself
        data = {
            "ip": ip,
            "hash": msg_hash,
            "message": message,
            "signed_by": all_message["signature"].split("|")[0] if all_message["signature"] else "",
            "cert": cert,
            "site": self.site.address,
            "broadcast": False,
            "timestamp": all_message.get("timestamp")
        }
        for ws in getWebsockets(self.site):
            ws.cmd("peerSend", data)


    def handlePeerSendSelf(self, all_message, to, msg_hash, message, cert, immediate):
        signature_address = all_message["signature"].split("|")[0] if all_message["signature"] else ""

        if to is not None:
            # This is a reply to peerSend
            self.site.p2p_to[to].set({
                "hash": msg_hash,
                "message": message,
                "signed_by": signature_address,
                "cert": cert,
                "timestamp": all_message.get("timestamp")
            })
        else:
            # Broadcast
            websockets = getWebsockets(self.site)

            data = {
                "ip": "self",
                "hash": msg_hash,
                "message": message,
                "signed_by": signature_address,
                "cert": cert,
                "site": self.site.address,
                "broadcast": False,
                "timestamp": all_message.get("timestamp")
            }

            for ws in websockets:
                ws.cmd("peerReceive", data)

            # Save to cache
            if not websockets and immediate:
                self.site.p2p_unread.append(data)



    def p2pGetSignature(self, hash, data, privatekey):
        if privatekey is None:
            return "", None, None

        cert = None
        cert_text = ""

        # Get private key
        if privatekey == "stored":
            # Using site privatekey
            privatekey = self.user.getSiteData(self.site.address).get("privatekey")
        elif privatekey is False:
            # Using user privatekey
            privatekey = self.user.getAuthPrivatekey(self.site.address)
            cert = self.user.getCert(self.site.address)

            if cert:
                site_data = self.user.getSiteData(self.site.address, create=False)
                cert_issuer = site_data["cert"]

                p2p_json = self.site.storage.loadJson("p2p.json")
                if cert_issuer in p2p_json.get("cert_signers", {}):
                    cert = [cert["auth_type"], cert["auth_user_name"], cert_issuer, cert["cert_sign"]]
                    cert_text = "%s/%s@%s" % tuple(cert[:3])
                else:
                    cert = None

        # Generate signature
        address = Crypt.privatekeyToAddress(privatekey)
        return "%s|%s" % (address, Crypt.sign("%s|%s|%s" % (address, hash, data), privatekey)), cert, cert_text


    def actionPeerInvalid(self, to, hash):
        if hash in self.site.p2p_result:
            self.site.p2p_result[hash].set(False)
    def actionPeerValid(self, to, hash):
        if hash in self.site.p2p_result:
            self.site.p2p_result[hash].set(True)



    def peerGenerateMessage(self, all_message, privatekey=None):
        all_message = json.dumps(all_message)
        nonce = str(random.randint(0, 1000000000))
        msg_hash = hashlib.sha256(("%s,%s" % (nonce, all_message)).encode("ascii")).hexdigest()
        signature, cert, cert_text = self.p2pGetSignature(msg_hash, all_message, privatekey)
        return {
            "raw": all_message,
            "signature": signature,
            "cert": cert,
            "nonce": nonce
        }, msg_hash, cert_text


    def peerCheckMessage(self, to, message):
        # Check whether there is p2p.json
        if not self.site.storage.isFile("p2p.json"):
            self.response(to, {"error": "Site %s doesn't support P2P messages" % self.site.address})
            return False

        # Check whether P2P messages are supported
        p2p_json = self.site.storage.loadJson("p2p.json")
        if "filter" not in p2p_json:
            self.response(to, {"error": "Site %s doesn't support P2P messages" % self.site.address})
            return False

        # Check whether the message matches passive filter
        if not SafeRe.match(p2p_json["filter"], json.dumps(message)):
            self.response(to, {"error": "Invalid message for site %s: %s" % (self.site.address, message)})
            return False

        # Not so fast
        if "freq_limit" in p2p_json and time.time() - self.site.p2p_last_recv.get("self", 0) < p2p_json["freq_limit"]:
            self.response(to, {"error": "Too fast messages"})
            return False
        self.site.p2p_last_recv["self"] = time.time()

        # Not so much
        if "size_limit" in p2p_json and len(json.dumps(message)) > p2p_json["size_limit"]:
            self.response(to, {"error": "Too big message"})
            return False

        return True