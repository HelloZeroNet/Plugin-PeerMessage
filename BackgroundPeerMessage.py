def module(io):
	scope0 = io["scope0"][0]
	scope0.import_(names=[("ZeroFrame", "_")], from_=None, level=None)
	zeroframe = scope0["_"]

	class PeerMessage(object):
		def join(self):
			zeroframe.cmd("channelJoin", "peerReceive")

		def onPeerReceive(self, callback):
			def func(message):
				callback(**message)
			zeroframe.on("peerReceive", func)

		def peerBroadcast(self, *args, **kwargs):
			return zeroframe.cmd("peerBroadcast", *args, **kwargs)

		def peerSend(self, *args, **kwargs):
			return zeroframe.cmd("peerSend", *args, **kwargs)

		def peerInvalid(self, *args, **kwargs):
			return zeroframe.cmd("peerInvalid", *args, **kwargs)

		def peerValid(self, *args, **kwargs):
			return zeroframe.cmd("peerValid", *args, **kwargs)

	return PeerMessage()