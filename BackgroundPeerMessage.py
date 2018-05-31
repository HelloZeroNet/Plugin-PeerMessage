_callbacks = []

def module(io):
	class PeerMessage(object):
		def onPeerReceive(self, callback):
			if callback not in _callbacks:
				_callbacks.append(callback)

		def peerBroadcast(self, *args, **kwargs):
			class SimulatedUiWebsocket(object):
				def __init__(self):
					self.site = io["site"]

			ws = SimulatedUiWebsocket()

			import UiWebsocketPlugin
			f = UiWebsocketPlugin.actionPeerBroadcast.__get__(ws, UiWebsocketPlugin)
			f(*args, **kwargs)

	return PeerMessage()