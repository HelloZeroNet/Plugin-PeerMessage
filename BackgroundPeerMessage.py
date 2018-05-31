def module(io):
	_callbacks = []

	class PeerMessage(object):
		def onPeerReceive(callback):
			if callback not in:
				_callbacks.append(callback)

		def peerBroadcast(*args, **kwargs):
			class SimulatedUiWebsocket(object):
				def __init__(self):
					self.site = io["site"]

			ws = SimulatedUiWebsocket()

			import UiWebsocketPlugin
			f = UiWebsocketPlugin.actionPeerBroadcast.__get__(ws, UiWebsocketPlugin)
			f(*args, **kwargs)

	return PeerMessage()