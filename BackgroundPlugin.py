import BackgroundPeerMessage

try:
	import BackgroundProcessing
	BackgroundProcessing.addModule("PeerMessage", BackgroundPeerMessage)
except ImportError:
	pass