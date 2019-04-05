try:
	import BackgroundProcessing
	from .BackgroundPeerMessage import module
	BackgroundProcessing.addModule("PeerMessage", module)
except ImportError:
	pass