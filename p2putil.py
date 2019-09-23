try:
    from MergerSite import MergerSitePlugin
    has_merger_plugin = True
except ImportError:
    has_merger_plugin = False

from . import BackgroundPeerMessage
import functools
import socket
import subprocess
import gevent
import gevent.subprocess
from util import helper


def getWebsockets(site):
    # First, site's own websockets
    websockets = site.websockets[:]

    # Now merger site
    if has_merger_plugin:
        merger_sites = MergerSitePlugin.merged_to_merger.get(site.address, [])
        for merger_site in merger_sites:
            if merger_site.address == site.address:
                continue
            websockets += merger_site.websockets

    # Filter out sites not supporting P2P
    # (e.g. ZeroHello, which joins all channels automatically)
    return [ws for ws in websockets if "peerReceive" in ws.channels]


@functools.lru_cache(maxsize=2048)
def traceroute(ip):
    subprocess.run("C:\\Windows\\System32\\cmd.exe /c chcp 437", capture_output=True)

    threads = [gevent.spawn(ping, ip, ttl) for ttl in range(1, 31)]
    gevent.joinall(threads)

    ips = []
    for thread in threads:
        if thread.value == ip:
            break
        if thread.value is not None and not helper.isPrivateIp(thread.value):
            ips.append(thread.value)

    subprocess.run("C:\\Windows\\System32\\cmd.exe /c chcp 65001", capture_output=True)

    return ips


def ping(ip, ttl):
    args = [
        "C:\\Windows\\System32\\ping.exe",
        "-n", "1",
        "-i", str(ttl),
        "-w", "1000",
        ip
    ]

    lines = gevent.subprocess.run(args, capture_output=True).stdout.split(b"\r\n")
    reply_ip = None
    for line in lines:
        if line.startswith(b"Reply from "):
            reply_ip = line[len(b"Reply from "):].split(b":")[0].decode()

    return reply_ip