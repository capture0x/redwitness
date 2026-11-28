"""
Endpoint address check. The operator enters the endpoint URL; SSRF protection is still kept: http(s) only,
userinfo forbidden, ALL of the DNS answer is checked. Metadata/link-local/multicast/CGNAT are always blocked;
loopback and private networks only when the endpoint has `local=True` (for a local model).
Known limit: the connection is NOT pinned to the resolved IP here (rebinding window); this check is pre-request.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

from .reasons import Reason

ALWAYS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "fe80::/10", "fec0::/10", "ff00::/8", "2001::/32",
    "fd00:ec2::/32", "64:ff9b:1::/48")]
LOCAL = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7")]
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_6TO4 = ipaddress.ip_network("2002::/16")


def _inner(ip):
    if ip.version != 6:
        return ip
    n = int(ip)
    if ip in _MAPPED or ip in _NAT64:
        return ipaddress.IPv4Address(n & 0xFFFFFFFF)
    if ip in _6TO4:
        return ipaddress.IPv4Address((n >> 80) & 0xFFFFFFFF)
    return ip


def classify(ip) -> str:
    """'always' | 'local' | 'public'"""
    ip = _inner(ip)
    if any(ip in n for n in ALWAYS):
        return "always"
    if any(ip in n for n in LOCAL):
        return "local"
    return "public"


def default_resolver(host: str, port: int) -> list[str]:
    return [ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def check_endpoint(url: str, local: bool, resolver=default_resolver) -> tuple[Reason | None, dict]:
    """(None, detail) if suitable; otherwise (Reason, detail)."""
    if not url or len(url) > 2048 or any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in url):
        return Reason.ENDPOINT_MALFORMED, {"why": "forbidden character or length"}
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return Reason.ENDPOINT_MALFORMED, {"why": "could not be parsed"}
    if u.scheme not in ("http", "https", "ws", "wss") or not u.hostname:
        return Reason.ENDPOINT_MALFORMED, {"why": "scheme must be http/https (or ws/wss for a WebSocket target)"}
    if u.username is not None or u.password is not None or "@" in u.netloc:
        return Reason.ENDPOINT_MALFORMED, {"why": "user info is not allowed"}
    if "%" in u.netloc:
        return Reason.ENDPOINT_MALFORMED, {"why": "'%' in authority"}
    port = port or (443 if u.scheme in ("https", "wss") else 80)
    try:
        addrs = resolver(u.hostname, port)
    except Exception as e:  # noqa: BLE001
        return Reason.ENDPOINT_DNS_FAILURE, {"why": str(e)[:200]}
    if not addrs:
        return Reason.ENDPOINT_DNS_FAILURE, {"why": "no address"}
    return judge_addresses(addrs, local)


def judge_addresses(addrs: list[str], local: bool) -> tuple[Reason | None, dict]:
    """ALL resolved addresses are checked; if even one is unacceptable, all are refused."""
    seen = []
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            return Reason.ENDPOINT_DNS_FAILURE, {"why": f"invalid address {a}"}
        seen.append(str(ip))
        cls = classify(ip)
        if cls == "always" or (cls == "local" and not local):
            return Reason.ENDPOINT_BLOCKED_ADDRESS, {"ip": str(ip), "class": cls, "resolved": seen}
    return None, {"resolved": seen}


class PinError(Exception):
    def __init__(self, reason: Reason, detail: dict):
        super().__init__(f"{reason.value}: {detail}")
        self.reason, self.detail = reason, detail


def pin_address(host: str, port: int, local: bool, resolver=default_resolver) -> str:
    """Resolves ONCE at CONNECT TIME, checks all addresses and returns the IP to connect to.
    The check and the connection use the same resolution: there is no room for rebinding (a DNS change between check and connect)."""
    try:
        addrs = resolver(host, port)
    except Exception as e:  # noqa: BLE001
        raise PinError(Reason.ENDPOINT_DNS_FAILURE, {"why": str(e)[:200]}) from None
    if not addrs:
        raise PinError(Reason.ENDPOINT_DNS_FAILURE, {"why": "no address"})
    bad, det = judge_addresses(addrs, local)
    if bad:
        raise PinError(bad, det)
    ips = sorted((ipaddress.ip_address(a.split("%")[0]) for a in addrs), key=lambda i: (i.version, int(i)))
    return str(ips[0])
