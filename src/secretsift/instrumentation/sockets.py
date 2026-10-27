"""Network policy helpers and the process-global socket guard."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from secretsift.instrumentation.capture import Instrumentation

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9-]{1,30}$")


def normalize_host(host: str | bytes) -> str:
    """Lower-case host without brackets, IPv6 zone or trailing dot."""
    text = host.decode("utf-8", "replace") if isinstance(host, bytes) else host
    text = text.strip().strip("[]").split("%", 1)[0].rstrip(".")
    return text.casefold()


def is_loopback(host: str | bytes) -> bool:
    """True for localhost and loopback IP literals (IPv4, IPv6, IPv4-mapped)."""
    name = normalize_host(host)
    if name in _LOOPBACK_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


def normalize_allowlist(entries: Iterable[str]) -> frozenset[str]:
    """Normalize allowlist entries (hostnames, IPs, ``*.suffix`` wildcards)."""
    return frozenset(normalize_host(e) for e in entries if e.strip())


def host_allowed(host: str | bytes, *, offline: bool, allowlist: frozenset[str]) -> bool:
    """Loopback is always allowed. Offline blocks the rest; online enforces a non-empty list."""
    if is_loopback(host):
        return True
    if offline:
        return False
    if not allowlist:
        return True
    name = normalize_host(host)
    if name in allowlist:
        return True
    return any(e.startswith("*.") and name.endswith(e[1:]) for e in allowlist)


def blocked_message(host: str | bytes, *, offline: bool) -> str:
    """Error text naming at most the last two DNS labels (hosts can carry data)."""
    name = normalize_host(host)
    labels = name.split(".")
    view = "<host>"
    try:
        view = str(ipaddress.ip_address(name))
    except ValueError:
        tail = labels[-2:]
        if all(_SAFE_LABEL.match(part) for part in tail):
            view = ("..." if len(labels) > 2 else "") + ".".join(tail)
    reason = "offline mode" if offline else "not in network_allowlist"
    return f"network access to non-loopback host {view} blocked by secretsift ({reason})"


def patch_attr(owner: Any, name: str, replacement: Any) -> Callable[[], None]:
    """Replace ``owner.name``; the returned callable restores it exactly."""
    had_own = name in vars(owner)
    original = vars(owner).get(name)
    setattr(owner, name, replacement)

    def restore() -> None:
        if had_own:
            setattr(owner, name, original)
        else:
            delattr(owner, name)

    return restore


def _guard_address(inst: Instrumentation, address: Any) -> None:
    if isinstance(address, tuple) and address and isinstance(address[0], str | bytes):
        inst.guard_host(address[0])


def install(active: Callable[[], Instrumentation | None]) -> Callable[[], None]:
    """Guard ``socket.socket.connect/connect_ex`` and ``socket.getaddrinfo``."""
    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_getaddrinfo = socket.getaddrinfo

    def connect(self: socket.socket, address: Any) -> None:
        inst = active()
        if inst is not None:
            _guard_address(inst, address)
        orig_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        inst = active()
        if inst is not None:
            _guard_address(inst, address)
        return orig_connect_ex(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        inst = active()
        if inst is not None and isinstance(host, str | bytes) and host:
            inst.guard_host(host)
        return orig_getaddrinfo(host, *args, **kwargs)

    restores = [
        patch_attr(socket.socket, "connect", connect),
        patch_attr(socket.socket, "connect_ex", connect_ex),
        patch_attr(socket, "getaddrinfo", getaddrinfo),
    ]

    def restore() -> None:
        for undo in reversed(restores):
            undo()

    return restore
