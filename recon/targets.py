"""Target validation: the first gate of the pipeline.

Every scan starts with validate_target(). If the input is not exactly one of the
allowlisted lab URLs, a TargetError is raised and no scanner is ever started.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from recon import config

MAX_TARGET_LENGTH = 100


class TargetError(ValueError):
    """The requested target is not an allowed local lab target."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    @property
    def url(self) -> str:
        """The URL as seen from this machine, e.g. http://127.0.0.1:3001."""
        return f"http://{self.host}:{self.port}"

    @property
    def scanner_host(self) -> str:
        # Always the IPv4 loopback inside the scanner container, even if the user
        # typed "localhost", so tools never try IPv6 (::1) where nothing listens.
        return "127.0.0.1"

    @property
    def scanner_port(self) -> int:
        """The port Juice Shop listens on inside the shared container network."""
        return config.HOST_TO_CONTAINER_PORT[self.port]

    @property
    def scanner_url(self) -> str:
        """The URL as seen from a scanner container, e.g. http://127.0.0.1:3000."""
        return f"http://{self.scanner_host}:{self.scanner_port}"


def validate_target(raw: str) -> Target:
    """Return a Target if `raw` is an allowlisted lab URL, otherwise raise TargetError.

    Accepted form: http://<host>:<port> or http://<host>:<port>/ where (host, port)
    is in config.ALLOWED_TARGETS. Anything else is rejected rather than "cleaned up",
    because guessing what the user meant is how scanners end up hitting the wrong host.
    """
    if not isinstance(raw, str) or not raw:
        raise TargetError("Target must be a non-empty string.")
    if len(raw) > MAX_TARGET_LENGTH:
        raise TargetError("Target is too long.")
    if raw != raw.strip() or any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise TargetError("Target must not contain whitespace or control characters.")

    parts = urlsplit(raw)

    if parts.scheme != "http":
        raise TargetError(f"Only http:// targets are allowed, got {raw!r}.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("Credentials in the target URL are not allowed.")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise TargetError("Target must be just http://host:port, without path, query or fragment.")

    host = (parts.hostname or "").lower()
    try:
        port = parts.port  # raises ValueError for things like ":abc" or ":99999"
    except ValueError as exc:
        raise TargetError(f"Invalid port in target {raw!r}.") from exc
    if port is None:
        raise TargetError("Target must include an explicit port, e.g. http://127.0.0.1:3001.")

    if (host, port) not in config.ALLOWED_TARGETS:
        allowed = ", ".join(f"http://{h}:{p}" for h, p in sorted(config.ALLOWED_TARGETS))
        raise TargetError(f"Target {host}:{port} is not in the allowlist. Allowed: {allowed}")

    return Target(host=host, port=port)
