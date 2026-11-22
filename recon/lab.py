"""Check that the lab answers before any scanner is started."""

import logging
import urllib.error
import urllib.request

from recon import config
from recon.targets import Target

logger = logging.getLogger(__name__)

# An opener with an empty ProxyHandler ignores HTTP_PROXY/HTTPS_PROXY environment
# variables, so the lab check can never be routed through a proxy to another machine.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LabUnreachableError(Exception):
    """The lab did not answer; scanning would only produce errors."""


def check_lab(target: Target) -> None:
    """Raise LabUnreachableError unless the lab returns any HTTP response."""
    try:
        with _opener.open(target.url, timeout=config.LAB_CHECK_TIMEOUT) as response:
            logger.info("Lab is up: %s answered HTTP %s", target.url, response.status)
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is still an answer from a running web server.
        logger.info("Lab is up: %s answered HTTP %s", target.url, exc.code)
    except (urllib.error.URLError, OSError) as exc:
        raise LabUnreachableError(
            f"Lab at {target.url} is not reachable ({exc}). "
            "Is Docker running? Start the lab with: docker compose up -d"
        ) from exc
