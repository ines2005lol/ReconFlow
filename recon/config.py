"""Settings for the pipeline.

Everything here is a plain constant on purpose: the set of scannable targets must not
be changeable from the command line or from input, only by editing this file.
"""

# The only targets the tool will ever scan, as (host, port) pairs.
# This is the port Juice Shop is published on, on this machine (see docker-compose.yml).
ALLOWED_TARGETS: frozenset[tuple[str, int]] = frozenset({
    ("127.0.0.1", 3001),
    ("localhost", 3001),
})

# The scanners run in their own containers attached to the Juice Shop container's
# network (docker run --network container:<name>). Inside that shared network,
# Juice Shop is on its *container* port, not the host port we publish:
#
#   your PC:             127.0.0.1:3001  --(Docker port mapping)-->  Juice Shop :3000
#   scanner container:   127.0.0.1:3000  (same network namespace as Juice Shop)
LAB_CONTAINER = "recon-lab-juice-shop-1"
HOST_TO_CONTAINER_PORT: dict[int, int] = {3001: 3000}

# Scanner images, pinned to exact versions so results are reproducible.
NMAP_IMAGE = "instrumentisto/nmap:7.98"

# Seconds before a step is killed. Generous enough for a single-port lab,
# short enough that a hung scanner never blocks the pipeline forever.
LAB_CHECK_TIMEOUT = 5
NMAP_TIMEOUT = 300
HTTPX_TIMEOUT = 120
NUCLEI_TIMEOUT = 900
