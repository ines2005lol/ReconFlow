"""The single place where the tool starts external programs.

Every scanner goes through run_command(), so the safety rules live in one spot:
  - the command is a list of arguments, never a shell string (no shell=True),
  - every call has a timeout,
  - every way a program can fail becomes a ScannerError with a readable message.
"""

import logging
import subprocess

logger = logging.getLogger(__name__)

# How much of a failing program's stderr to keep in the error message.
MAX_STDERR_CHARS = 1000


class ScannerError(Exception):
    """An external program could not be run or did not finish successfully."""


def run_command(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run `args` and return the finished process, or raise ScannerError.

    Because `args` is a list and there is no shell, each element reaches the program
    as exactly one argument. A value like "127.0.0.1; del C:\\*" stays one harmless
    (and invalid) argument instead of becoming a second command.
    """
    # isinstance(list) matters: a plain string is iterable too, and each character
    # would pass the str check below.
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        raise ScannerError("Command must be a non-empty list of strings.")

    program = args[0]
    logger.debug("Running: %s", " ".join(args))

    try:
        result = subprocess.run(
            args,
            capture_output=True,  # collect stdout/stderr instead of printing them
            text=True,  # give us str, not bytes
            encoding="utf-8",
            errors="replace",  # a stray non-UTF-8 byte must not crash the parser
            timeout=timeout,  # the child is killed when this runs out
            check=False,  # we inspect the return code ourselves, below
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"{program!r} was not found. Is it installed and on your PATH?") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{program!r} did not finish within {timeout} seconds.") from exc
    except OSError as exc:  # e.g. permission denied, blocked by Windows policy
        raise ScannerError(f"{program!r} could not be started: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()[-MAX_STDERR_CHARS:] or "(no error output)"
        raise ScannerError(f"{program!r} exited with code {result.returncode}: {stderr}")

    return result
