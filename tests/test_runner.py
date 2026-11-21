"""Tests for run_command(). They start the current Python interpreter as a harmless
child process instead of a real scanner, so no scan is ever run."""

import sys

import pytest

from recon.runner import ScannerError, run_command


def test_returns_stdout_on_success():
    result = run_command([sys.executable, "-c", "print('hello')"], timeout=10)
    assert result.stdout.strip() == "hello"


def test_nonzero_exit_raises_with_stderr():
    code = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    with pytest.raises(ScannerError, match="code 3: boom"):
        run_command([sys.executable, "-c", code], timeout=10)


def test_timeout_raises():
    with pytest.raises(ScannerError, match="did not finish within 1 seconds"):
        run_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)


def test_missing_program_raises():
    with pytest.raises(ScannerError, match="was not found"):
        run_command(["definitely-not-a-real-scanner-xyz"], timeout=10)


def test_arguments_are_not_interpreted_by_a_shell():
    # With shell=True, "; echo injected" would run a second command.
    # Without a shell it arrives as one literal argument.
    code = "import sys; print(sys.argv[1])"
    result = run_command([sys.executable, "-c", code, "x; echo injected"], timeout=10)
    assert result.stdout.strip() == "x; echo injected"


@pytest.mark.parametrize("bad", [[], "nmap -sV 127.0.0.1", ["nmap", 3001]])
def test_rejects_non_list_commands(bad):
    with pytest.raises(ScannerError, match="non-empty list of strings"):
        run_command(bad, timeout=10)  # type: ignore[arg-type]
