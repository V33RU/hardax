"""Shared pytest fixtures and helpers for the HARDAX test suite."""
import os
import sys
import glob
import json

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import hardax  # noqa: E402

PKG_DIR = os.path.dirname(hardax.__file__)
COMMANDS_DIR = os.path.join(PKG_DIR, "commands")
SCHEMA_PATH = os.path.join(PKG_DIR, "commands.schema.json")


class FakeDevice(hardax.Device):
    """Test double for a Device: returns canned output for shell commands.

    responses maps a substring of the command to the output to return; the
    first matching entry wins, otherwise `default` is returned.
    """

    def __init__(self, responses=None, default=""):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def shellEx(self, command):
        """Canned output is treated as stdout with a clean exit.

        Recorded fixtures are device stdout, so stderr is empty and the exit
        status is 0. A fixture that records a device failure message therefore
        arrives on stdout exactly as it does on real hardware, which is where
        the engine detects it.
        """
        self.calls.append(command)
        for key, val in self.responses.items():
            if key in command:
                return hardax.ShellResult(val, "", 0)
        return hardax.ShellResult(self.default, "", 0)

    def shell(self, command):
        return self.shellEx(command).merged

    def idString(self):
        return "fake-device"


def make_check(**over):
    """A minimal valid check dict, overridable per test."""
    base = {
        "category": "TEST",
        "label": "unit-check",
        "command": "getprop x",
        "safe_pattern": ".",
        "level": "info",
        "description": "test check",
    }
    base.update(over)
    return base


def load_all_checks():
    """Every check across all bundled command files, each tagged with _file."""
    out = []
    for fp in sorted(glob.glob(os.path.join(COMMANDS_DIR, "*.json"))):
        data = json.load(open(fp, encoding="utf-8"))
        checks = data["checks"] if isinstance(data, dict) else data
        for c in checks:
            c = dict(c)
            c["_file"] = os.path.basename(fp)
            out.append(c)
    return out


@pytest.fixture
def run_check():
    """Run a single check through the engine and return (row, counts)."""
    def _run(check, output="", responses=None, **kw):
        dev = FakeDevice(responses=responses, default=output)
        rows, counts = hardax.runChecks(dev, [check], **kw)
        return rows[0], counts
    return _run
