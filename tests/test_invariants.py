"""invariant I1 (sec. 8, sec. 3.3) — no AWS client with write capability, ever.

sec. 3.3: the broker is the sole credential holder; no other component in this
repository SHALL construct an AWS client with write capability. In Phases 0-2 the
broker itself has none either (`dependencies = []`, no boto3), so the check is
stricter than the invariant needs: no shipped module may import an AWS SDK, a
network client, or a process-spawning facility. A subprocess running the AWS CLI
is a write-capable client by another name, and a raw socket is one by hand.
A Phase 3 broker client would need an explicit, reviewable exemption here.

A2.1 requires an adversarial test for every invariant, and sec. 9.2 makes that
"an input designed to defeat the rule". A grep for `boto3` is defeated by
`import botocore.session`, by `__import__("boto3")`, by `os.system("aws ...")` and
by an import tucked inside a function; the scanner below reads the syntax tree
instead, and `ScannerCanFailTests` feeds it each of those evasions so a scanner
that quietly stopped seeing them fails the suite.

Limits, stated because a static scan has them: it cannot see a module name
computed at runtime (`__import__(name)`, `getattr(os, "sys" + "tem")`) or code
built with `exec`. The `sys.modules` test corroborates the SDK half at runtime.

Complementary, not covered here: I8 (no code path serves a writ) is verified by
human review, not by assertion (A2.4). Stdlib `ast` only (sec. 9.1); no network,
no credentials (sec. 5.5).
"""

from __future__ import annotations

import ast
import importlib
import sys
import tempfile
import textwrap
import tomllib
import unittest
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The code that ships. tests/ is deliberately absent: the suite legitimately
# holds sockets and subprocesses (test_offline, test_redaction) to police this.
SHIPPED_DIRS = ("writ", "tools")

AWS_SDKS = ("boto3", "botocore", "aioboto3", "aiobotocore", "s3transfer", "awscrt")
NETWORK_CLIENTS = (
    "socket", "socketserver", "ssl", "http", "urllib.request", "urllib3", "requests",
    "httpx", "aiohttp", "ftplib", "smtplib", "imaplib", "poplib", "nntplib", "telnetlib",
    "xmlrpc",
)
PROCESS_SPAWNING = ("subprocess", "pty", "multiprocessing")

# Module name -> why it is forbidden. A name matches on itself or any dotted
# ancestor, so `botocore` covers `botocore.session` and `urllib.request` is
# forbidden while its sibling `urllib.parse` is not.
FORBIDDEN_MODULES = {
    **{name: "AWS SDK" for name in AWS_SDKS},
    **{name: "network client" for name in NETWORK_CLIENTS},
    **{name: "process spawning" for name in PROCESS_SPAWNING},
}

# `posix` is what `os` re-exports on Linux: `posix.system(...)` is `os.system(...)`.
OS_MODULES = frozenset({"os", "posix"})
FORBIDDEN_OS_NAMES = frozenset({"system", "popen"})
FORBIDDEN_OS_PREFIXES = ("exec", "spawn", "posix_spawn")

DYNAMIC_IMPORTERS = frozenset({"__import__", "import_module"})


def _forbidden_module(name: str) -> str | None:
    """Why `name` is forbidden, or None. Matches the name or any dotted ancestor."""
    parts = name.split(".")
    for end in range(1, len(parts) + 1):
        reason = FORBIDDEN_MODULES.get(".".join(parts[:end]))
        if reason is not None:
            return reason
    return None


def _forbidden_os_name(name: str) -> bool:
    return name in FORBIDDEN_OS_NAMES or name.startswith(FORBIDDEN_OS_PREFIXES)


def _os_aliases(tree: ast.AST) -> dict[str, str]:
    """Local names bound to `os`/`posix`, so `import os as o; o.system(...)` is seen."""
    aliases = {module: module for module in OS_MODULES}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in OS_MODULES and alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def _importer_names(tree: ast.AST) -> frozenset[str]:
    """Names that import by string: `__import__`, `import_module`, and any alias."""
    names = set(DYNAMIC_IMPORTERS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("importlib", "builtins"):
            names.update(a.asname for a in node.names if a.asname and a.name in DYNAMIC_IMPORTERS)
    return frozenset(names)


def _dynamic_import_literal(call: ast.Call, importers: frozenset[str]) -> str | None:
    """The string literal handed to a dynamic import, if there is one."""
    func = call.func
    if isinstance(func, ast.Name):
        called = func.id
    elif isinstance(func, ast.Attribute):
        called = func.attr
    else:
        return None
    if called not in importers:
        return None
    if call.args:
        arg = call.args[0]
    else:
        arg = next((kw.value for kw in call.keywords if kw.arg == "name"), None)
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


def forbidden_in_source(source: str | bytes, filename: str) -> list[str]:
    """Every forbidden capability in `source`, as `filename:line: what`, in line order.

    Walks the whole tree, so an import inside a function, a `try`, or an
    `if TYPE_CHECKING:` block is found like any other. A type-only import is
    flagged deliberately: the rule is no SDK anywhere, not no SDK at runtime.
    Relative imports are skipped; they name a sibling module, not a library.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError, RecursionError) as exc:
        # A file that cannot be read cannot be cleared; passing it would be the
        # scanner's way of being defeated by a syntax error.
        return [f"{filename}: cannot be parsed, so cannot be verified ({type(exc).__name__})"]

    os_aliases = _os_aliases(tree)
    importers = _importer_names(tree)
    hits: list[tuple[int, int, str]] = []

    def add(node: ast.AST, what: str) -> None:
        hits.append((node.lineno, node.col_offset, what))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                reason = _forbidden_module(alias.name)
                if reason:
                    add(node, f"imports {alias.name} ({reason})")
        elif isinstance(node, ast.ImportFrom) and not node.level:
            base = node.module or ""
            reason = _forbidden_module(base)
            if reason:
                add(node, f"imports {base} ({reason})")
                continue
            for alias in node.names:
                # `from urllib import request` imports urllib.request.
                full = f"{base}.{alias.name}"
                reason = _forbidden_module(full)
                if reason:
                    add(node, f"imports {full} ({reason})")
                elif base in OS_MODULES and _forbidden_os_name(alias.name):
                    add(node, f"imports {full} (process spawning)")
        elif isinstance(node, ast.Attribute):
            # A reference, not only a call: `run = os.system` must not slip through.
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in os_aliases
                and _forbidden_os_name(node.attr)
            ):
                add(node, f"references {os_aliases[node.value.id]}.{node.attr} (process spawning)")
        elif isinstance(node, ast.Call):
            literal = _dynamic_import_literal(node, importers)
            if literal is not None:
                reason = _forbidden_module(literal)
                if reason:
                    add(node, f"dynamically imports {literal} ({reason})")

    return [f"{filename}:{line}: {what}" for line, _col, what in sorted(hits)]


def shipped_python_files(root: Path) -> list[Path]:
    """Every .py file under the shipped directories of `root`."""
    files: list[Path] = []
    for name in SHIPPED_DIRS:
        files.extend(sorted((root / name).rglob("*.py")))
    return files


def forbidden_in_tree(root: Path) -> list[str]:
    """Findings across every shipped file under `root`."""
    findings: list[str] = []
    for path in shipped_python_files(root):
        findings.extend(forbidden_in_source(path.read_bytes(), path.relative_to(root).as_posix()))
    return findings


def loaded_sdk_modules(module_names: Iterable[str]) -> list[str]:
    """Names in `module_names` that are an AWS SDK or one of its submodules."""
    return sorted(
        name
        for name in module_names
        if any(name == sdk or name.startswith(sdk + ".") for sdk in AWS_SDKS)
    )


class InvariantI1Tests(unittest.TestCase):
    """invariant I1 — checked against the real tree, the real imports, the real manifest."""

    def test_shipped_code_constructs_no_aws_client(self) -> None:
        """invariant I1, sec. 3.3 — nothing under writ/ or tools/ can hold an AWS client."""
        findings = forbidden_in_tree(REPO_ROOT)
        self.assertEqual(
            findings,
            [],
            "invariant I1 (sec. 3.3): shipped code holds an AWS SDK, network client or "
            "process-spawning capability:\n  " + "\n  ".join(findings),
        )

    def test_the_scan_covers_the_shipped_modules(self) -> None:
        """A scan of nothing passes the test above; the scan must reach the real modules."""
        scanned = {p.relative_to(REPO_ROOT).as_posix() for p in shipped_python_files(REPO_ROOT)}
        for expected in (
            "writ/admission.py",
            "writ/cli.py",
            "writ/decisions.py",
            "writ/petition.py",
            "writ/writs.py",
            "tools/redact_fixture.py",
        ):
            self.assertIn(expected, scanned, f"I1 scan did not reach {expected}")
        self.assertGreaterEqual(len(scanned), 6)

    def test_no_python_ships_outside_the_scanned_directories(self) -> None:
        """A new code directory (a `scripts/`, say) would otherwise escape the scan.

        Every committed .py file is either a test or under SHIPPED_DIRS. Adding a
        directory means adding it to SHIPPED_DIRS, which puts it under I1.
        """
        from tests.test_redaction import committed_files

        outside = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in committed_files()
            if path.suffix == ".py"
            and path.relative_to(REPO_ROOT).parts[0] not in (*SHIPPED_DIRS, "tests")
        )
        self.assertEqual(
            outside, [], f"Python outside {SHIPPED_DIRS} and tests/ is not scanned for I1"
        )

    def test_importing_the_broker_loads_no_aws_sdk(self) -> None:
        """invariant I1 — runtime corroboration of the static scan.

        Only SDK names are checked: this process legitimately has socket and
        subprocess loaded by other tests, so those would be false alarms here.
        """
        for name in ("writ.cli", "writ.admission", "writ.decisions", "writ.petition", "writ.writs"):
            importlib.import_module(name)
        self.assertEqual(
            loaded_sdk_modules(list(sys.modules)),
            [],
            "invariant I1: importing the broker loaded an AWS SDK",
        )

    def test_no_runtime_dependencies_are_declared(self) -> None:
        """CLAUDE.md, invariant I1 — Phases 0-2 declare no dependency, so no boto3.

        An absent `dependencies` key fails too: the manifest must say so explicitly.
        """
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        self.assertEqual(project.get("dependencies"), [])


class ScannerCanFailTests(unittest.TestCase):
    """sec. 9.2 — the detector must be able to fail, or it asserts nothing.

    Each source below is an attempt to hold write capability that a naive check
    misses. Exercised on in-memory text, so the check never depends on a real
    violation existing to prove it works.
    """

    EVASIONS = (
        # AWS SDKs, every import spelling.
        ("import boto3", "boto3"),
        ("import botocore.session", "botocore.session"),
        ("from botocore.client import Config", "botocore.client"),
        ("from boto3 import client", "boto3"),
        ("import aioboto3", "aioboto3"),
        ("import aiobotocore.session", "aiobotocore.session"),
        ("import s3transfer", "s3transfer"),
        ("import awscrt.http", "awscrt.http"),
        # Process spawning: the AWS CLI through a subprocess is a client.
        ("import subprocess", "subprocess"),
        ("from subprocess import run", "subprocess"),
        ("import pty", "pty"),
        ("import multiprocessing", "multiprocessing"),
        # Network clients.
        ("import socket", "socket"),
        ("import ssl", "ssl"),
        ("import http", "http"),
        ("import http.client", "http.client"),
        ("import http.server", "http.server"),
        ("from urllib.request import urlopen", "urllib.request"),
        ("import urllib.request", "urllib.request"),
        ("from urllib import request", "urllib.request"),
        ("import urllib3", "urllib3"),
        ("import requests", "requests"),
        ("import httpx", "httpx"),
        ("import aiohttp", "aiohttp"),
        ("import ftplib", "ftplib"),
        ("import smtplib", "smtplib"),
        ("import xmlrpc.client", "xmlrpc.client"),
        # Dynamic imports whose argument is a string literal.
        ('__import__("boto3")', "boto3"),
        ('__import__(name="boto3")', "boto3"),
        ('import importlib\nimportlib.import_module("botocore")', "botocore"),
        ('import importlib\nimportlib.import_module(name="botocore.session")', "botocore.session"),
        ('from importlib import import_module\nimport_module("botocore.session")', "botocore.session"),
        ('from importlib import import_module as load\nload("boto3")', "boto3"),
        ('import builtins\nbuiltins.__import__("subprocess")', "subprocess"),
        # Process replacement or launch through os.
        ('import os\nos.system("aws s3 rm ...")', "os.system"),
        ('import os\nos.popen("aws s3 rm ...")', "os.popen"),
        ('import os\nos.execv("/usr/bin/aws", ["aws"])', "os.execv"),
        ('import os\nos.execvp("aws", ["aws"])', "os.execvp"),
        ('import os\nos.spawnl(os.P_WAIT, "/usr/bin/aws", "aws")', "os.spawnl"),
        ('import os\nos.posix_spawn("/usr/bin/aws", ["aws"], {})', "os.posix_spawn"),
        # Evasions of the os check: rebinding, reference without a call, posix.
        ('import os as o\no.system("aws s3 rm ...")', "os.system"),
        ('import os\nrun = os.system\nrun("aws s3 rm ...")', "os.system"),
        ("from os import system", "os.system"),
        ("from os import execv as go", "os.execv"),
        ('import posix\nposix.system("aws s3 rm ...")', "posix.system"),
        # Nesting: the import is not at module level.
        ("def f():\n    import boto3", "boto3"),
        ("async def f():\n    import subprocess", "subprocess"),
        ("class C:\n    import socket", "socket"),
        ("try:\n    import boto3\nexcept ImportError:\n    boto3 = None", "boto3"),
        ("try:\n    pass\nexcept Exception:\n    import requests", "requests"),
        ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import botocore.client", "botocore.client"),
        ("if True:\n    def f():\n        return __import__('boto3')", "boto3"),
    )

    HARMLESS = (
        "import json",
        "import hashlib",
        "import os\nos.path.join('a', 'b')\nos.replace('a', 'b')\nos.environ.get('X')",
        "import os as o\no.getcwd()",
        "from os import path",
        "from urllib.parse import quote",
        "import urllib.parse",
        "from urllib import parse",
        "from tests.test_redaction import ACCOUNT_ID_PATTERN",
        "from . import sibling\nfrom .sibling import thing",
        "from importlib import import_module\nimport_module('json')",
        "__import__('json')",
        "import importlib\nimportlib.import_module(name)",
        # Strings and comments that merely mention a forbidden name: the reason to
        # read the syntax tree rather than grep the text.
        '"""Never `import boto3`; never call os.system."""',
        "# import subprocess\nx = 'import boto3'\ny = ['socket', 'requests']",
        "def system(): ...\nsystem()",
    )

    def test_the_scanner_catches_each_evasion(self) -> None:
        """invariant I1 — every source here defeats a naive grep; none may pass this one."""
        for source, expected in self.EVASIONS:
            with self.subTest(source=source):
                findings = forbidden_in_source(source, "<probe>")
                self.assertTrue(findings, f"scanner missed: {source!r}")
                self.assertTrue(
                    any(expected in finding for finding in findings),
                    f"scanner reported {findings} but never named {expected!r}",
                )

    def test_the_scanner_does_not_flag_harmless_sources(self) -> None:
        """A scanner that flags everything would fail I1's test for the wrong reason."""
        for source in self.HARMLESS:
            with self.subTest(source=source):
                self.assertEqual(forbidden_in_source(source, "<probe>"), [])

    def test_a_finding_names_the_file_and_line(self) -> None:
        """The failure message must let a reviewer go straight to the offending line."""
        self.assertEqual(
            forbidden_in_source("x = 1\nimport boto3\n", "writ/probe.py"),
            ["writ/probe.py:2: imports boto3 (AWS SDK)"],
        )
        found = forbidden_in_source("import subprocess\nimport boto3\nimport json\n", "p.py")
        self.assertEqual([f.split(": ")[0] for f in found], ["p.py:1", "p.py:2"])

    def test_a_file_that_cannot_be_parsed_is_a_finding_not_a_pass(self) -> None:
        """A syntax error must not be a way to hide an import from the scan."""
        for source in ("def (:", "import boto3 as", "\x00import boto3"):
            with self.subTest(source=source):
                self.assertTrue(forbidden_in_source(source, "<probe>"))

    def test_the_tree_scan_reports_a_planted_violation(self) -> None:
        """The whole-tree path, not just the per-source one, can fail."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "writ").mkdir()
            (root / "tools").mkdir()
            (root / "writ" / "clean.py").write_text("import json\n", encoding="utf-8")
            (root / "writ" / "dirty.py").write_text(
                textwrap.dedent(
                    """\
                    def later():
                        import botocore.session
                    """
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                forbidden_in_tree(root),
                ["writ/dirty.py:2: imports botocore.session (AWS SDK)"],
            )

    def test_the_sdk_module_check_can_fail(self) -> None:
        """The runtime check needs a negative case too, or it asserts nothing."""
        self.assertEqual(
            loaded_sdk_modules(["json", "botocore.session", "boto3", "awscrt"]),
            ["awscrt", "boto3", "botocore.session"],
        )
        # A name that merely starts with an SDK's letters is a different module.
        self.assertEqual(loaded_sdk_modules(["boto3rd", "botocorex", "json"]), [])


if __name__ == "__main__":
    unittest.main()
