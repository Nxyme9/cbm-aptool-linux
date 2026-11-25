#!/usr/bin/env python3
"""Offline checks for mcp_cbm_server.py: six read-only tools, no device, no PE.

Fixtures are synthetic regular files under /tmp/opencode. Tool functions are
called directly (no live MCP handshake); one case runs the real locally built
./cbm-tool to prove the schema cbm/1 reaches through.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import mcp_cbm_server as server  # noqa: E402
except ModuleNotFoundError as exc:
    # Environment gate: the server module imports the Python mcp SDK. CI
    # installs it into a venv (see .github/workflows/ci.yml); a machine without
    # it reports a skip rather than a failure the code did not cause.
    if (exc.name or "").split(".")[0] != "mcp":
        raise
    print(f"SKIP: Python mcp SDK not installed ({exc}); install 'mcp' to run these tests")
    raise SystemExit(0)

EXPECTED_TOOLS = {
    "cbm_container_info", "cbm_container_dump", "cbm_container_diff",
    "cbm_device_layout", "cbm_device_scan", "cbm_entropy_profile",
}
WRITE_WORDS = ("write", "repair", "carve", "mutate", "inject", "restore", "format")
CONTAINER_SIZE = 85688

FAKE_CLI = '''#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
with open(os.environ["CBM_FAKE_ARGV"], "w", encoding="utf-8") as fh:
    json.dump(args, fh)
if os.environ.get("CBM_FAKE_SLEEP"):
    time.sleep(float(os.environ["CBM_FAKE_SLEEP"]))
if os.environ.get("CBM_FAKE_STDERR"):
    sys.stderr.write(os.environ["CBM_FAKE_STDERR"] + "\\n")
if os.environ.get("CBM_FAKE_RC"):
    sys.exit(int(os.environ["CBM_FAKE_RC"]))
print(json.dumps({"schema": os.environ.get("CBM_FAKE_SCHEMA", "cbm/1"),
                  "command": args[0], "status": "ok", "argv": args}))
'''


class McpServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        base = Path("/tmp/opencode")
        base.mkdir(parents=True, exist_ok=True)
        cls.tmp = Path(tempfile.mkdtemp(prefix="cbm-mcp-", dir=str(base)))
        cls.container = cls.tmp / "container.bin"
        cls.plain_a = cls.tmp / "a.plain"
        cls.plain_b = cls.tmp / "b.plain"
        cls.image = cls.tmp / "image.bin"
        cls.output = cls.tmp / "out.plain"
        cls.container.write_bytes(b"\0" * CONTAINER_SIZE)
        cls.plain_a.write_bytes(b"A" * 64)
        cls.plain_b.write_bytes(b"B" * 64)
        cls.image.write_bytes(b"\0" * (1024 * 1024))
        cls.fake_cli = cls.tmp / "fake-cbm-tool"
        cls.fake_cli.write_text(FAKE_CLI, encoding="utf-8")
        cls.fake_cli.chmod(0o700)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _fake(self, **env: str):
        argv_log = self.tmp / f"argv-{len(list(self.tmp.glob('argv-*'))) + 1}.json"
        values = {"CBM_FAKE_ARGV": str(argv_log), **env}
        return (
            mock.patch.object(server, "TOOL_PATH", self.fake_cli),
            mock.patch.dict(os.environ, values),
            argv_log,
        )

    def test_registered_tools_exact_and_read_only(self) -> None:
        tools = asyncio.run(server.mcp.list_tools())
        names = {tool.name for tool in tools}
        self.assertEqual(names, EXPECTED_TOOLS, "exactly six tools must be registered")
        self.assertEqual(len(tools), 6)
        for tool in tools:
            ann = tool.annotations

            def hint(snake: str, camel: str):
                return getattr(ann, snake, getattr(ann, camel, None))

            self.assertIs(hint("read_only_hint", "readOnlyHint"), True, tool.name)
            self.assertIs(hint("destructive_hint", "destructiveHint"), False, tool.name)
            self.assertIs(hint("idempotent_hint", "idempotentHint"), True, tool.name)
            self.assertIs(hint("open_world_hint", "openWorldHint"), False, tool.name)
            required = tool.input_schema.get("required", [])
            self.assertTrue(required, f"{tool.name} declares no required args")
            for arg in required:
                self.assertIn(arg, tool.description, f"{tool.name} must name {arg} in its description")
        exposed_writes = [n for n in names if any(word in n for word in WRITE_WORDS)]
        self.assertEqual(exposed_writes, [], "no write/repair tool may be exposed")

    def test_schema_cbm_1_reaches_through_real_cli(self) -> None:
        doc = server.cbm_container_info(str(self.container))
        self.assertEqual(doc.get("schema"), "cbm/1", doc)
        self.assertEqual(doc.get("status"), "ok", doc)
        self.assertEqual(doc.get("path"), str(self.container))
        self.assertIn("body_len", doc)

    def test_all_six_tools_call_cli_with_argv_and_bare_json(self) -> None:
        cases = [
            (server.cbm_container_info, (str(self.container),),
             "container", [str(self.container)]),
            (server.cbm_container_dump, (str(self.container), str(self.output)),
             "container", [str(self.container), "--dump-plain", str(self.output)]),
            (server.cbm_container_diff, (str(self.plain_a), str(self.plain_b)),
             "diff", [str(self.plain_a), str(self.plain_b)]),
            (server.cbm_device_layout, (str(self.image),), "doctor", [str(self.image)]),
            (server.cbm_device_scan, (str(self.image),), "scan", [str(self.image)]),
            (server.cbm_entropy_profile, (str(self.image),), "heatmap", [str(self.image)]),
        ]
        for fn, args, mode, expected in cases:
            with self.subTest(tool=fn.__name__):
                patch_tool, patch_env, log = self._fake()
                with patch_tool, patch_env:
                    doc = fn(*args)
                self.assertEqual(doc.get("schema"), "cbm/1", doc)
                self.assertEqual(doc.get("status"), "ok", doc)
                self.assertEqual(doc.get("command"), mode, doc)
                self.assertEqual(json.loads(log.read_text()), [mode, *expected, "--json"])

    def test_dump_refuses_device_like_and_input_paths(self) -> None:
        before = self.container.read_bytes()
        patch_tool, patch_env, log = self._fake()
        with patch_tool, patch_env:
            device = server.cbm_container_dump(str(self.container), "/dev/sda")
            same = server.cbm_container_dump(str(self.container), str(self.container))
            uri = server.cbm_container_dump(str(self.container), "file:///tmp/opencode/x")
        self.assertEqual(device["status"], "error", device)
        self.assertIn("device", device["error"])
        self.assertEqual(same["status"], "error", same)
        self.assertIn("must differ", same["error"])
        self.assertEqual(uri["status"], "error", uri)
        self.assertIn("URI", uri["error"])
        self.assertFalse(log.exists(), "rejected writes must not reach the CLI")
        self.assertEqual(self.container.read_bytes(), before)

    def test_error_surfaces_stderr_and_exit_code(self) -> None:
        patch_tool, patch_env, _ = self._fake(
            CBM_FAKE_RC="7", CBM_FAKE_STDERR="synthetic cbm-tool failure"
        )
        with patch_tool, patch_env:
            doc = server.cbm_container_info(str(self.container))
        self.assertEqual(doc["status"], "error", doc)
        self.assertIn("exited 7", doc["error"])
        self.assertIn("synthetic cbm-tool failure", doc["error"])

    def test_timeout_is_enforced(self) -> None:
        patch_tool, patch_env, _ = self._fake(CBM_FAKE_SLEEP="2")
        with patch_tool, patch_env, mock.patch.object(server, "TIMEOUT_SECONDS", 0.2):
            started = time.monotonic()
            doc = server.cbm_container_info(str(self.container))
            elapsed = time.monotonic() - started
        self.assertEqual(doc["status"], "error", doc)
        self.assertIn("timed out", doc["error"])
        self.assertLess(elapsed, 1.5, "subprocess timeout did not fire promptly")

    def test_unexpected_schema_is_rejected(self) -> None:
        patch_tool, patch_env, _ = self._fake(CBM_FAKE_SCHEMA="cbm/0")
        with patch_tool, patch_env:
            doc = server.cbm_container_info(str(self.container))
        self.assertEqual(doc["status"], "error", doc)
        self.assertIn("cbm/1", doc["error"])


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    )
    if result.wasSuccessful():
        print(f"test_mcp_server: {result.testsRun} passed")
    else:
        print(f"test_mcp_server: {len(result.failures) + len(result.errors)} failed, {result.testsRun} run")
        sys.exit(1)
