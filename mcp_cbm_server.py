#!/usr/bin/env python3
"""stdio MCP server: thin read-only wrappers over the local ./cbm-tool CLI.

Requires a locally built ./cbm-tool (``make``) and the Python ``mcp`` SDK.
No network, no vendor PE, no device writes and no MBR repair are exposed.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

SCHEMA = "cbm/1"
REPO_ROOT = Path(__file__).resolve().parent
TOOL_PATH = REPO_ROOT / "cbm-tool"
TIMEOUT_SECONDS = 20.0

ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

mcp = MCPServer("cbm")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _err(command: str, message: str) -> dict:
    return {"schema": SCHEMA, "command": command, "status": "error", "error": message}


def _local_path(value: object, label: str) -> str:
    """Accept only plain local paths (never URIs, UNC, flags or NUL bytes)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty local path")
    if "\0" in value or value.startswith("-") or value.startswith("\\\\") or value.startswith("//"):
        raise ValueError(f"{label} must be a plain local path, not a flag/UNC/NUL path: {value!r}")
    if _SCHEME.match(value):
        raise ValueError(f"{label} must be local, not a URI: {value!r}")
    return os.path.abspath(value)


def _is_device(path: str) -> bool:
    """True for block/char devices and anything under /dev (stub-safe)."""
    if path == "/dev" or path.startswith("/dev/"):
        return True
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode)


def _dump_target(output_path: object, source: str) -> str:
    """Validate the only local write target before cbm-tool is invoked."""
    target = _local_path(output_path, "output_path")
    if _is_device(target):
        raise ValueError(f"output_path must be a local regular file, not a device: {target!r}")
    if os.path.realpath(target) == os.path.realpath(source):
        raise ValueError("output_path must differ from the container path; refusing to overwrite the input")
    if os.path.exists(target):
        if not stat.S_ISREG(os.stat(target).st_mode):
            raise ValueError(f"output_path must be a regular file: {target!r}")
        try:
            if os.path.samefile(target, source):
                raise ValueError("output_path must differ from the container path; refusing to overwrite the input")
        except OSError:
            pass
    parent = os.path.dirname(target) or "."
    if not os.path.isdir(parent):
        raise ValueError(f"output_path parent directory does not exist: {parent!r}")
    return target


def _run_cli(command: str, arguments: list[str]) -> dict:
    """Run one CLI mode with an argv list, a timeout and one JSON document."""
    argv = [str(TOOL_PATH), command, *arguments, "--json"]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, check=False,
            cwd=str(REPO_ROOT), timeout=TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return _err(command, f"cbm-tool not found at {TOOL_PATH}; build it locally with `make`")
    except subprocess.TimeoutExpired:
        return _err(command, f"cbm-tool {command} timed out after {TIMEOUT_SECONDS:g}s; check target size or use a smaller range")

    stderr = proc.stderr.strip()
    doc = None
    try:
        doc = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        pass

    if proc.returncode != 0:
        detail = str(doc.get("error", "")) if isinstance(doc, dict) else ""
        if stderr and stderr != detail:
            detail = f"{detail}; {stderr}" if detail else stderr
        return _err(command, f"cbm-tool {command} exited {proc.returncode}: {detail or 'no stderr output'}")

    if not isinstance(doc, dict):
        return _err(command, f"cbm-tool {command} did not return one JSON object: {proc.stdout[:200]!r}")
    if doc.get("schema") != SCHEMA:
        return _err(command, f"cbm-tool {command} returned schema {doc.get('schema')!r}, expected {SCHEMA}; rebuild with `make`")
    if doc.get("status") != "ok":
        return _err(command, str(doc.get("error") or f"cbm-tool {command} reported status {doc.get('status')!r}"))
    return doc


@mcp.tool(
    name="cbm_container_info",
    description="Read-only container header, size, entropy and token hits. Required: path (local container file).",
    annotations=ANNOTATIONS,
)
def cbm_container_info(path: str) -> dict:
    try:
        return _run_cli("container", [_local_path(path, "path")])
    except ValueError as exc:
        return _err("container", str(exc))


@mcp.tool(
    name="cbm_container_dump",
    description="Decrypt a container to a local plaintext file (the only file write). Required: path (container), output_path (regular local file, never the input or a device).",
    annotations=ANNOTATIONS,
)
def cbm_container_dump(path: str, output_path: str) -> dict:
    try:
        source = _local_path(path, "path")
        target = _dump_target(output_path, source)
        return _run_cli("container", [source, "--dump-plain", target])
    except ValueError as exc:
        return _err("container", str(exc))


@mcp.tool(
    name="cbm_container_diff",
    description="Read-only changed ranges between two plaintext bodies. Required: path_a, path_b (local plaintext files).",
    annotations=ANNOTATIONS,
)
def cbm_container_diff(path_a: str, path_b: str) -> dict:
    try:
        a = _local_path(path_a, "path_a")
        b = _local_path(path_b, "path_b")
        return _run_cli("diff", [a, b])
    except ValueError as exc:
        return _err("diff", str(exc))


@mcp.tool(
    name="cbm_device_layout",
    description="Read-only MBR and DJ partition validation report. Required: path (local image or block device).",
    annotations=ANNOTATIONS,
)
def cbm_device_layout(path: str) -> dict:
    try:
        return _run_cli("doctor", [_local_path(path, "path")])
    except ValueError as exc:
        return _err("doctor", str(exc))


@mcp.tool(
    name="cbm_device_scan",
    description="Read-only container scan of an image or device. Required: path (local image or block device).",
    annotations=ANNOTATIONS,
)
def cbm_device_scan(path: str) -> dict:
    try:
        return _run_cli("scan", [_local_path(path, "path")])
    except ValueError as exc:
        return _err("scan", str(exc))


@mcp.tool(
    name="cbm_entropy_profile",
    description="Read-only block entropy summary for an image or device. Required: path (local image or block device).",
    annotations=ANNOTATIONS,
)
def cbm_entropy_profile(path: str) -> dict:
    try:
        return _run_cli("heatmap", [_local_path(path, "path")])
    except ValueError as exc:
        return _err("heatmap", str(exc))


if __name__ == "__main__":
    mcp.run(transport="stdio")
