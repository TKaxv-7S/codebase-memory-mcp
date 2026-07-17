#!/usr/bin/env python3
"""Bounded interactive MCP smoke scenarios.

Unlike a regular-file fixture, this keeps stdin open while each potentially
long-running request completes. That models a standing coding-agent session
and prevents EOF/session cancellation from racing the response assertions.
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO


INITIALIZE_PARAMS = {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "interactive-smoke", "version": "1.0"},
}


class SmokeFailure(RuntimeError):
    pass


def read_json_lines(
    stream: BinaryIO,
    responses: "queue.Queue[dict[str, Any]]",
    transcript: list[dict[str, Any]],
) -> None:
    for raw_line in iter(stream.readline, b""):
        try:
            message = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(message, dict):
            transcript.append(message)
            responses.put(message)


def drain(stream: BinaryIO, chunks: list[bytes]) -> None:
    for chunk in iter(lambda: stream.read(8192), b""):
        chunks.append(chunk)


def send(process: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    if process.stdin is None:
        raise SmokeFailure("MCP stdin is unavailable")
    encoded = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    try:
        process.stdin.write(encoded)
        process.stdin.flush()
    except (BrokenPipeError, OSError) as error:
        raise SmokeFailure("MCP server closed stdin early") from error


def wait_response(
    process: subprocess.Popen[bytes],
    responses: "queue.Queue[dict[str, Any]]",
    request_id: int,
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None and responses.empty():
            raise SmokeFailure(
                f"MCP server exited {process.returncode} before response id={request_id}"
            )
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise queue.Empty
            message = responses.get(timeout=remaining)
        except queue.Empty as error:
            raise SmokeFailure(f"timed out waiting for MCP response id={request_id}") from error
        if message.get("id") != request_id:
            continue
        if "error" in message:
            raise SmokeFailure(
                f"MCP response id={request_id} returned JSON-RPC error: {message['error']!r}"
            )
        result = message.get("result")
        if isinstance(result, dict) and result.get("isError") is True:
            raise SmokeFailure(
                f"MCP tool response id={request_id} reported isError=true"
            )
        return message


def request(
    process: subprocess.Popen[bytes],
    responses: "queue.Queue[dict[str, Any]]",
    request_id: int,
    method: str,
    params: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    send(
        process,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    )
    return wait_response(process, responses, request_id, timeout)


def run_scenario(
    process: subprocess.Popen[bytes],
    responses: "queue.Queue[dict[str, Any]]",
    scenario: str,
    repo_path: str,
    timeout: float,
) -> None:
    request(process, responses, 1, "initialize", INITIALIZE_PARAMS, timeout)
    send(
        process,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )
    request(
        process,
        responses,
        2,
        "tools/call",
        {
            "name": "index_repository",
            "arguments": {"repo_path": repo_path, "mode": "fast"},
        },
        timeout,
    )
    if scenario == "roundtrip":
        request(
            process,
            responses,
            3,
            "tools/call",
            {"name": "search_graph", "arguments": {"name_pattern": "compute"}},
            timeout,
        )
        return
    request(
        process,
        responses,
        3,
        "tools/call",
        {
            "name": "search_code",
            "arguments": {"pattern": "compute", "mode": "compact", "limit": 3},
        },
        timeout,
    )
    request(
        process,
        responses,
        4,
        "tools/call",
        {
            "name": "get_code_snippet",
            "arguments": {"qualified_name": "compute"},
        },
        timeout,
    )


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--scenario", choices=("roundtrip", "advanced"), required=True)
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--response-timeout", type=float, default=30.0)
    parser.add_argument("--exit-timeout", type=float, default=15.0)
    args = parser.parse_args()

    process = subprocess.Popen(
        [args.binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    responses: "queue.Queue[dict[str, Any]]" = queue.Queue()
    transcript: list[dict[str, Any]] = []
    stderr_chunks: list[bytes] = []
    stdout_thread = threading.Thread(
        target=read_json_lines,
        args=(process.stdout, responses, transcript),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr_chunks), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    try:
        run_scenario(
            process,
            responses,
            args.scenario,
            args.repo_path,
            args.response_timeout,
        )
        assert process.stdin is not None
        process.stdin.close()
        try:
            return_code = process.wait(timeout=args.exit_timeout)
        except subprocess.TimeoutExpired as error:
            raise SmokeFailure("MCP server did not exit after interactive stdin EOF") from error
        if return_code != 0:
            raise SmokeFailure(f"MCP server exited nonzero after completed session: {return_code}")
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        for message in transcript:
            print(json.dumps(message, separators=(",", ":"), ensure_ascii=False))
        return 0
    except SmokeFailure as error:
        stop_process(process)
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        print(f"FAIL: {error}", file=sys.stderr)
        if stderr:
            print("--- MCP stderr ---", file=sys.stderr)
            print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
