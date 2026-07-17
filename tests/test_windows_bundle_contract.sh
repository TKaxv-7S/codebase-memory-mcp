#!/usr/bin/env bash
# Static release-surface contract for the Windows permanent launcher.
#
# This intentionally inspects the checked-in packaging sources.  Native
# launcher behavior is covered separately on Windows; this guard makes it hard
# for a release/package edit to silently put the managed launcher where a
# portable wrapper expects the payload (or omit one half of the release pair).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$ROOT" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1])
failures: list[str] = []


def read(relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def yaml_run_blocks(text: str) -> list[str]:
    """Return literal/folded YAML run blocks without requiring PyYAML."""
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*[|>]", lines[index])
        if match is None:
            index += 1
            continue
        base_indent = len(match.group(1))
        block: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= base_indent:
                break
            block.append(line)
            index += 1
        blocks.append("\n".join(block))
    return blocks


launcher = "codebase-memory-mcp.exe"
payload = "codebase-memory-mcp.payload.exe"
windows_archive_names = (
    launcher,
    payload,
    "LICENSE",
    "install.ps1",
    "THIRD_PARTY_NOTICES.md",
)

# Every Windows archive (standard/UI, x64/ARM64) is a five-file bundle containing
# the executable pair plus the three release/legal files. Check the producing run
# block itself so an attestation or comment cannot accidentally satisfy it.
build_workflow = read(".github/workflows/_build.yml")
build_blocks = yaml_run_blocks(build_workflow)
archives = (
    "codebase-memory-mcp-windows-amd64.zip",
    "codebase-memory-mcp-ui-windows-amd64.zip",
    "codebase-memory-mcp-windows-arm64.zip",
    "codebase-memory-mcp-ui-windows-arm64.zip",
)
for archive in archives:
    archive_blocks = [block for block in build_blocks if archive in block]
    require(bool(archive_blocks), f"_build.yml has no run block producing {archive}")
    require(
        any(all(name in block for name in windows_archive_names) for block in archive_blocks),
        f"{archive} must archive the exact official five-file Windows bundle",
    )

# install.ps1 must preserve the complete adjacent pair and enter the native
# process through the downloaded launcher. The launcher owns containment and
# resolves the payload; invoking the payload directly bypasses that boundary.
installer = read("install.ps1")
require(
    "$DownloadedLauncher = Join-Path $TmpDir $BinName" in installer
    and "$DownloadedPayload = Join-Path $TmpDir $PayloadName" in installer
    and "Test-Path -LiteralPath $DownloadedLauncher -PathType Leaf" in installer
    and "Test-Path -LiteralPath $DownloadedPayload -PathType Leaf" in installer,
    "install.ps1 must retain an adjacent downloaded launcher/payload pair",
)
require(
    "& $DownloadedLauncher --version" in installer
    and "& $DownloadedLauncher @InstallArgs" in installer
    and "& $DownloadedPayload @InstallArgs" not in installer,
    "install.ps1 must verify and install through the downloaded launcher",
)

# Package-manager shims are intentionally one-shot portable instances on
# Windows. Their downloaders validate both release executables adjacently in a
# private temporary directory, cache the immutable pair for a later managed
# install transition, and execute the launcher. They must not create or
# interpret managed generation state themselves.
portable_cache_contracts = {
    "pkg/npm/install.js": (
        r"const\s+WINDOWS_PAYLOAD_NAME\s*=\s*['\"]codebase-memory-mcp\.payload\.exe['\"]",
        r"binName\s*=\s*platform\s*===\s*['\"]windows['\"]\s*\?\s*WINDOWS_PAYLOAD_NAME",
    ),
    "pkg/npm/bin.js": (
        r"binName\s*=\s*isWindows\s*\?\s*['\"]codebase-memory-mcp\.payload\.exe['\"]",
    ),
    "pkg/pypi/src/codebase_memory_mcp/_cli.py": (
        r"_WINDOWS_PAYLOAD_NAME\s*=\s*['\"]codebase-memory-mcp\.payload\.exe['\"]",
        r"def\s+_bin_path[\s\S]{0,500}_WINDOWS_PAYLOAD_NAME\s+if\s+sys\.platform\s*==\s*['\"]win32['\"]",
    ),
    "pkg/go/cmd/codebase-memory-mcp/main.go": (
        r"windowsPayloadName\s*=\s*['\"]codebase-memory-mcp\.payload\.exe['\"]",
        r"if\s+runtime\.GOOS\s*==\s*['\"]windows['\"][\s\S]{0,300}name\s*=\s*windowsPayloadName",
    ),
}
for relative, patterns in portable_cache_contracts.items():
    source = read(relative)
    require(
        payload in source
        and all(re.search(pattern, source, re.DOTALL) for pattern in patterns),
        f"{relative} must retain {payload} as the Windows cache readiness path",
    )
    require(
        ".cbm/generations" not in source and "current-v1" not in source,
        f"{relative} must remain portable and not own managed launcher state",
    )

# Portable package shims keep an immutable, exact-version launcher/payload pair.
# The launcher resolves its adjacent payload for every native command.
# Concurrent first-run contenders publish launcher first and payload
# last; payload is therefore the readiness signal. They never pre-delete or
# roll back a destination, and may accept a collision only after proving that
# the winner is byte-identical to the authenticated staged source and runnable.
immutable_pair_cache_contracts = {
    "pkg/npm/install.js": (
        "const cacheNames = platform === 'windows'",
        "const publishNames = platform === 'windows'",
        "filesEqualSha256",
    ),
    "pkg/pypi/src/codebase_memory_mcp/_cli.py": (
        "cache_names = extraction_names",
        "publish_names = (",
        "_files_equal_sha256",
    ),
    "pkg/go/cmd/codebase-memory-mcp/main.go": (
        "installWindowsPairAtomically(tmp, filepath.Dir(dest))",
        "filesEqualSHA256",
    ),
}
for relative, needles in immutable_pair_cache_contracts.items():
    source = read(relative)
    require(
        all(needle in source for needle in needles),
        f"{relative} must publish an immutable exact-version Windows pair with {payload} last",
    )
    require(
        "publishedPaths" not in source
        and "published_paths" not in source
        and "const published = []" not in source,
        f"{relative} must not roll back published destinations by pathname",
    )

npm_installer = read("pkg/npm/install.js")
require(
    re.search(
        r"const publishNames = platform === 'windows'\s*\?\s*"
        r"\[WINDOWS_LAUNCHER_NAME, WINDOWS_PAYLOAD_NAME\]",
        npm_installer,
    ) is not None
    and "filesEqualSha256(stagedPaths.get(name), destination)" in npm_installer
    and "fs.unlinkSync(destination)" not in npm_installer,
    "npm must publish launcher then payload and only accept an identical collision",
)
python_wrapper = read("pkg/pypi/src/codebase_memory_mcp/_cli.py")
require(
    re.search(
        r"publish_names = \(\s*\(_WINDOWS_LAUNCHER_NAME, "
        r"_WINDOWS_PAYLOAD_NAME\)",
        python_wrapper,
    ) is not None
    and "_files_equal_sha256(staged_paths[name], target)" in python_wrapper,
    "PyPI must publish launcher then payload and only accept an identical collision",
)
go_wrapper = read("pkg/go/cmd/codebase-memory-mcp/main.go")
require(
    "names := []string{windowsLauncherName, windowsPayloadName}" in go_wrapper
    and "filesEqualSHA256(staged[name], target)" in go_wrapper
    and "os.Remove(target)" not in go_wrapper,
    "Go must publish launcher then payload and only accept an identical collision",
)

npm_shim = read("pkg/npm/bin.js")
require(
    "launcherPath" in npm_shim
    and "windowsLauncherName" in npm_shim
    and "fs.existsSync(launcherPath)" in npm_shim,
    "pkg/npm/bin.js readiness must require the adjacent launcher/payload pair",
)
require(
    "const executionPath = isWindows ? launcherPath : binPath" in npm_shim
    and "spawnSync(executionPath, process.argv.slice(2)" in npm_shim
    and "spawnSync(binPath, process.argv.slice(2)" not in npm_shim,
    "npm must execute Windows commands through the adjacent launcher",
)
require(
    "verifyCandidate(extractedPaths.get(WINDOWS_LAUNCHER_NAME))" in npm_installer
    and "verifyCandidate(path.join(BIN_DIR, WINDOWS_LAUNCHER_NAME))" in npm_installer,
    "npm must validate extracted and cached Windows pairs through the launcher",
)
require(
    "_windows_pair_ready" in python_wrapper,
    "PyPI readiness must require and validate the adjacent launcher/payload pair",
)
require(
    "return payload.with_name(_WINDOWS_LAUNCHER_NAME)" in python_wrapper
    and "execution_path = _execution_path(bin_path, sys.platform)" in python_wrapper
    and "args = [str(execution_path)] + sys.argv[1:]" in python_wrapper
    and "result = subprocess.run(args)" in python_wrapper
    and "args = [str(bin_path)] + sys.argv[1:]" not in python_wrapper,
    "PyPI must execute Windows commands through the adjacent launcher",
)
require(
    "windowsLauncherPath" in go_wrapper
    and "installWindowsPairAtomically" in go_wrapper,
    "Go readiness must require and validate the adjacent launcher/payload pair",
)
require(
    "return filepath.Join(filepath.Dir(payload), windowsLauncherName)" in go_wrapper
    and "return executionPathForOS(payload, runtime.GOOS), nil" in go_wrapper
    and "execBinary(executable, os.Args[1:])" in go_wrapper,
    "Go must execute Windows commands through the adjacent launcher",
)

# All package downloaders parse the Windows archive against the exact official
# five-root-file allowlist. Portable wrappers privately validate the executable
# pair and cache that pair immutably; they may not silently ignore an
# attacker-controlled sixth member.
exact_archive_guards = {
    "install.ps1": (
        "$seen.Count -ne $WindowsArchiveNames.Count",
        '"LICENSE"',
        '"install.ps1"',
        "THIRD_PARTY_NOTICES.md",
    ),
    "pkg/npm/install.js": (
        "$seen.Count -ne $requiredNames.Count",
        "WINDOWS_LAUNCHER_NAME",
        "WINDOWS_PAYLOAD_NAME",
        "'LICENSE'",
        "'install.ps1'",
        "THIRD_PARTY_NOTICES.md",
    ),
    "pkg/pypi/src/codebase_memory_mcp/_cli.py": (
        "name not in required_set",
        "len(seen) != len(required)",
        "_WINDOWS_LAUNCHER_NAME",
        "_WINDOWS_PAYLOAD_NAME",
        '"LICENSE"',
        '"install.ps1"',
        "THIRD_PARTY_NOTICES.md",
    ),
    "pkg/go/cmd/codebase-memory-mcp/main.go": (
        "len(seen) != len(archiveNames)",
        "windowsLauncherName",
        "windowsPayloadName",
        '"LICENSE"',
        '"install.ps1"',
        "THIRD_PARTY_NOTICES.md",
    ),
}
for relative, needles in exact_archive_guards.items():
    source = read(relative)
    require(
        all(needle in source for needle in needles),
        f"{relative} must reject every Windows zip namespace except the official five-file allowlist",
    )

# A portable mutation refusal must point to the owning package manager and to
# the explicit one-time transition into managed mode.
guidance_contracts = {
    "pkg/npm/bin.js": (
        "npm install codebase-memory-mcp@latest",
        "npm uninstall codebase-memory-mcp",
        "codebase-memory-mcp install --yes",
    ),
    "pkg/pypi/src/codebase_memory_mcp/_cli.py": (
        "python -m pip install --upgrade codebase-memory-mcp",
        "python -m pip uninstall codebase-memory-mcp",
        "install --yes",
    ),
    "pkg/go/cmd/codebase-memory-mcp/main.go": (
        "go install github.com/DeusData/codebase-memory-mcp/pkg/go/cmd/codebase-memory-mcp@latest",
        "Remove-Item (Get-Command codebase-memory-mcp).Source",
        "codebase-memory-mcp install --yes",
    ),
}
for relative, needles in guidance_contracts.items():
    source = read(relative)
    require(
        all(needle in source for needle in needles),
        f"{relative} must provide actionable package and managed-install guidance",
    )

# Native Windows regression coverage moves from the transient activation helper
# to the permanent launcher suite.
windows_test_driver = read("scripts/test-windows.ps1")
require(
    "tests\\windows\\test_windows_launcher.py" in windows_test_driver
    or "tests/windows/test_windows_launcher.py" in windows_test_driver,
    "scripts/test-windows.ps1 must run tests/windows/test_windows_launcher.py",
)
require(
    "test_cli_activation_helper.py" not in windows_test_driver,
    "scripts/test-windows.ps1 must not run the legacy transient activation-helper test",
)

# Launcher supervision has two distinct failure directions: killing the
# launcher must kill its payload job, and killing only the launcher's immediate
# parent must terminate the launcher plus every descendant. Require the native
# test to invoke both probes, not merely define helpers that never run.
windows_launcher_test = read("tests/windows/test_windows_launcher.py")
require(
    windows_launcher_test.count("assert_launcher_death_contains_payload(") >= 2
    and "server.proc.kill()" in windows_launcher_test
    and "wait_for_process_exit(child_pid" in windows_launcher_test,
    "native Windows coverage must kill the launcher and reject an orphaned payload",
)
require(
    windows_launcher_test.count(
        "assert_immediate_parent_death_contains_launcher_tree("
    ) >= 2
    and '"--launcher-parent-probe"' in windows_launcher_test
    and "wrapper.kill()" in windows_launcher_test
    and "wait_for_process_exit(launcher_pid" in windows_launcher_test,
    "native Windows coverage must kill the immediate parent and reject a surviving launcher tree",
)

launcher_source = read("src/launcher/windows_launcher.c")
require(
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in launcher_source
    and "PROC_THREAD_ATTRIBUTE_JOB_LIST" in launcher_source
    and "launcher_parent_liveness_open" in launcher_source
    and "WaitForMultipleObjects" in launcher_source
    and "TerminateJobObject" in launcher_source,
    "the permanent launcher must contain payloads and supervise immediate-parent death",
)

# The build system exposes a distinct launcher artifact; release jobs later copy
# that small binary to the canonical public name.
makefile = read("Makefile.cbm")
launcher_target = re.search(
    r"(?m)^\s*[^#\n]*codebase-memory-mcp-launcher(?:\.exe|\$\([A-Za-z0-9_]+\))?\s*:",
    makefile,
)
require(
    launcher_target is not None,
    "Makefile.cbm must expose a codebase-memory-mcp-launcher executable target",
)

# Every native path-tree trust boundary must validate opened ancestor handles,
# reject reparse points, inspect mutation-capable allow ACEs, and recognize the
# bounded privileged-principal set (current user, SYSTEM, Administrators, and
# the fixed TrustedInstaller service SID).  The native test injects a real
# Everyone-modify ACE; these static markers keep all three independently linked
# implementations aligned even on non-Windows presubmit hosts.
ancestor_security_contracts = {
    "src/daemon/ipc.c": (
        "win_directory_component_secure",
        "win_file_security_secure(security, directory, false)",
        "ACCESS_SYSTEM_SECURITY",
        "956008885U",
        "FILE_ATTRIBUTE_REPARSE_POINT",
    ),
    "src/cli/windows_launcher_state.c": (
        "windows_owner_secure(component, false)",
        "windows_acl_secure(component)",
        "ACCESS_SYSTEM_SECURITY",
        "956008885U",
        "FILE_FLAG_OPEN_REPARSE_POINT",
    ),
    "src/launcher/windows_launcher.c": (
        "launcher_security_is_safe(component, false)",
        "ACCESS_SYSTEM_SECURITY",
        "956008885U",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "PIPE_REJECT_REMOTE_CLIENTS",
    ),
}
for relative, needles in ancestor_security_contracts.items():
    source = read(relative)
    require(
        all(needle in source for needle in needles),
        f"{relative} must enforce the shared cross-account ancestor trust policy",
    )

# Release smoke must run the canonical launcher while preserving the payload it
# resolves.  Requiring both names in the Windows smoke job prevents a test from
# accidentally continuing to exercise a renamed monolithic payload.
smoke_workflow = read(".github/workflows/_smoke.yml")
windows_match = re.search(
    r"(?ms)^  smoke-windows:\s*(.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
    smoke_workflow,
)
windows_smoke = windows_match.group(1) if windows_match else ""
require(bool(windows_smoke), "_smoke.yml must contain the smoke-windows job")
require(
    re.search(
        r"scripts/smoke-test\.sh\s+(?:\"|')?\./codebase-memory-mcp\.exe(?:\"|')?",
        windows_smoke,
    ) is not None,
    f"Windows release smoke must execute the canonical {launcher}",
)
require(
    launcher in windows_smoke and payload in windows_smoke,
    f"Windows release smoke must retain both {launcher} and {payload}",
)
smoke_blocks = yaml_run_blocks(windows_smoke)
require(
    any("zip" in block and launcher in block and payload in block for block in smoke_blocks),
    "Windows artifact-server smoke archive must contain launcher and payload",
)

# Native update transport remains HTTPS-only in production. Release smoke may
# use an explicit file:// CBM_DOWNLOAD_URL only for its local fixture, while the
# installer and raw-curl phases continue to exercise the loopback HTTP server.
smoke_script = read("scripts/smoke-test.sh")
require(
    'SMOKE_UPDATE_FIXTURE_DIR' in smoke_script
    and 'UPDATE_DOWNLOAD_URL="file://$UPDATE_FIXTURE_DIR"' in smoke_script
    and 'UPDATE_DOWNLOAD_URL="file:///$UPDATE_FIXTURE_DIR"' in smoke_script
    and 'CBM_DOWNLOAD_URL="$UPDATE_DOWNLOAD_URL"' in smoke_script,
    "Phase 14 native update must use an explicit file:// fixture override",
)
require(
    'CBM_DOWNLOAD_URL="$SMOKE_DOWNLOAD_URL"' in smoke_script
    and '"$SMOKE_DOWNLOAD_URL/$DL_ARCHIVE"' in smoke_script,
    "installer and raw download smoke phases must retain loopback HTTP coverage",
)
require(
    smoke_workflow.count("SMOKE_UPDATE_FIXTURE_DIR: /tmp/smoke-server") == 2,
    "Unix and Windows release smoke must identify their local update fixture",
)

cli_source = read("src/cli/cli.c")
file_override_match = re.search(
    r"static bool cli_download_is_explicit_file_override\(.*?\n}\n",
    cli_source,
    re.DOTALL,
)
protocol_match = re.search(
    r"static const char \*cli_download_protocol\(.*?\n}\n",
    cli_source,
    re.DOTALL,
)
file_override = file_override_match.group(0) if file_override_match else ""
protocol = protocol_match.group(0) if protocol_match else ""
require(
    'cbm_safe_getenv(\n        "CBM_DOWNLOAD_URL"' in file_override
    and 'strncmp(override, "file://", 7)' in file_override
    and "strncmp(url, override, override_length)" in file_override,
    "file:// downloads must remain restricted to the explicit test override",
)
require(
    'strncmp(url, "https://", 8)' in protocol
    and 'return "=https"' in protocol
    and "cli_download_is_explicit_file_override(url)" in protocol
    and 'return "=file"' in protocol
    and '"http://"' not in protocol,
    "production native downloads must remain HTTPS-only",
)
download_helpers = cli_source[
    cli_source.find("static int cbm_download_to_file("):
    cli_source.find("/* ── macOS ad-hoc signing")
]
require(
    download_helpers.count('"--proto"') >= 2
    and download_helpers.count('"--proto-redir"') >= 2,
    "native curl invocations must pin both initial and redirected protocols",
)

# PR smoke builds artifacts in-place rather than downloading a release archive.
# It must therefore stage the build payload and permanent launcher under their
# release names in a disposable directory, then exercise the canonical launcher.
pr_workflow = read(".github/workflows/pr.yml")
pr_smoke_match = re.search(
    r"(?ms)^  pr-smoke:\s*(.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
    pr_workflow,
)
pr_smoke = pr_smoke_match.group(1) if pr_smoke_match else ""
require(bool(pr_smoke), "pr.yml must contain the pr-smoke job")
pr_windows_blocks = [
    block
    for block in yaml_run_blocks(pr_smoke)
    if "scripts/build.sh CC=clang CXX=clang++" in block
]
require(
    len(pr_windows_blocks) == 1,
    "PR smoke must contain exactly one Windows production build run block",
)
if pr_windows_blocks:
    pr_windows_block = re.sub(r"\\\s*\n\s*", " ", pr_windows_blocks[0])
    pr_windows_block = re.sub(r"\s+", " ", pr_windows_block).strip()
    staging_steps = (
        'SMOKE_DIR="$(mktemp -d)"',
        'trap \'rm -rf "$SMOKE_DIR"\' EXIT',
        'cp build/c/codebase-memory-mcp-launcher.exe '
        '"$SMOKE_DIR/codebase-memory-mcp.exe"',
        'cp build/c/codebase-memory-mcp.exe '
        '"$SMOKE_DIR/codebase-memory-mcp.payload.exe"',
        'scripts/smoke-test.sh "$SMOKE_DIR/codebase-memory-mcp.exe"',
    )
    positions = [pr_windows_block.find(step) for step in staging_steps]
    require(
        all(position >= 0 for position in positions),
        "Windows PR smoke must stage launcher and payload under release names "
        "and invoke the canonical launcher",
    )
    require(
        all(left < right for left, right in zip(positions, positions[1:])),
        "Windows PR smoke must create the temporary bundle before invoking it",
    )
    require(
        pr_windows_block.count("scripts/smoke-test.sh") == 1,
        "Windows PR smoke must invoke smoke-test exactly once through the launcher",
    )

if failures:
    print("Windows launcher bundle contract FAILED:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("Windows launcher bundle contract passed")
PY
