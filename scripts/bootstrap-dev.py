#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Dev Environment Bootstrap Script
=========================================
Sets up a complete development environment on Ubuntu (22.04 / 24.04).
Designed for WSL2 but works on native Linux too.

Usage:
    python3 scripts/bootstrap-dev.py          # Install everything
    python3 scripts/bootstrap-dev.py --check  # Just verify, don't install

Requirements: Python 3.10+ (ships with Ubuntu 22.04+)
"""

import subprocess
import sys
import os
import shutil
import argparse
import json
from pathlib import Path
from dataclasses import dataclass

# ─── Configuration ───────────────────────────────────────────────────────────

GO_VERSION = "1.23.6"
NODE_VERSION = "20"
BUF_VERSION = "1.47.2"
CLANG_MIN_VERSION = 15
PYTHON_MIN_VERSION = (3, 12)

APT_PACKAGES = [
    # eBPF / kernel development
    "clang",
    "llvm",
    "libelf-dev",
    "libbpf-dev",
    "linux-tools-common",
    # Build essentials
    "build-essential",
    "pkg-config",
    "protobuf-compiler",
    # Utilities
    "curl",
    "wget",
    "unzip",
    "git",
    "jq",
    # Python
    "python3-pip",
    "python3-venv",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def log(msg: str, color: str = CYAN):
    print(f"{color}{BOLD}>>> {msg}{RESET}")

def ok(msg: str):
    print(f"  {GREEN}✓ {msg}{RESET}")

def warn(msg: str):
    print(f"  {YELLOW}⚠ {msg}{RESET}")

def fail(msg: str):
    print(f"  {RED}✗ {msg}{RESET}")

def run(cmd: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command."""
    return subprocess.run(
        cmd, shell=True, check=check,
        capture_output=capture, text=True
    )

def cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None

def get_version(cmd: str) -> str:
    """Run a command and return its stdout (first line)."""
    try:
        r = run(cmd, check=False, capture=True)
        return r.stdout.strip().split("\n")[0] if r.returncode == 0 else ""
    except Exception:
        return ""

# ─── Check Functions ─────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    installed: bool
    version: str
    required: str
    note: str = ""

def check_all() -> list[CheckResult]:
    """Check all dev tools and return results."""
    results = []

    # Python
    py_ver = sys.version.split()[0]
    py_ok = sys.version_info >= PYTHON_MIN_VERSION
    results.append(CheckResult("Python", py_ok, py_ver, f">= {PYTHON_MIN_VERSION[0]}.{PYTHON_MIN_VERSION[1]}"))

    # clang
    clang_ver = get_version("clang --version")
    clang_num = 0
    if clang_ver:
        try:
            # e.g., "Ubuntu clang version 18.1.3 ..."
            parts = clang_ver.split("version")
            if len(parts) > 1:
                clang_num = int(parts[1].strip().split(".")[0])
        except (ValueError, IndexError):
            pass
    results.append(CheckResult("clang", clang_num >= CLANG_MIN_VERSION, clang_ver[:60] if clang_ver else "not found", f">= {CLANG_MIN_VERSION}"))

    # llvm (llc)
    llc_ver = get_version("llc --version")
    llc_ok = "LLVM" in llc_ver if llc_ver else False
    results.append(CheckResult("LLVM (llc)", llc_ok, llc_ver[:60] if llc_ver else "not found", "any"))

    # Go
    go_ver = get_version("go version")
    go_ok = "go1." in go_ver if go_ver else False
    results.append(CheckResult("Go", go_ok, go_ver if go_ver else "not found", f">= {GO_VERSION}"))

    # Node
    node_ver = get_version("node --version")
    node_ok = node_ver.startswith("v2") if node_ver else False  # v20+
    results.append(CheckResult("Node.js", node_ok, node_ver if node_ver else "not found", f">= {NODE_VERSION}"))

    # npm
    npm_ver = get_version("npm --version")
    results.append(CheckResult("npm", bool(npm_ver), npm_ver if npm_ver else "not found", "any"))

    # Docker
    docker_ver = get_version("docker --version")
    results.append(CheckResult("Docker", bool(docker_ver), docker_ver if docker_ver else "not found", "any",
                               note="Via Docker Desktop WSL integration"))

    # Docker Compose
    compose_ver = get_version("docker compose version")
    results.append(CheckResult("Docker Compose", bool(compose_ver), compose_ver if compose_ver else "not found", "any"))

    # buf
    buf_ver = get_version("buf --version")
    results.append(CheckResult("buf", bool(buf_ver), buf_ver if buf_ver else "not found", f">= {BUF_VERSION}"))

    # protoc
    protoc_ver = get_version("protoc --version")
    results.append(CheckResult("protoc", bool(protoc_ver), protoc_ver if protoc_ver else "not found", "any"))

    # Git
    git_ver = get_version("git --version")
    results.append(CheckResult("Git", bool(git_ver), git_ver if git_ver else "not found", "any"))

    # libbpf headers
    libbpf_ok = Path("/usr/include/bpf/bpf.h").exists()
    results.append(CheckResult("libbpf-dev", libbpf_ok, "headers present" if libbpf_ok else "not found", "any"))

    # libelf headers
    libelf_ok = Path("/usr/include/libelf.h").exists() or Path("/usr/include/gelf.h").exists()
    results.append(CheckResult("libelf-dev", libelf_ok, "headers present" if libelf_ok else "not found", "any"))

    # BTF support (kernel)
    btf_ok = Path("/sys/kernel/btf/vmlinux").exists()
    results.append(CheckResult("Kernel BTF", btf_ok, "enabled" if btf_ok else "not available", "required for CO-RE"))

    return results

def print_report(results: list[CheckResult]):
    """Print a formatted status report."""
    print()
    log("Phantex Dev Environment Status", BOLD)
    print(f"  {'Tool':<20} {'Status':<10} {'Version':<45} {'Required'}")
    print(f"  {'─'*20} {'─'*10} {'─'*45} {'─'*20}")
    for r in results:
        status = f"{GREEN}OK{RESET}" if r.installed else f"{RED}MISSING{RESET}"
        note = f"  ({r.note})" if r.note else ""
        print(f"  {r.name:<20} {status:<19} {r.version:<45} {r.required}{note}")
    print()

    missing = [r for r in results if not r.installed]
    if missing:
        warn(f"{len(missing)} tool(s) need attention: {', '.join(r.name for r in missing)}")
    else:
        ok("All tools installed and verified!")
    print()

# ─── Install Functions ───────────────────────────────────────────────────────

def install_apt_packages():
    """Install system packages via apt."""
    log("Installing system packages via apt...")
    run("sudo apt update")
    pkg_list = " ".join(APT_PACKAGES)
    run(f"sudo apt install -y {pkg_list}")
    ok("System packages installed")

def install_go():
    """Install Go from official tarball."""
    go_ver = get_version("go version")
    if go_ver and GO_VERSION in go_ver:
        ok(f"Go already installed: {go_ver}")
        return

    log(f"Installing Go {GO_VERSION}...")
    tarball = f"go{GO_VERSION}.linux-amd64.tar.gz"
    run(f"wget -q https://go.dev/dl/{tarball} -O /tmp/{tarball}")
    run(f"sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/{tarball}")
    run(f"rm /tmp/{tarball}")

    # Add to PATH in .bashrc if not already there
    bashrc = Path.home() / ".bashrc"
    go_path_line = 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
    if bashrc.exists():
        content = bashrc.read_text()
        if "/usr/local/go/bin" not in content:
            with open(bashrc, "a") as f:
                f.write(f"\n# Go (added by phantex bootstrap)\n{go_path_line}\n")

    # Make available in current session
    os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('GOPATH', str(Path.home() / 'go'))}/bin:{os.environ['PATH']}"

    ver = get_version("go version")
    ok(f"Go installed: {ver}")

def install_node():
    """Install Node.js via nvm."""
    # Check if nvm is already installed
    nvm_dir = Path.home() / ".nvm"
    if not nvm_dir.exists():
        log(f"Installing nvm (Node Version Manager)...")
        run("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash")

    log(f"Installing Node.js {NODE_VERSION} via nvm...")
    # nvm is a bash function, so we need to source it
    nvm_script = f"""
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
    nvm install {NODE_VERSION}
    nvm use {NODE_VERSION}
    nvm alias default {NODE_VERSION}
    """
    run(f"bash -c '{nvm_script}'")

    # Add nvm to .bashrc if not already there (install script usually does this)
    bashrc = Path.home() / ".bashrc"
    if bashrc.exists():
        content = bashrc.read_text()
        if "NVM_DIR" not in content:
            with open(bashrc, "a") as f:
                f.write('\n# nvm (added by phantex bootstrap)\n')
                f.write('export NVM_DIR="$HOME/.nvm"\n')
                f.write('[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"\n')
                f.write('[ -s "$NVM_DIR/bash_completion" ] && \\. "$NVM_DIR/bash_completion"\n')

    # Make node available in current session
    nvm_node = list((nvm_dir / "versions" / "node").glob(f"v{NODE_VERSION}*"))
    if nvm_node:
        node_bin = nvm_node[0] / "bin"
        os.environ["PATH"] = f"{node_bin}:{os.environ['PATH']}"

    ver = get_version("node --version")
    ok(f"Node.js installed: {ver}")

def install_buf():
    """Install buf (Protobuf tooling)."""
    buf_ver = get_version("buf --version")
    if buf_ver and BUF_VERSION in buf_ver:
        ok(f"buf already installed: {buf_ver}")
        return

    log(f"Installing buf {BUF_VERSION}...")
    run(f"curl -sSL https://github.com/bufbuild/buf/releases/download/v{BUF_VERSION}/buf-Linux-x86_64 -o /tmp/buf")
    run("sudo mv /tmp/buf /usr/local/bin/buf")
    run("sudo chmod +x /usr/local/bin/buf")

    ver = get_version("buf --version")
    ok(f"buf installed: {ver}")

def install_python_tools():
    """Install Python dev tools (poetry, ruff, pip-audit)."""
    log("Installing Python dev tools...")
    run("pip3 install --user --break-system-packages pipx 2>/dev/null || pip3 install --user pipx", check=False)

    # Ensure pipx bin is in PATH
    pipx_bin = Path.home() / ".local" / "bin"
    if str(pipx_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{pipx_bin}:{os.environ['PATH']}"

    # Install via pipx for isolation
    for tool in ["poetry", "ruff"]:
        if not cmd_exists(tool):
            run(f"python3 -m pipx install {tool}", check=False)

    # pip-audit via pip (it's a scanner, not a long-running tool)
    run("pip3 install --user --break-system-packages pip-audit 2>/dev/null || pip3 install --user pip-audit", check=False)

    ok("Python dev tools installed (poetry, ruff, pip-audit)")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Phantex Dev Environment Bootstrap")
    parser.add_argument("--check", action="store_true", help="Only check tools, don't install")
    parser.add_argument("--skip-apt", action="store_true", help="Skip apt package installation")
    args = parser.parse_args()

    print()
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║   Phantex Dev Environment Bootstrap      ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{RESET}")
    print()

    if args.check:
        results = check_all()
        print_report(results)
        missing = [r for r in results if not r.installed]
        sys.exit(1 if missing else 0)

    # Check we're on Linux
    if sys.platform != "linux":
        fail("This script must be run on Linux (WSL2 or native).")
        fail("Run it inside WSL2: wsl -d Ubuntu-24.04 -- python3 scripts/bootstrap-dev.py")
        sys.exit(1)

    # Check we have sudo
    if os.geteuid() != 0 and not cmd_exists("sudo"):
        fail("sudo is required. Run as root or install sudo.")
        sys.exit(1)

    # Install everything
    try:
        if not args.skip_apt:
            install_apt_packages()

        install_go()
        install_node()
        install_buf()
        install_python_tools()

    except subprocess.CalledProcessError as e:
        fail(f"Command failed: {e.cmd}")
        fail(f"Return code: {e.returncode}")
        sys.exit(1)

    # Final verification
    print()
    log("Running final verification...", BOLD)
    results = check_all()
    print_report(results)

    missing = [r for r in results if not r.installed]
    if missing:
        warn("Some tools may need a shell restart to appear in PATH.")
        warn("Run: source ~/.bashrc  (or open a new terminal)")
        warn(f"Then re-check: python3 {__file__} --check")
    else:
        ok("Environment is ready! You can start building Phantex.")

    print(f"  {CYAN}Next step: Initialize the Git repo and start Block A1.{RESET}")
    print()

if __name__ == "__main__":
    main()
