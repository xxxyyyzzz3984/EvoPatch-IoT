#!/usr/bin/env python3
"""Collect Raspberry Pi BusyBox build outputs and logs."""

from __future__ import annotations

import argparse
import getpass
import os
import posixpath
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

import paramiko

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_BASE = "/home/xyh3984/busybox-build-work"
DEFAULT_LOCAL_OUT = PROJECT_ROOT / "raspi_build_results"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.1.103")
    parser.add_argument("--user", default="xyh3984")
    parser.add_argument("--password-env", default="PI_SSH_PASSWORD")
    parser.add_argument("--remote-base", default=DEFAULT_REMOTE_BASE)
    parser.add_argument("--local-out", type=Path, default=DEFAULT_LOCAL_OUT)
    parser.add_argument("--clean-downloaded", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    return parser.parse_args(argv)


def connect(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20)
    return client


def run(client: paramiko.SSHClient, cmd: str) -> str:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    stdout.channel.recv_exit_status()
    return out + ("\nERR:\n" + err if err.strip() else "")


def exists(sftp: paramiko.SFTPClient, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except IOError:
        return False


def download_tree(sftp: paramiko.SFTPClient, remote_path: str, local_path: Path) -> int:
    try:
        attrs = sftp.stat(remote_path)
    except IOError:
        return 0
    count = 0
    if stat.S_ISDIR(attrs.st_mode):
        local_path.mkdir(parents=True, exist_ok=True)
        for item in sftp.listdir_attr(remote_path):
            count += download_tree(sftp, posixpath.join(remote_path, item.filename), local_path / item.filename)
    else:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote_path, str(local_path))
        count += 1
    return count


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    password = os.environ.get(args.password_env) or getpass.getpass(f"SSH password for {args.user}@{args.host}: ")
    args.local_out.mkdir(parents=True, exist_ok=True)
    client = connect(args.host, args.user, password)
    sftp = client.open_sftp()
    try:
        base = args.remote_base
        status_cmd = f"""
echo '## process'; pgrep -af run_target57_background.sh || true
echo '## disk'; df -h {base}
echo '## master tail'; tail -40 {base}/logs/batch_target57_master.log 2>/dev/null || true
echo '## remote out summary'; find {base}/out -maxdepth 2 -type f 2>/dev/null | sed 's|{base}/out/||' | sort | tail -50
echo '## status summary'; find {base}/logs -name '*.status' -type f 2>/dev/null | xargs -r grep -H . | sed 's|{base}/logs/||' | sort | tail -80
"""
        print(run(client, status_cmd))
        if args.status_only:
            return 0
        files = 0
        files += download_tree(sftp, posixpath.join(base, "out"), args.local_out)
        files += download_tree(sftp, posixpath.join(base, "logs"), args.local_out / "logs")
        print(f"downloaded_files={files}")
        if args.clean_downloaded:
            print("clean-downloaded is intentionally conservative; remote cleanup should be done after verifying local manifest.")
    finally:
        sftp.close()
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
