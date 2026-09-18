#!/usr/bin/env python3
"""Orchestrate BusyBox multi-arch builds on a Raspberry Pi over SSH.

The script uploads a small remote builder, runs one version at a time, downloads
stripped binaries and logs back to the local project, and cleans remote build
artifacts to save Raspberry Pi disk space.
"""

from __future__ import annotations

import argparse
import getpass
import os
import posixpath
import stat
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import paramiko

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCAL_OUT = PROJECT_ROOT / "raspi_build_results"
DEFAULT_REMOTE_BASE = "/home/xyh3984/busybox-build-work"
DATASET_DIR = PROJECT_ROOT / "busybox_unstripped_dataset"
SOURCES_DIR = PROJECT_ROOT / "busybox_sources_codes"

REMOTE_BUILDER = r'''#!/usr/bin/env bash
set -u
BASE="$1"
VERSION="$2"
JOBS="$3"
shift 3
ARCHES=("$@")
SRC_ROOT="$BASE/sources/busybox_sources_codes"
BUILD_ROOT="$BASE/build"
OUT_ROOT="$BASE/out"
LOG_ROOT="$BASE/logs"
mkdir -p "$BUILD_ROOT" "$OUT_ROOT/$VERSION" "$LOG_ROOT/$VERSION"

arch_cross() {
  case "$1" in
    aarch64) echo "arm64 aarch64-linux-gnu- aarch64-linux-gnu-strip" ;;
    arm) echo "arm arm-linux-gnueabi- arm-linux-gnueabi-strip" ;;
    armhf) echo "arm arm-linux-gnueabihf- arm-linux-gnueabihf-strip" ;;
    mips) echo "mips mips-linux-gnu- mips-linux-gnu-strip" ;;
    mipsel) echo "mips mipsel-linux-gnu- mipsel-linux-gnu-strip" ;;
    x86_64) echo "x86_64 x86_64-linux-gnu- x86_64-linux-gnu-strip" ;;
    *) return 1 ;;
  esac
}

set_config_n() {
  key="$1"
  if [ -f .config ]; then
    if grep -q "^${key}=" .config; then
      sed -i "s/^${key}=.*/# ${key} is not set/" .config
    elif ! grep -q "^# ${key} is not set" .config; then
      echo "# ${key} is not set" >> .config
    fi
  fi
}

set_config_y() {
  key="$1"
  if [ -f .config ]; then
    if grep -q "^# ${key} is not set" .config; then
      sed -i "s/^# ${key} is not set/${key}=y/" .config
    elif grep -q "^${key}=" .config; then
      sed -i "s/^${key}=.*/${key}=y/" .config
    else
      echo "${key}=y" >> .config
    fi
  fi
}

patch_config() {
  set_config_n CONFIG_STATIC
  set_config_n CONFIG_WERROR
  set_config_n CONFIG_PIE
  set_config_n CONFIG_BUILD_LIBBUSYBOX
  set_config_n CONFIG_SHA1_HWACCEL
  set_config_n CONFIG_SHA256_HWACCEL
  set_config_n CONFIG_SELINUX
  set_config_n CONFIG_PAM
  set_config_n CONFIG_TC
  set_config_n CONFIG_INOTIFYD
  set_config_n CONFIG_FEATURE_IP_TUNNEL
  set_config_n CONFIG_IPTUNNEL
  set_config_n CONFIG_FEATURE_INETD_RPC
  set_config_n CONFIG_DNSD
  set_config_n CONFIG_MOUNT
  set_config_n CONFIG_UMOUNT
  set_config_n CONFIG_FEATURE_MOUNT_NFS
  set_config_n CONFIG_FEATURE_HAVE_RPC
  set_config_n CONFIG_FLASH_ERASEALL
  set_config_n CONFIG_FEATURE_2_4_MODULES
  set_config_n CONFIG_FEATURE_QUERY_MODULE_INTERFACE
  set_config_y CONFIG_FEATURE_2_6_MODULES
  set_config_n CONFIG_MONOTONIC_SYSCALL
  set_config_n CONFIG_DMALLOC
  set_config_n CONFIG_EFENCE
  set_config_y CONFIG_INSTALL_NO_USR
}

patch_legacy_makefile() {
  if [ ! -f Makefile ]; then
    return 0
  fi
  python3 - <<'PY'
from pathlib import Path

path = Path("Makefile")
text = path.read_text()
orig = text

text = text.replace(
    "config %config: scripts_basic outputmakefile FORCE\n"
    "\t$(Q)mkdir -p include\n"
    "\t$(Q)$(MAKE) $(build)=scripts/kconfig $@\n"
    "\t$(Q)$(MAKE) -C $(srctree) KBUILD_SRC= .kernelrelease\n",
    "config: scripts_basic outputmakefile FORCE\n"
    "\t$(Q)mkdir -p include\n"
    "\t$(Q)$(MAKE) $(build)=scripts/kconfig $@\n"
    "\t$(Q)$(MAKE) -C $(srctree) KBUILD_SRC= .kernelrelease\n"
    "%config: scripts_basic outputmakefile FORCE\n"
    "\t$(Q)mkdir -p include\n"
    "\t$(Q)$(MAKE) $(build)=scripts/kconfig $@\n"
    "\t$(Q)$(MAKE) -C $(srctree) KBUILD_SRC= .kernelrelease\n",
)

text = text.replace(
    "/ %/: prepare scripts FORCE\n"
    "\t$(Q)$(MAKE) KBUILD_MODULES=$(if $(CONFIG_MODULES),1) \\\n"
    "\t$(build)=$(build-dir)\n",
    "%/: prepare scripts FORCE\n"
    "\t$(Q)$(MAKE) KBUILD_MODULES=$(if $(CONFIG_MODULES),1) \\\n"
    "\t$(build)=$(build-dir)\n"
    "/: prepare scripts FORCE\n"
    "\t$(Q)$(MAKE) KBUILD_MODULES=$(if $(CONFIG_MODULES),1) \\\n"
    "\t$(build)=$(build-dir)\n",
)

if text != orig:
    path.write_text(text)
    print("patched legacy GNU make rules")
PY
}

patch_legacy_sources() {
  python3 - <<'PY'
from pathlib import Path

patches = []

compat_h = Path("compat_busybox_build.h")
compat_h.write_text(
    "#ifndef COMPAT_BUSYBOX_BUILD_H\n"
    "#define COMPAT_BUSYBOX_BUILD_H\n"
    "#ifndef __ASSEMBLER__\n"
    "#include <sys/resource.h>\n"
    "#include <sys/sysmacros.h>\n"
    "#include <sys/time.h>\n"
    "#include <time.h>\n"
    "static inline int busybox_compat_stime(const time_t *t) {\n"
    "    struct timeval tv;\n"
    "    tv.tv_sec = *t;\n"
    "    tv.tv_usec = 0;\n"
    "    return settimeofday(&tv, 0);\n"
    "}\n"
    "#define stime busybox_compat_stime\n"
    "#endif\n"
    "#endif\n"
)
patches.append("compat-header")

mount_c = Path("util-linux/mount.c")
if mount_c.exists():
    text = mount_c.read_text()
    orig = text
    if "#include <rpc/rpc.h>" in text and "#if ENABLE_FEATURE_MOUNT_NFS" not in text:
        start = text.find("#include <sys/utsname.h>")
        end = text.find("#include <rpc/pmap_clnt.h>")
        if start != -1 and end != -1:
            end = text.find("\n", end)
            if end != -1:
                end += 1
                block = text[start:end]
                guarded = (
                    "#if ENABLE_FEATURE_MOUNT_NFS\n"
                    + block +
                    "#endif\n"
                )
                text = text[:start] + guarded + text[end:]
    if text != orig:
        mount_c.write_text(text)
        patches.append("mount-rpc-guard")

makefile_flags = Path("Makefile.flags")
if makefile_flags.exists():
    text = makefile_flags.read_text()
    orig = text
    text = text.replace("LDLIBS += m crypt\n", "LDLIBS += m\n")
    if text != orig:
        makefile_flags.write_text(text)
        patches.append("drop-forced-libcrypt")

runsv_c = Path("runit/runsv.c")
if runsv_c.exists():
    import re

    text = runsv_c.read_text()
    orig = text
    text = text.replace(
        "\tif (sizeof(struct timeval) == sizeof(struct timespec)\n"
        "\t && sizeof(((struct timeval*)ts)->tv_usec) == sizeof(ts->tv_nsec)\n"
        "\t) {\n"
        "\t\t/* Cheat */\n"
        "\t\tgettimeofday((void*)ts, NULL);\n"
        "\t\tts->tv_nsec *= 1000;\n"
        "\t} else {\n"
        "\t\textern void BUG_need_to_implement_gettimeofday_ns(void);\n"
        "\t\tBUG_need_to_implement_gettimeofday_ns();\n"
        "\t}\n",
        "\tstruct timeval tv;\n"
        "\tgettimeofday(&tv, NULL);\n"
        "\tts->tv_sec = tv.tv_sec;\n"
        "\tts->tv_nsec = tv.tv_usec * 1000;\n",
    )
    if text == orig:
        text, _ = re.subn(
            r"#else\s+static void gettimeofday_ns\(struct timespec \*ts\)\s*\{\s*"
            r"(?:BUILD_BUG_ON\([^\n]+\);\s*)?"
            r"(?:BUILD_BUG_ON\([^\n]+\);\s*)?"
            r"/\* Cheat \*/\s*gettimeofday\(\(void\*\)ts, NULL\);\s*ts->tv_nsec \*= 1000;\s*"
            r"\}\s*#endif",
            "#else\n"
            "static void gettimeofday_ns(struct timespec *ts)\n"
            "{\n"
            "\tstruct timeval tv;\n"
            "\tgettimeofday(&tv, NULL);\n"
            "\tts->tv_sec = tv.tv_sec;\n"
            "\tts->tv_nsec = tv.tv_usec * 1000;\n"
            "}\n"
            "#endif",
            text,
            count=1,
            flags=re.S,
        )
    if text != orig:
        runsv_c.write_text(text)
        patches.append("runsv-timeval-fallback")

udhcp_common_c = Path("networking/udhcp/common.c")
if udhcp_common_c.exists():
    text = udhcp_common_c.read_text()
    orig = text
    marker = "#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1\nvoid FAST_FUNC log1s"
    replacement = (
        "#if defined(__mips__) && defined(log1s)\n"
        "# undef log1s\n"
        "#endif\n"
        "\n"
        "#if defined CONFIG_UDHCP_DEBUG && CONFIG_UDHCP_DEBUG >= 1\n"
        "void FAST_FUNC log1s"
    )
    if marker in text and "defined(__mips__) && defined(log1s)" not in text:
        text = text.replace(marker, replacement, 1)
    if text != orig:
        udhcp_common_c.write_text(text)
        patches.append("udhcp-mips-log1s-undef")

if patches:
    print("patched legacy sources: " + ",".join(patches))
PY
}

build_one() {
  arch="$1"
  meta="$(arch_cross "$arch")" || { echo "unknown arch $arch"; return 2; }
  make_arch="$(echo "$meta" | awk '{print $1}')"
  cross="$(echo "$meta" | awk '{print $2}')"
  stripper="$(echo "$meta" | awk '{print $3}')"
  src="$SRC_ROOT/$VERSION"
  work="$BUILD_ROOT/${VERSION}-${arch}"
  out="$OUT_ROOT/$VERSION/busybox-${arch}-stripped"
  log="$LOG_ROOT/$VERSION/${arch}.log"
  status="$LOG_ROOT/$VERSION/${arch}.status"
  rm -rf "$work"
  mkdir -p "$work"
  cp -a "$src/." "$work/"
  cd "$work" || return 3
  find . -type f -exec chmod u+rw {} + 2>/dev/null || true
  find scripts applets -type f -exec chmod +x {} + 2>/dev/null || true
  find . -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
  patch_legacy_makefile
  patch_legacy_sources
  {
    echo "## build start $(date -Is) version=$VERSION arch=$arch make_arch=$make_arch cross=$cross"
    echo "## disk before"; df -h "$BASE" || true
    command -v "${cross}gcc" || true
    command -v "$stripper" || true
    make distclean >/dev/null 2>&1 || true
    make mrproper >/dev/null 2>&1 || true
    echo "## make defconfig"
    if ! make ARCH="$make_arch" CROSS_COMPILE="$cross" defconfig; then
      echo "defconfig_failed"
      echo "FAIL defconfig" > "$status"
      return 10
    fi
    patch_config
    yes "" | make ARCH="$make_arch" CROSS_COMPILE="$cross" oldconfig >/dev/null 2>&1 || true
    flags="-include compat_busybox_build.h -Wno-error -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=format-overflow -Wno-error=format-truncation -Wno-error=array-bounds -Wno-error=stringop-overflow -fcommon"
    echo "## make busybox parallel jobs=$JOBS"
    if ! make ARCH="$make_arch" CROSS_COMPILE="$cross" EXTRA_CFLAGS="$flags" -j"$JOBS" busybox; then
      echo "## parallel build failed, retry serial"
      if ! make ARCH="$make_arch" CROSS_COMPILE="$cross" EXTRA_CFLAGS="$flags" -j1 busybox; then
        echo "FAIL build" > "$status"
        return 20
      fi
    fi
    if [ ! -s busybox ]; then
      echo "FAIL missing_busybox" > "$status"
      return 21
    fi
    echo "## strip"
    if ! "$stripper" -s busybox -o "$out"; then
      echo "FAIL strip" > "$status"
      return 30
    fi
    if [ ! -s "$out" ]; then
      echo "FAIL missing_output" > "$status"
      return 31
    fi
    file "$out" || true
    readelf -h "$out" | head -30 || true
    ls -lh busybox "$out" || true
    echo "OK" > "$status"
    echo "## build success $(date -Is)"
  } > "$log" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL rc=$rc" > "$status"
  fi
  rm -rf "$work"
  return "$rc"
}

src_dir="$SRC_ROOT/$VERSION"
if [ ! -d "$src_dir" ]; then
  echo "missing source: $src_dir" >&2
  exit 4
fi
version_rc=0
for arch in "${ARCHES[@]}"; do
  echo "[builder] $VERSION $arch start"
  if build_one "$arch"; then
    echo "[builder] $VERSION $arch ok"
  else
    rc=$?
    echo "[builder] $VERSION $arch fail rc=$rc"
    version_rc=1
  fi
  df -h "$BASE" || true
done
exit "$version_rc"
'''


def target_versions() -> List[str]:
    if DATASET_DIR.exists():
        return sorted([p.name for p in DATASET_DIR.iterdir() if p.is_dir() and p.name.startswith("busybox-")])
    return []


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.1.103")
    parser.add_argument("--user", default="xyh3984")
    parser.add_argument("--password-env", default="PI_SSH_PASSWORD")
    parser.add_argument("--remote-base", default=DEFAULT_REMOTE_BASE)
    parser.add_argument("--local-out", type=Path, default=DEFAULT_LOCAL_OUT)
    parser.add_argument("--versions", nargs="+", default=["busybox-1.37.0"], help="Version names, or 'target57'.")
    parser.add_argument("--archs", nargs="+", default=["aarch64", "arm", "mips", "mipsel", "x86_64"])
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--keep-remote", action="store_true")
    return parser.parse_args(argv)


def connect(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=password, timeout=20, banner_timeout=20, auth_timeout=20)
    return client


def run_remote(client: paramiko.SSHClient, command: str, timeout: Optional[int] = None) -> int:
    stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=timeout)
    while not stdout.channel.exit_status_ready():
        while stdout.channel.recv_ready():
            print(stdout.channel.recv(4096).decode("utf-8", "replace"), end="")
        time.sleep(0.5)
    while stdout.channel.recv_ready():
        print(stdout.channel.recv(4096).decode("utf-8", "replace"), end="")
    err = stderr.read().decode("utf-8", "replace")
    if err.strip():
        print(err, file=sys.stderr)
    return stdout.channel.recv_exit_status()


def sftp_mkdirs(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = []
    cur = path
    while cur not in ("", "/"):
        parts.append(cur)
        cur = posixpath.dirname(cur)
    for item in reversed(parts):
        try:
            sftp.stat(item)
        except IOError:
            sftp.mkdir(item)


def upload_builder(sftp: paramiko.SFTPClient, remote_base: str) -> str:
    remote_script = posixpath.join(remote_base, "scripts", "remote_busybox_builder.sh")
    sftp_mkdirs(sftp, posixpath.dirname(remote_script))
    with sftp.file(remote_script, "w") as f:
        f.write(REMOTE_BUILDER)
    sftp.chmod(remote_script, 0o755)
    return remote_script


def download_tree(sftp: paramiko.SFTPClient, remote_path: str, local_path: Path) -> None:
    ensure = local_path.mkdir
    try:
        attrs = sftp.stat(remote_path)
    except IOError:
        return
    if stat.S_ISDIR(attrs.st_mode):
        local_path.mkdir(parents=True, exist_ok=True)
        for item in sftp.listdir_attr(remote_path):
            download_tree(sftp, posixpath.join(remote_path, item.filename), local_path / item.filename)
    else:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote_path, str(local_path))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    password = os.environ.get(args.password_env)
    if not password:
        password = getpass.getpass(f"SSH password for {args.user}@{args.host}: ")
    versions = target_versions() if args.versions == ["target57"] else args.versions
    args.local_out.mkdir(parents=True, exist_ok=True)
    client = connect(args.host, args.user, password)
    sftp = client.open_sftp()
    try:
        remote_script = upload_builder(sftp, args.remote_base)
        print(f"remote builder: {remote_script}")
        run_remote(client, f"mkdir -p {args.remote_base}/build {args.remote_base}/out {args.remote_base}/logs {args.remote_base}/scripts && df -h {args.remote_base}", timeout=60)
        for version in versions:
            print(f"\n=== BUILD {version} archs={','.join(args.archs)} ===")
            cmd = " ".join(["bash", remote_script, args.remote_base, version, str(args.jobs)] + args.archs)
            rc = run_remote(client, cmd, timeout=None)
            print(f"=== BUILD {version} rc={rc} ===")
            local_version = args.local_out / version
            download_tree(sftp, posixpath.join(args.remote_base, "out", version), local_version)
            download_tree(sftp, posixpath.join(args.remote_base, "logs", version), args.local_out / "logs" / version)
            if not args.keep_remote:
                run_remote(client, f"rm -rf {args.remote_base}/out/{version} {args.remote_base}/logs/{version} {args.remote_base}/build/{version}-*; df -h {args.remote_base}", timeout=120)
    finally:
        sftp.close()
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
