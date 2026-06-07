#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  agent_sleep_windows_libvirt_host_test.sh [options]

Builds and runs the Windows headless libvirt sleep/resume test.

The script:
  1. Builds the Windows lockbox.exe.
  2. Stages LOCKBOX.EXE and TEST.PS1 into target/vm/windows/lockbox-transfer.iso.
  3. Mounts the copied Windows qcow2 test disk with qemu-nbd.
  4. Writes C:\lhs.cmd, which runs TEST.PS1 at boot and records results.
  5. Verifies the boot task file C:\Windows\System32\Tasks\lhs exists.
  6. Starts the no-video libvirt VM.
  7. Wakes it once it reaches pmsuspended state.
  8. Extracts C:\lockbox-agent-sleep-test.txt and the agent log.

The script intentionally operates on the copied test qcow2 disk. Do not point
--disk at the original downloaded VHDX.

Options:
  --domain <name>          Libvirt domain name. Default: lockbox-win-s3-test
  --disk <path>            Copied Windows qcow2 disk.
                           Default: target/vm/windows/windows-server-2025-headless-task.qcow2
  --xml <path>             Libvirt domain XML.
                           Default: target/vm/windows/lockbox-win-s3-libvirt.xml
  --nbd <device>           NBD device. Default: /dev/nbd0
  --mount-dir <dir>        Temporary NTFS mount dir.
                           Default: /tmp/lockbox-win-s3-mount
  --out-dir <dir>          Extracted result directory.
                           Default: target/vm/windows/results
  --skip-build             Reuse the existing Windows lockbox.exe.
  --skip-task-check        Do not require C:\Windows\System32\Tasks\lhs.
  --prepare-only           Only stage ISO and write C:\lhs.cmd.
  --extract-only           Only extract previous result files.
  --force-destroy          Destroy the test domain if it is already running.
  --recover-ntfs           For the copied test disk only: clear NTFS dirty
                           state and remove a hibernation file if Windows left
                           the partition unsafe to mount read/write.
  -h, --help               Show this help.

If the script reports that C:\Windows\System32\Tasks\lhs is missing, run:

  tools/agent_sleep_windows_setup_task_domain.sh --force-destroy --launch-manager

Then open the temporary visible setup VM and run this as Administrator:

  schtasks /create /tn lhs /tr C:\lhs.cmd /sc onstart /ru SYSTEM /f
  shutdown /s /t 0

Then run this script again with the no-video domain.
USAGE
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="lockbox-win-s3-test"
DISK="$ROOT/target/vm/windows/windows-server-2025-headless-task.qcow2"
XML="$ROOT/target/vm/windows/lockbox-win-s3-libvirt.xml"
NBD="/dev/nbd0"
MOUNT_DIR="/tmp/lockbox-win-s3-mount"
OUT_DIR="$ROOT/target/vm/windows/results"
SKIP_BUILD=0
SKIP_TASK_CHECK=0
PREPARE_ONLY=0
EXTRACT_ONLY=0
FORCE_DESTROY=0
RECOVER_NTFS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="${2:?missing value for --domain}"
      shift 2
      ;;
    --disk)
      DISK="${2:?missing value for --disk}"
      shift 2
      ;;
    --xml)
      XML="${2:?missing value for --xml}"
      shift 2
      ;;
    --nbd)
      NBD="${2:?missing value for --nbd}"
      shift 2
      ;;
    --mount-dir)
      MOUNT_DIR="${2:?missing value for --mount-dir}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:?missing value for --out-dir}"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-task-check)
      SKIP_TASK_CHECK=1
      shift
      ;;
    --prepare-only)
      PREPARE_ONLY=1
      shift
      ;;
    --extract-only)
      EXTRACT_ONLY=1
      shift
      ;;
    --force-destroy)
      FORCE_DESTROY=1
      shift
      ;;
    --recover-ntfs)
      RECOVER_NTFS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() {
  printf 'stage: %s\n' "$*"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing required file: $1" >&2
    exit 2
  fi
}

cleanup_done=0
cleanup() {
  if [[ "$cleanup_done" -eq 1 ]]; then
    return
  fi
  cleanup_done=1
  if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
    sudo umount "$MOUNT_DIR" >/dev/null 2>&1 || true
  fi
  if [[ -b "$NBD" ]]; then
    sudo qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

preflight() {
  require_command cargo
  require_command cp
  require_command genisoimage
  require_command findmnt
  require_command lsblk
  require_command ntfs-3g
  require_command qemu-nbd
  require_command virsh
  require_command sudo
  if [[ "$RECOVER_NTFS" -eq 1 ]]; then
    require_command ntfsfix
  fi
  require_file "$DISK"
  require_file "$XML"
  require_file "$ROOT/tools/agent_sleep_windows_vm_test.ps1"
  sudo -v
}

stage_iso() {
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "build Windows lockbox.exe"
    cargo build -p lockbox_cli --target x86_64-pc-windows-gnu
  fi

  require_file "$ROOT/target/x86_64-pc-windows-gnu/debug/lockbox.exe"
  log "stage transfer ISO"
  mkdir -p "$ROOT/target/vm/windows/share"
  cp "$ROOT/target/x86_64-pc-windows-gnu/debug/lockbox.exe" \
    "$ROOT/target/vm/windows/share/LOCKBOX.EXE"
  cp "$ROOT/tools/agent_sleep_windows_vm_test.ps1" \
    "$ROOT/target/vm/windows/share/TEST.PS1"
  genisoimage -quiet -V LOCKBOX -r -J \
    -o "$ROOT/target/vm/windows/lockbox-transfer.iso" \
    "$ROOT/target/vm/windows/share"
}

connect_disk() {
  local mode="$1"
  log "connect $DISK to $NBD"
  cleanup_done=0
  sudo modprobe nbd max_part=16
  if [[ "$mode" == "ro" ]]; then
    sudo qemu-nbd --connect="$NBD" --read-only "$DISK"
  else
    sudo qemu-nbd --connect="$NBD" "$DISK"
  fi
  sleep 1
}

ntfs_partition() {
  local part
  while read -r part; do
    if [[ -n "$part" ]]; then
      printf '%s\n' "$part"
      return 0
    fi
  done < <(lsblk -nrpo NAME,FSTYPE "$NBD" | awk '$2 == "ntfs" { print $1 }')
  return 1
}

mount_disk() {
  local mode="$1"
  local part
  part="$(ntfs_partition)" || {
    lsblk "$NBD" >&2
    echo "could not find an NTFS partition on $NBD" >&2
    exit 1
  }
  log "mount $part"
  sudo mkdir -p "$MOUNT_DIR"
  if [[ "$mode" == "ro" ]]; then
    sudo mount -o ro "$part" "$MOUNT_DIR"
  else
    if sudo ntfs-3g -o windows_names "$part" "$MOUNT_DIR"; then
      if mount_is_rw; then
        return 0
      fi
      sudo umount "$MOUNT_DIR" >/dev/null 2>&1 || true
    fi
    if [[ "$RECOVER_NTFS" -ne 1 ]]; then
      cat >&2 <<'MSG'
The NTFS partition could not be mounted read/write.

Windows probably left the copied test disk in a hibernated, fast-startup, or
unclean state. For the disposable copied qcow2 test disk, rerun with:

  tools/agent_sleep_windows_libvirt_host_test.sh --force-destroy --recover-ntfs

Do not use --recover-ntfs against the original downloaded VHDX.
MSG
      exit 1
    fi
    log "recover NTFS dirty or hibernated state"
    sudo ntfsfix -d "$part"
    sudo ntfs-3g -o windows_names,remove_hiberfile "$part" "$MOUNT_DIR"
    require_rw_mount
  fi
}

mount_is_rw() {
  local opts
  opts="$(findmnt -n -o OPTIONS --target "$MOUNT_DIR" 2>/dev/null || true)"
  [[ -n "$opts" && ",$opts," != *",ro,"* ]]
}

require_rw_mount() {
  if ! mount_is_rw; then
    findmnt --target "$MOUNT_DIR" >&2 || true
    echo "NTFS mount is still read-only; cannot write C:\\lhs.cmd" >&2
    exit 1
  fi
}

write_boot_command() {
  log "write C:\\lhs.cmd"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'CMD'
@echo off
set LOG=C:\lockbox-agent-sleep-test.txt
echo started %DATE% %TIME% > %LOG%
echo powercfg /a before test: >> %LOG%
powercfg /a >> %LOG% 2>&1
echo running lockbox sleep test >> %LOG%
powershell -NoProfile -ExecutionPolicy Bypass -File D:\TEST.PS1 -LockboxBin D:\LOCKBOX.EXE >> %LOG% 2>&1
echo test exit=%ERRORLEVEL% >> %LOG%
echo powercfg /a after test: >> %LOG%
powercfg /a >> %LOG% 2>&1
schtasks /delete /tn lhs /f >> %LOG% 2>&1
shutdown /s /t 0 /f
CMD
  sudo install -m 0644 "$tmp" "$MOUNT_DIR/lhs.cmd"
  rm -f "$tmp"

  if [[ "$SKIP_TASK_CHECK" -eq 0 && ! -f "$MOUNT_DIR/Windows/System32/Tasks/lhs" ]]; then
    cat >&2 <<'MSG'
C:\Windows\System32\Tasks\lhs is missing.

The boot command has been written to C:\lhs.cmd, but Windows will not run it
until the startup task is recreated. Run:

  tools/agent_sleep_windows_setup_task_domain.sh --force-destroy --launch-manager

Then open the temporary visible setup VM and run this as Administrator:

  schtasks /create /tn lhs /tr C:\lhs.cmd /sc onstart /ru SYSTEM /f
  shutdown /s /t 0

Then rerun this host script with the no-video domain.
MSG
    exit 1
  fi
}

prepare_disk() {
  connect_disk rw
  mount_disk rw
  write_boot_command
  sudo sync
  cleanup
}

domain_state() {
  virsh -c qemu:///session domstate "$DOMAIN" 2>/dev/null || true
}

ensure_domain_ready() {
  local state
  state="$(domain_state)"
  if [[ "$state" == "running" || "$state" == "paused" || "$state" == "pmsuspended" ]]; then
    if [[ "$FORCE_DESTROY" -ne 1 ]]; then
      echo "domain $DOMAIN is already active: $state" >&2
      echo "rerun with --force-destroy if this is the disposable test VM" >&2
      exit 1
    fi
    log "destroy active test domain"
    virsh -c qemu:///session destroy "$DOMAIN"
    for _ in $(seq 1 60); do
      state="$(domain_state)"
      if [[ "$state" == "shut off" || -z "$state" ]]; then
        break
      fi
      sleep 1
    done
  fi

  state="$(domain_state)"
  if [[ -n "$state" ]]; then
    log "undefine existing libvirt domain"
    virsh -c qemu:///session undefine "$DOMAIN" --nvram >/dev/null \
      || virsh -c qemu:///session undefine "$DOMAIN" >/dev/null
  fi

  log "define libvirt domain"
  virsh -c qemu:///session define "$XML" >/dev/null
}

run_domain_test() {
  ensure_domain_ready
  log "start headless Windows VM"
  virsh -c qemu:///session start "$DOMAIN" >/dev/null

  log "wait for suspend"
  local state
  for _ in $(seq 1 240); do
    state="$(domain_state)"
    if [[ "$state" == "pmsuspended" ]]; then
      log "wake suspended VM"
      virsh -c qemu:///session dompmwakeup "$DOMAIN" >/dev/null || true
      break
    fi
    if [[ "$state" == "shut off" ]]; then
      break
    fi
    sleep 2
  done

  log "wait for VM shutdown"
  for _ in $(seq 1 240); do
    state="$(domain_state)"
    if [[ "$state" == "shut off" ]]; then
      return 0
    fi
    sleep 2
  done

  echo "VM did not shut down after the test; current state: $(domain_state)" >&2
  echo "inspect manually, or rerun with --force-destroy after confirming it is safe" >&2
  exit 1
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    sudo cp "$src" "$dst"
    sudo chown "$(id -u):$(id -g)" "$dst"
    return 0
  fi
  return 1
}

extract_results() {
  mkdir -p "$OUT_DIR"
  connect_disk ro
  mount_disk ro

  log "extract result files"
  local result="$OUT_DIR/lockbox-agent-sleep-test.txt"
  local agent_log="$OUT_DIR/agent.log"
  copy_if_exists "$MOUNT_DIR/lockbox-agent-sleep-test.txt" "$result" || true
  copy_if_exists "$MOUNT_DIR/Windows/Temp/lockbox-agent-sleep-test/agent.log" "$agent_log" || true

  if [[ ! -f "$result" ]]; then
    echo "missing result file: C:\\lockbox-agent-sleep-test.txt" >&2
    exit 1
  fi

  echo "result: $result"
  sed -n '1,220p' "$result"
  if [[ -f "$agent_log" ]]; then
    echo "agent log: $agent_log"
    sed -n '1,220p' "$agent_log"
  else
    echo "missing agent log: C:\\Windows\\Temp\\lockbox-agent-sleep-test\\agent.log" >&2
  fi

  if ! grep -q 'pass: cache cleared on sleep' "$result"; then
    echo "Windows sleep test did not report success" >&2
    exit 1
  fi
  if [[ -f "$agent_log" ]] && ! grep -q 'suspend requested; cleared' "$agent_log"; then
    echo "agent log did not show suspend cache clearing" >&2
    exit 1
  fi
  echo "pass: Windows agent sleep test completed"
}

preflight

if [[ "$EXTRACT_ONLY" -eq 1 ]]; then
  extract_results
  exit 0
fi

stage_iso
prepare_disk

if [[ "$PREPARE_ONLY" -eq 1 ]]; then
  echo "prepared Windows disk and transfer ISO"
  exit 0
fi

run_domain_test
extract_results
