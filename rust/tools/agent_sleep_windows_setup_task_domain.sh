#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  agent_sleep_windows_setup_task_domain.sh [options]

Defines and starts a temporary visible Windows libvirt VM so the one-time
startup task can be recreated inside Windows.

This setup VM intentionally has a virtual display. It is only for running:

  schtasks /create /tn lhs /tr C:\lhs.cmd /sc onstart /ru SYSTEM /f
  shutdown /s /t 0

Do not use this VM to validate S3. The real S3 test must run in the no-video
lockbox-win-s3-test domain.

Options:
  --domain <name>          Setup domain name. Default: lockbox-win-task-setup
  --disk <path>            Copied Windows qcow2 disk.
                           Default: target/vm/windows/windows-server-2025-headless-task.qcow2
  --iso <path>             Transfer ISO.
                           Default: target/vm/windows/lockbox-transfer.iso
  --force-destroy          Destroy setup domain if already active.
  --launch-manager         Start virt-manager after defining/starting the VM.
  -h, --help               Show this help.
USAGE
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="lockbox-win-task-setup"
DISK="$ROOT/target/vm/windows/windows-server-2025-headless-task.qcow2"
ISO="$ROOT/target/vm/windows/lockbox-transfer.iso"
VARS="$ROOT/target/vm/windows/lockbox-win-task-setup-vars.fd"
XML="$ROOT/target/vm/windows/lockbox-win-task-setup.xml"
FORCE_DESTROY=0
LAUNCH_MANAGER=0

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
    --iso)
      ISO="${2:?missing value for --iso}"
      shift 2
      ;;
    --force-destroy)
      FORCE_DESTROY=1
      shift
      ;;
    --launch-manager)
      LAUNCH_MANAGER=1
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

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing required file: $1" >&2
    exit 2
  fi
}

domain_state() {
  virsh -c qemu:///session domstate "$DOMAIN" 2>/dev/null || true
}

require_file "$DISK"
require_file "$ISO"
require_file /usr/share/OVMF/OVMF_CODE_4M.fd
require_file /usr/share/OVMF/OVMF_VARS_4M.fd

state="$(domain_state)"
if [[ "$state" == "running" || "$state" == "paused" || "$state" == "pmsuspended" ]]; then
  if [[ "$FORCE_DESTROY" -ne 1 ]]; then
    echo "domain $DOMAIN is already active: $state" >&2
    echo "rerun with --force-destroy if this is the disposable setup VM" >&2
    exit 1
  fi
  virsh -c qemu:///session destroy "$DOMAIN" >/dev/null
fi

if [[ ! -f "$VARS" ]]; then
  cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARS"
fi

cat >"$XML" <<XML
<domain type='kvm'>
  <name>$DOMAIN</name>
  <memory unit='MiB'>4096</memory>
  <currentMemory unit='MiB'>4096</currentMemory>
  <vcpu placement='static'>4</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.fd</loader>
    <nvram template='/usr/share/OVMF/OVMF_VARS_4M.fd'>$VARS</nvram>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <smm state='on'/>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none'/>
  <clock offset='localtime'/>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$DISK'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$ISO'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
    <controller type='sata' index='0'/>
    <controller type='usb' model='qemu-xhci'/>
    <input type='keyboard' bus='usb'/>
    <input type='tablet' bus='usb'/>
    <graphics type='spice' autoport='yes'>
      <listen type='none'/>
    </graphics>
    <video>
      <model type='qxl'/>
    </video>
    <memballoon model='none'/>
  </devices>
</domain>
XML

virsh -c qemu:///session define "$XML" >/dev/null
virsh -c qemu:///session start "$DOMAIN" >/dev/null

cat <<MSG
Started temporary visible setup VM: $DOMAIN

Open virt-manager, connect to qemu:///session, and open $DOMAIN.

Inside Windows, run this as Administrator:

  schtasks /create /tn lhs /tr C:\\lhs.cmd /sc onstart /ru SYSTEM /f
  shutdown /s /t 0

After the VM shuts down, run:

  tools/agent_sleep_windows_libvirt_host_test.sh --force-destroy --recover-ntfs

MSG

if [[ "$LAUNCH_MANAGER" -eq 1 ]]; then
  virt-manager --connect qemu:///session >/dev/null 2>&1 &
fi
