# Agent Sleep VM Testing

This document records how to set up the Linux, macOS, and Windows VM
environments used to test that the session agent clears cached lockbox keys on
system sleep.

The invariant under test is:

1. open a lockbox so the session agent caches its content key;
2. verify `lockbox session` reports the lockbox as open;
3. put the guest operating system into sleep from inside the guest;
4. resume the guest;
5. verify `lockbox session --format tsv` reports no open lockboxes;
6. verify the agent log contains `suspend requested; cleared`.

The helper scripts are:

- `tools/agent_sleep_unix_vm_test.sh`
- `tools/agent_sleep_windows_vm_test.ps1`
- `tools/agent_sleep_windows_libvirt_host_test.sh`

The Windows VM setup is materially different from Linux and macOS. Windows only
reported S3 as available when the VM had no virtual video adapter attached.

## Local Build Checks

Run these before VM work:

```sh
cargo check -p lockbox_vault
cargo check -p lockbox_cli
cargo test -p lockbox_cli --test agent_flow
cargo check -p lockbox_cli --target x86_64-pc-windows-gnu
```

The Windows target check requires the GNU Windows target and linker toolchain.

## Linux VM

Use a normal systemd Linux guest under QEMU/KVM. Multipass can run the agent
smoke test, but it did not emit a reliable guest suspend/resume event in our
test. Direct QEMU with a systemd guest did.

Guest requirements:

- `systemd` and `systemd-logind`;
- `systemctl suspend` works in the guest;
- the host can wake the guest from the QEMU monitor;
- Rust toolchain installed, or a Linux `lockbox` binary copied in.

Build the CLI on the host or guest:

```sh
cargo build -p lockbox_cli
```

Run the no-sleep readiness test in the guest:

```sh
tools/agent_sleep_unix_vm_test.sh \
  --bin target/debug/lockbox \
  --no-sleep
```

Expected output includes:

```text
prepared: cache is populated and sleep watcher is active
```

Run the real sleep test in the guest:

```sh
tools/agent_sleep_unix_vm_test.sh \
  --bin target/debug/lockbox \
  --work-dir /tmp/lockbox-agent-sleep-test-full
```

When the script prints:

```text
sleeping now; resume the VM if the hypervisor does not do it automatically
```

wake the VM from the host QEMU monitor:

```text
system_wakeup
```

Expected result:

```text
pass: cache cleared on sleep
```

The log path printed by the script should contain:

```text
sleep watcher started
suspend requested; cleared 1 cached lockboxes
```

## macOS VM

The macOS test was run with
`target/vm/mac/workspace/OneClick-macOS-Simple-KVM`, using QEMU/KVM and a
mounted test ISO. The installed test account was:

- user: `lockbox`
- password: `Lockbox123`

Guest requirements:

- Command Line Tools installed (`xcode-select -p` succeeds);
- Rust installed, or the runner can install rustup;
- the test ISO mounted as `LOCKBOX`.

Patch the OneClick `basic.sh` launcher to attach the test ISO:

```sh
[[ -n "${LOCKBOX_TEST_ISO:-}" ]] && {
    MOREARGS+=(
        -drive id=LockboxTestIso,format=raw,if=none,media=cdrom,readonly=on,file="$LOCKBOX_TEST_ISO"
        -device ide-cd,bus=sata.5,drive=LockboxTestIso
    )
}
```

Build the source archives used by the ISO:

```sh
mkdir -p target/vm/mac/share

tar \
  --exclude=target \
  --exclude=.git \
  --exclude=.agents \
  --exclude=.codex \
  --exclude=.mcp_logs \
  -czf target/vm/mac/share/lockbox-src.tgz \
  -C /home/bsutton/git/reVault rust

tar \
  --exclude=target \
  --exclude=.git \
  --exclude=benchmarks \
  --exclude=.agents \
  --exclude=.codex \
  --exclude=.mcp_logs \
  -czf target/vm/mac/share/zstd-rs.tgz \
  -C /home/bsutton/git zstd-rs
```

`zstd-rs.tgz` must include the top-level `Readme.md`; `ruzstd` uses it in
`include_str!`.

Place this runner on the ISO as
`target/vm/mac/share/run-lockbox-mac-test.command`:

```sh
#!/bin/bash
set -euo pipefail

LOG="$HOME/Desktop/lockbox-mac-test.log"
exec > >(tee "$LOG") 2>&1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$HOME/lockbox-mac-test-src"
rm -rf "$WORK"
mkdir -p "$WORK"
tar -xzf "$SCRIPT_DIR/lockbox-src.tgz" -C "$WORK" --strip-components=1
mkdir -p "$WORK/zstd-rs"
tar -xzf "$SCRIPT_DIR/zstd-rs.tgz" -C "$WORK/zstd-rs" --strip-components=1
perl -0pi -e 's#\.\./\.\./\.\./zstd-rs/ruzstd#../zstd-rs/ruzstd#g' \
  "$WORK/lockbox_core/Cargo.toml"

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Command Line Tools are not installed."
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y --profile minimal
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

cd "$WORK"
cargo build -p lockbox_cli

tools/agent_sleep_unix_vm_test.sh --bin target/debug/lockbox --no-sleep
tools/agent_sleep_unix_vm_test.sh \
  --bin target/debug/lockbox \
  --work-dir /tmp/lockbox-agent-sleep-test-full

echo "lockbox macOS agent sleep test passed"
```

Build the ISO:

```sh
chmod +x target/vm/mac/share/run-lockbox-mac-test.command
genisoimage -V LOCKBOX -r -J \
  -o target/vm/mac/lockbox-test.iso \
  target/vm/mac/share
```

Start the VM:

```sh
cd target/vm/mac/workspace/OneClick-macOS-Simple-KVM
env HEADLESS=1 \
  LOCKBOX_TEST_ISO=/home/bsutton/git/reVault/rust/target/vm/mac/lockbox-test.iso \
  ./basic.sh
```

Open the `LOCKBOX` volume in Finder and run
`run-lockbox-mac-test.command`.

When the script prints:

```text
sleeping now; resume the VM if the hypervisor does not do it automatically
```

wake the VM from the QEMU monitor:

```text
system_wakeup
```

Expected result:

```text
pass: cache cleared on sleep
lockbox macOS agent sleep test passed
```

## Windows VM

Windows Server 2025 under raw QEMU did not expose S0 or S3. The viable setup was
a libvirt/KVM VM using Q35 + OVMF with S3 explicitly enabled, and no virtual
video device.

With `qxl`, `vga`, `bochs`, or `virtio` video attached, `powercfg /a` reported:

```text
Standby (S3)
    An internal system component has disabled this standby state.
        Graphics
```

With `<video><model type='none'/></video>`, `powercfg /a` reported:

```text
The following sleep states are available on this system:
    Standby (S3)
```

### Build the Windows CLI

```sh
cargo build -p lockbox_cli --target x86_64-pc-windows-gnu
```

Stage the executable and script:

```sh
mkdir -p target/vm/windows/share
cp target/x86_64-pc-windows-gnu/debug/lockbox.exe target/vm/windows/share/LOCKBOX.EXE
cp tools/agent_sleep_windows_vm_test.ps1 target/vm/windows/share/TEST.PS1
genisoimage -V LOCKBOX -r -J \
  -o target/vm/windows/lockbox-transfer.iso \
  target/vm/windows/share
```

### Disk and Firmware

Use a copied disk image. Do not modify the original VHDX:

```sh
qemu-img convert -O qcow2 \
  target/vm/windows/windows-server-2025-eval.vhdx \
  target/vm/windows/windows-server-2025-libvirt.qcow2

cp target/vm/windows/OVMF_VARS_4M.fd \
  target/vm/windows/lockbox-win-s3-vars.fd
```

If the Administrator password is unknown, reset only the copied qcow2. The test
run used the utilman-to-cmd recovery method on the copied disk and set:

```text
Administrator / LockboxTest123!
```

Restore `Utilman.exe` on any disk image that will be kept beyond testing.

### Libvirt Domain

Use `qemu:///session` so the VM can use workspace-hosted disk images without
root-owned libvirt storage.

The critical pieces of the domain XML are:

```xml
<domain type='kvm'>
  <name>lockbox-win-s3-test</name>
  <memory unit='MiB'>4096</memory>
  <vcpu placement='static'>4</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.fd</loader>
    <nvram template='/usr/share/OVMF/OVMF_VARS_4M.fd'>/home/bsutton/git/reVault/rust/target/vm/windows/lockbox-win-s3-vars.fd</nvram>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <smm state='on'/>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none'/>
  <pm>
    <suspend-to-mem enabled='yes'/>
    <suspend-to-disk enabled='yes'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/home/bsutton/git/reVault/rust/target/vm/windows/windows-server-2025-libvirt.qcow2'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/home/bsutton/git/reVault/rust/target/vm/windows/lockbox-transfer.iso'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
    <controller type='sata' index='0'/>
    <controller type='usb' model='qemu-xhci'/>
    <input type='keyboard' bus='usb'/>
    <input type='tablet' bus='usb'/>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <video>
      <model type='none'/>
    </video>
    <memballoon model='none'/>
  </devices>
</domain>
```

Define and start:

```sh
virsh -c qemu:///session define target/vm/windows/lockbox-win-s3-libvirt.xml
virsh -c qemu:///session start lockbox-win-s3-test
```

### Prove S3 Availability Headless

Because the VM is headless, run `powercfg /a` through a boot task or service and
read the output offline. The proof run used this one-shot script:

```bat
powercfg /a > \lockbox-headless-powercfg.txt 2>&1
schtasks /delete /tn lhs /f
```

registered as:

```bat
schtasks /create /tn lhs /tr \lhs.cmd /sc onstart /ru SYSTEM /f
```

After booting headless, stop the VM:

```sh
virsh -c qemu:///session destroy lockbox-win-s3-test
```

Read `\lockbox-headless-powercfg.txt` from the NTFS partition. Expected:

```text
The following sleep states are available on this system:
    Standby (S3)
```

### Run the Agent Sleep Test

The preferred host-side runner is:

```sh
tools/agent_sleep_windows_libvirt_host_test.sh --force-destroy
```

The runner builds the Windows binary, refreshes `lockbox-transfer.iso`, mounts
the copied qcow2 disk with `qemu-nbd`, writes `C:\lhs.cmd`, starts the no-video
libvirt VM, wakes it from `pmsuspended`, and extracts the result files into:

```text
target/vm/windows/results/lockbox-agent-sleep-test.txt
target/vm/windows/results/agent.log
```

It needs `sudo` for `modprobe`, `qemu-nbd`, mounting the NTFS partition, and
unmounting. It must only be pointed at a copied qcow2 test disk, not the
original downloaded VHDX.

If the copied test disk was previously destroyed while Windows was running, the
NTFS partition may be left in a hibernated, fast-startup, or dirty state. The
runner will refuse to write to a read-only fallback mount. For the disposable
copied qcow2 disk, rerun with:

```sh
tools/agent_sleep_windows_libvirt_host_test.sh --force-destroy --recover-ntfs
```

Do not use `--recover-ntfs` against the original downloaded VHDX.

If the runner reports that `C:\Windows\System32\Tasks\lhs` is missing, the
previous proof run has deleted the boot task. Start a temporary visible setup
VM:

```sh
tools/agent_sleep_windows_setup_task_domain.sh --force-destroy --launch-manager
```

Open `lockbox-win-task-setup` in `virt-manager`, then run this as
Administrator inside Windows:

```bat
schtasks /create /tn lhs /tr C:\lhs.cmd /sc onstart /ru SYSTEM /f
shutdown /s /t 0
```

Then rerun:

```sh
tools/agent_sleep_windows_libvirt_host_test.sh --force-destroy
```

For the full Windows agent test, run `tools/agent_sleep_windows_vm_test.ps1` as
a boot-time SYSTEM task in the headless VM. The command inside the guest is:

```powershell
powershell -ExecutionPolicy Bypass -File D:\TEST.PS1 -LockboxBin D:\LOCKBOX.EXE
```

The script:

1. runs `powercfg /hibernate off`;
2. verifies `powercfg /a` reports S0/S1/S2/S3 availability;
3. populates the lockbox session cache;
4. calls `rundll32.exe powrprof.dll,SetSuspendState 0,1,0`;
5. verifies the cache is empty after resume.

Wake the sleeping guest from libvirt or QEMU:

```sh
virsh -c qemu:///session dompmwakeup lockbox-win-s3-test
```

or, from QEMU monitor:

```text
system_wakeup
```

Expected result file/log content:

```text
pass: cache cleared on sleep
suspend requested; cleared
```

If `powercfg /a` reports `Graphics` as the S3 blocker, the domain still has a
virtual video adapter. Remove all graphics/video devices and repeat the test.
