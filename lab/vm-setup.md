# VM setup — Windows 11 lab

Goal: one offline Windows 11 VM, 4 vCPU / 4 GiB, session libvirt, qcow2 on the
external volume, snapshots before every run, with the repo visible inside.

Everything below runs as your user. No `sudo`, no root libvirt.

## 0. What you need first

| Item | Why | Where |
|---|---|---|
| Windows 11 ISO (24H2 or later) | guest OS | download while online |
| virtio-win ISO | disk/net/balloon drivers, guest agent, optional virtiofs | fedorapeople.org / GitHub |
| .NET 10 SDK | build the core | dot.net |
| Python 3.13+ | hunter | python.org |
| Sysinternals suite (optional) | Process Explorer, VMMap for screenshots | learn.microsoft.com |
| pe-sieve (optional) | Phase 5 validation | GitHub |

Put the ISOs on the external volume, e.g. `$HOME/lab/isos/`.

## 1. Create the VM

```bash
export ISO=$HOME/lab/isos/Win11_24H2_English_x64.iso
export VIRTIO_ISO=$HOME/lab/isos/virtio-win.iso
./lab/create-vm.sh
```

What the script does:

- refuses to overwrite an existing domain;
- creates a 64 GiB qcow2 under `$HOME/lab/vms/`;
- `qemu:///session`, q35, UEFI, TPM 2.0 (Windows 11 requires both);
- 4 vCPU, 4096 MiB;
- **user-mode networking for the install phase only** (you need updates and the
  toolchain);
- virtiofs share of the repository, mounted in the guest as `Z:`;
- SPICE display, so `virt-manager` can attach.

If you prefer XML, [domain.xml](domain.xml) is the same machine in libvirt form.

## 2. Install Windows

1. `virt-manager` → connect to **QEMU/KVM User session** → open `sl33p-win11`.
2. Install Windows 11. At the network screen, use `Shift+F10` →
   `start ms-cxh:localonly` to create a local account without a Microsoft
   login. (Older builds: `OOBE\BYPASSNRO`.)
3. Install the virtio-win drivers from the second CD: at minimum **viostor**
   (disk is already visible if you used SATA; with virtio-blk you need it during
   setup), **NetKVM**, **Balloon**, and **qemu-guest-agent**.
4. Install virtiofs support if you want the `Z:` share: `virtio-win` →
   `virtiofs` (needs WinFsp; the installer is on the same ISO under
   `virtiofs\`). Reboot.
5. Rename the machine to `sl33p-lab`, set the timezone, disable sleep.

## 3. Install the toolchain (still online)

```powershell
# .NET 10 SDK
winget install Microsoft.DotNet.SDK.10

# Python 3.13+
winget install Python.Python.3.13

# optional but useful
winget install Microsoft.Sysinternals
winget install Microsoft.PowerShell
```

Then copy the repository in. Two options:

**A. virtiofs (preferred).** In the guest, install WinFsp and the virtiofs
driver, then map the share:

```powershell
net use Z: \\?\virtiofs\sl33p
# or: the virtiofs service exposes it as a drive automatically
```

**B. Copy once.** From the host, while the NIC still exists:

```bash
# on the host, in the repo
python3 -m http.server 8000 --bind 0.0.0.0
```

```powershell
# in the guest
curl.exe -O http://10.0.2.2:8000/sl33p.zip
Expand-Archive sl33p.zip C:\lab\
```

Option B means the guest copy and the host copy drift. Use it once, then treat
the guest as the runner and the host as the source of truth, syncing by zip
when needed.

## 4. Build and smoke test

```powershell
cd C:\lab\sl33p
dotnet build src/core -c Release
.\src\core\bin\Release\net10.0\sl33p-core.exe --help
```

Expected: usage text, exit code 0. Then, in a second terminal:

```powershell
# terminal 1
.\src\core\bin\Release\net10.0\sl33p-core.exe --lab-ack --mode plain --protect rw --sleep 60

# terminal 2 (use the pid printed in the status line)
python src\hunt\sl33p_hunt.py --pid <pid> --duration 20 --html out.html
```

Expected: `D1-marker` at the region address, verdict `DETECTED`.

## 5. Add Defender exclusions — and disclose them

Windows Defender will eventually quarantine a binary that allocates executable
memory, flips protections and holds a high-entropy buffer. That is correct
behaviour on its part.

For this VM only:

```powershell
Add-MpPreference -ExclusionPath 'C:\lab\sl33p'
Add-MpPreference -ExclusionPath 'C:\lab\sl33p\src\core\bin'
```

This is lab hygiene, not evasion: the VM is offline, the path is fixed, and the
exclusion is documented here and in the README. Do not add exclusions on a
machine that is not the lab.

## 6. Go offline and snapshot

```powershell
# confirm what is connected
Get-NetAdapter | Format-Table Name, Status
```

On the host:

```bash
virsh -c qemu:///session domiflist sl33p-win11
virsh -c qemu:///session detach-interface sl33p-win11 --type network --mac <MAC>
```

Then shut down and snapshot:

```bash
virsh -c qemu:///session shutdown sl33p-win11
virsh -c qemu:///session snapshot-create-as sl33p-win11 baseline-offline \
  --description "toolchain installed, no NIC, clean boot" --atomic
virsh -c qemu:///session start sl33p-win11
```

Verify inside the guest:

```powershell
Get-NetAdapter | Format-Table Name, Status          # nothing connected
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
```

## 7. Reproduce from scratch

A rebuild is: `create-vm.sh`, install Windows, install toolchain, build, remove
NIC, snapshot. Budget 45–60 minutes, most of it Windows installation. That is
why `baseline-offline` is worth protecting: reverting takes seconds, rebuilding
takes an hour.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Setup says "this PC can't run Windows 11" | TPM or Secure Boot | Recreate with `--tpm` and `--boot uefi,loader.secure=yes` |
| Disk not visible in setup | virtio-blk without driver | Use `--disk ...,bus=sata` for install, or load viostor |
| `Z:` missing | virtiofs driver not installed | Install WinFsp + virtiofs from the virtio-win ISO |
| Very slow disk | qcow2 on NTFS/FUSE | Expected; keep the VM on internal btrfs if you can |
| VM will not start after moving the drive | stale absolute path | `virsh -c qemu:///session edit sl33p-win11` and fix `<source file=...>` |
| Defender deletes the core | behavioural detection | Documented exclusion above; do not disable Defender globally |
