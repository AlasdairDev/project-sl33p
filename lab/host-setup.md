# Host setup — Aurora DX

> Paths below are this machine's. Substitute your own when reproducing;
> `lab/create-vm.sh` defaults to `$HOME/lab/vms` and takes `VM_DIR`.

Checked on 2026-11-22 against this machine. The host is **Aurora DX**, an
immutable Fedora Kinoite image, so the rules are different from a normal
distro: no `dnf install` on the host, no compiling into `/usr`, no packages
layered with `rpm-ostree` unless there is no alternative.

## Verified inventory

| Item | Value | Verdict |
|---|---|---|
| OS | Aurora 45.20261117.1 (Kinoite), stable | OK |
| Kernel | 7.2.11-300.fc45.x86_64 | OK |
| CPU | i5-1135G7, 4C/8T, VT-x, bare metal | OK |
| KVM | `/dev/kvm` present, mode `crw-rw-rw-` | OK |
| Groups | `libvirt`, `docker`, `incus-admin` | OK — DX already provisioned |
| Virtualisation | `virt-manager`, `qemu-system-x86_64`, `virt-install`, `qemu-img` | OK |
| Shared folders | `virtiofsd` at `/usr/libexec/virtiofsd` | OK |
| Existing VM | `owasp-bwa`, running, user session, 1 GiB, user networking | Reference pattern |
| RAM | 15 GiB total, **~5.3 GiB available**, 8 GiB swap (4.8 used) | Tight |
| Internal disk | btrfs `/var/home`, 236 G total, **21 G free** | Too tight for a 64 G VM |
| External disk | an NTFS volume, **386 G free** | Use for VM disk |
| .NET | SDK 11.0.100 (no local .NET 10 runtime) | Builds `net10.0` via NuGet |
| Python | 3.15.2 via mise, no `pip` module | Tests need no packages |
| Python libs | `PyYAML`, `cryptography` already importable | Matrix + D6 work |
| PowerShell | 7.7.0 | Optional, guest has 5.1 |
| Windows VM | **none** | The one missing piece |

## What this means

1. **Do not install anything on the host to make this project work.** Everything
   the host needs is already there: `dotnet` builds the core, `python3` runs the
   tests and the replay path, `git` is present. If a tool is genuinely needed
   later, `brew install` it (that is the Aurora DX way) or run it in a distrobox.

2. **Use session libvirt, like your existing VM.** `virsh` already defaults to
   `qemu:///session` and `owasp-bwa` runs as your user. That means no root, no
   `svirt` SELinux labels, and no permission fights over the NTFS mount. Keep
   the same pattern:

   ```bash
   virsh -c qemu:///session list --all
   ```

3. **The internal disk is not the place for the VM.** 21 GB free cannot hold a
   64 GB qcow2 plus snapshots. Put the disk on the NTFS volume under
   `$HOME/lab/vms/`, and accept the caveats below.

4. **Stop the BWA VM before a lab run.** 4 GiB for Windows 11 plus 1 GiB for
   `owasp-bwa` plus a browser will start swapping. `virsh -c qemu:///session
   shutdown owasp-bwa` is enough.

5. **Move the repository off NTFS.** `git` on `ntfs-3g` loses POSIX modes and
   symlink behaviour, and a fuseblk filesystem is the wrong place for a
   portfolio repo you will push. Recommended:

   ```bash
   mkdir -p ~/lab
   rsync -a --info=progress2 \
     "$PWD/" ~/lab/sl33p/
   cd ~/lab/sl33p && git init -b main
   ```

   Keep the VM images on the external volume; keep the source on btrfs.

## NTFS caveats for the VM disk

The external volume is mounted with `fuseblk` (`ntfs-3g`). It works, but:

- Never unplug the drive while the VM is running. A qcow2 on a yanked FUSE
  mount is a corrupt qcow2.
- Use `cache=writeback` for the disk. `O_DIRECT` is unreliable on FUSE.
- Internal qcow2 snapshots still work; they live inside the qcow2 file.
- `qemu-img info` and `qemu-img check` are your friends after any hard stop.

If you can free ~50 GB on the internal btrfs volume, move the disk there and
delete this section from your life.

## Host-side commands that should already work

```bash
# core compiles (Windows-only at runtime, that is expected)
cd ~/lab/sl33p
dotnet build src/core/sl33p.csproj          # Build succeeded, 0 warnings

# 56 unit tests, no installs
python3 -m unittest discover -s tests

# offline evidence path
python3 tools/make_capture.py
python3 src/hunt/sl33p_hunt.py --replay lab/captures/demo.json \
  --out report/out/demo.json --html report/out/demo.html
```

If `dotnet build` ever fails after an SDK update, check `global.json`: it pins
10.0.100 with `rollForward: latestMajor`, so SDK 11 is used locally and SDK 10
is used inside a VM that has it.

## Gaps to close before Phase 2 runs live

- [ ] Create the Windows 11 VM: [vm-setup.md](vm-setup.md)
- [ ] Take `baseline-offline` snapshot: [snapshots.md](snapshots.md)
- [ ] Confirm no guest network adapter and no outbound connections
- [ ] Confirm the repo is reachable from the guest (virtiofs share or copy)
- [ ] Run `sl33p-core --lab-ack --mode plain --protect rw --sleep 30` and hunt it
- [ ] Run one `noaccess` cycle and confirm the hunter wins on metadata alone
