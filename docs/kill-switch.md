# Kill switch

What to do when a run misbehaves, the VM state is unclear, or you just want the
lab back to a known-good point.

## 1. Stop the process

On the Windows guest:

```powershell
Get-Process sl33p-core -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process sl33p-core -ErrorAction SilentlyContinue   # expect: nothing
```

If the process is wedged in `NOACCESS` on its own stack, it cannot respond —
that is a bug in the core, not a feature. Terminate it.

## 2. Stop the VM

Graceful first, from the Linux host:

```bash
virsh -c qemu:///session shutdown sl33p-win11
```

If it does not shut down within 60 seconds:

```bash
virsh -c qemu:///session destroy sl33p-win11   # hard stop, discards RAM state
```

`destroy` is the correct emergency action. Snapshots are on disk and survive it.

## 3. Revert to the snapshot

```bash
virsh -c qemu:///session snapshot-list sl33p-win11
virsh -c qemu:///session snapshot-revert sl33p-win11 baseline-offline
virsh -c qemu:///session start sl33p-win11
```

`baseline-offline` is taken after the toolchain is installed and the network is
removed. Revert to it after any run that changed system state, installed
anything, or made you unsure.

## 4. Verify isolation

In the guest:

```powershell
Get-NetAdapter | Format-Table Name, Status
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
```

The first command should show no connected adapter in the offline
configuration. The second should be empty (loopback-only services may appear;
investigate anything else).

On the host:

```bash
virsh -c qemu:///session domiflist sl33p-win11
```

Expect no interfaces.

## 5. Preserve evidence before reverting

If the run produced a finding worth keeping, copy the artefacts out first:

```powershell
# guest -> share or clipboard
Copy-Item C:\lab\sl33p\report\out\*.json Z:\evidence\
Copy-Item C:\lab\sl33p\report\out\*.html Z:\evidence\
```

If the VM has no share, take a screenshot of the report and the hunter's stderr,
then revert. A finding you cannot reproduce is not evidence.

## When to burn the VM instead of reverting

Rebuild from scratch if:

- the guest boot is unstable after a snapshot revert;
- the Windows installation was modified outside the documented steps;
- you cannot explain a process, service or scheduled task you did not create;
- the network configuration does not match `lab/snapshots.md`.

The rebuild is cheap: `lab/create-vm.sh`, install, snapshot. That is the point of
keeping the setup as code.

## What the kill switch does not cover

- Host compromise. The lab is not designed to contain a kernel exploit, and
  nothing in this repository runs at ring 0.
- Data exfiltration. There is no network path and nothing to exfiltrate; if you
  add one, this document is out of date and the scope review has failed.
