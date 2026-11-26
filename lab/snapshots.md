# Snapshots

The rule is simple: **no run without a snapshot, no revert without evidence
copied out.** Everything here uses session libvirt, matching the host setup.

```bash
V="virsh -c qemu:///session"
VM=sl33p-win11
```

## Naming

| Name | When | Contents |
|---|---|---|
| `baseline-online` | after Windows + drivers, before toolchain | clean OS, NIC present |
| `baseline-offline` | after toolchain, NIC removed, build verified | the lab's starting point |
| `pre-<case>` | immediately before a matrix case or demo | whatever state you were in |
| `post-<case>` | optional, after a case you want to keep | evidence state |

`baseline-offline` is the one you protect. If it is gone, you are rebuilding.

## Create

```bash
$V snapshot-list $VM
$V snapshot-create-as $VM pre-obf-rw \
  --description "before obf_rw case, $(date -Is)" --atomic
```

`--atomic` makes libvirt fail the whole snapshot rather than leave a partial
one. Use it.

## Revert

```bash
$V snapshot-revert $VM baseline-offline
$V start $VM
```

A revert discards the current disk state, including anything you forgot to copy
out. That is both the benefit and the hazard.

## Inspect and clean up

```bash
$V snapshot-info $VM pre-obf-rw
$V snapshot-dumpxml $VM baseline-offline
$V snapshot-delete $VM pre-obf-rw
```

qcow2 internal snapshots grow with changed blocks. Watch the file:

```bash
qemu-img info "$HOME/lab/vms/$VM.qcow2"
qemu-img check "$HOME/lab/vms/$VM.qcow2"
```

If the disk is on the NTFS volume, `qemu-img check` after any hard stop is not
optional.

## What snapshots do not cover

- **The virtiofs share.** It is a live host directory, not part of the qcow2.
  Reverting the VM does not revert `report/out/*.json` or any source edit.
  Copy evidence out before reverting if you want it.
- **The host's copy of the repo.** Same reason.
- **RAM state.** These are disk snapshots. A running VM is shut down first, so
  there is no saved memory image. That is deliberate: the lab is about on-disk
  reproducibility, not about resuming a suspicious process.

## Matrix hygiene

The runner does not snapshot automatically. Snapshotting from inside a run is
how you end up with nested snapshots and a 200 GB qcow2. The discipline is:

```bash
$V snapshot-create-as $VM pre-matrix --atomic
python src/matrix/run.py --core ...
# copy out report/out/*.json and *.html
$V snapshot-revert $VM baseline-offline
```

If a case wedges the guest, see [../docs/kill-switch.md](../docs/kill-switch.md)
before touching anything else.

## Verify a snapshot is usable

A snapshot you have never reverted is a hope, not a backup. Do it once:

```bash
$V snapshot-revert $VM baseline-offline
$V start $VM
# in the guest
dotnet build C:\lab\sl33p\src\core -c Release
```

If that works, the snapshot is real.
