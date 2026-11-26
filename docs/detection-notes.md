# Detection notes

## Operating model

The hunter is a differ, not a scanner. It takes a baseline snapshot of the
target's regions, then polls. Every rule is anchored to a transition:

- bytes that **became** random,
- protection that **changed**,
- a `NOACCESS` region that **appeared**,
- CPU that **stayed** flat while the above happened.

A static high-entropy region is not interesting. A 64 KiB region that was 4.1
bits/byte at t=0 and 7.99 at t=1, in a process using no CPU, is interesting.

### The baseline problem

This is a design constraint, not a bug: **a detector that first sees the target
after it is already asleep cannot measure an entropy delta.** The baseline would
itself be ciphertext, and D2 would correctly report "no change".

That is why the core has an `--awake` window and why the matrix starts the
hunter on `ready`, not on `asleep`. It models an always-on monitor, which is the
realistic deployment. A hunter launched mid-sleep falls back to D3/D4 (metadata)
and D6 (if the pages are readable) — still useful, but the D2 row becomes a
dash, and the report should say so rather than pretend otherwise.

## Why absolute entropy is the wrong rule

`.NET` heaps, JIT pages, PNGs, zipped resources and TLS buffers all sit near 7.9
bits/byte in perfectly ordinary processes. A rule of "entropy > 7.5" would fire
on Notepad's neighbours and teach nothing.

`D2` therefore requires a rise of at least 1.0 bits/byte from a baseline taken
while the process was awake. The lab payload goes from ~4.2 to ~7.99: a delta of
about 3.8. That is not a threshold that needs tuning; it is a different kind of
signal.

## Rules

### D1 — marker (confidence 0.99)

Scans readable private regions for the 24-byte marker. Evidence: absolute
offsets of up to three hits, hit count, bytes scanned.

- Fires: baseline case, and the wake tick of every encrypted case.
- Misses: while the region is encrypted or unreadable.
- False positives: effectively none, because the marker is a 24-byte literal.
  A detector that hard-codes a marker is not general — this one is honest about
  being format-aware.

### D2 — entropy delta (0.80 / 0.50 / 0.70)

Compares mean 4 KiB block entropy against the baseline for the same region.

| Condition | Confidence |
|---|---|
| delta ≥ 2.0 bits | 0.80 |
| delta ≥ 1.0 bits | 0.50 |
| baseline < 6.0 and current ≥ 7.8 | 0.70 |

Evidence: baseline entropy, current entropy, delta, sample size.

- Misses: `NOACCESS` pages (cannot read), or a payload that was already
  high-entropy before sleeping.
- False positives: a region that legitimately fills with random data while the
  process idles (RNG pools, hash tables). Mitigated by D3/D4 correlation and by
  the control case, not eliminated.

### D3 — protection flip (0.85 / 0.70)

Diffs `VirtualQueryEx` snapshots. A private region that moves to `NOACCESS`
scores 0.85; any other flip to `RX`/`RWX` scores 0.70. Evidence: from/to
protection, region size.

- This is the rule that makes `noaccess` mode a loss for the offence side. It
  needs no read permission at all.
- Misses: a technique that leaves protection untouched (`rw` mode), or a flip
  that happens and reverts between two polls.
- False positives: guard pages and stack growth produce flips; filtering to
  private regions ≥ 4 KiB removes most of them.

### D4 — orphan NOACCESS (0.60)

A committed private `NOACCESS` region that the baseline did not have. Ordinary
processes rarely hold large private `NOACCESS` regions for long.

- Independent of D3: it survives a poll that missed the transition but caught
  the state.
- False positives: `VirtualAlloc(PAGE_NOACCESS)` guards, some allocators,
  deliberate `PROT_NONE` reservations.

### D5 — idle thread (0.35)

`GetProcessTimes` delta < 25 ms across the poll window, while D3 or D4 fired.
It does not stand alone; it raises confidence on an existing signal.

- Evidence: CPU delta in ms, window length.
- Misses: a payload that keeps a spinning thread, or a busy host process.
- False positives: a process that legitimately idles while a worker thread
  touches memory.

### D6 — key recovery (0.99, optional)

The strongest and most limited rule. It looks for a 60-byte structure in a
small private region: 12-byte nonce, 16-byte GCM tag, 32-byte key-shaped blob.
It then tries to decrypt each readable private region with that key and
validates the GCM tag. A successful tag check is proof, not a heuristic.

- Requires `cryptography` (`pip install cryptography`). Without it the rule
  reports `unavailable`, and the matrix records a gap rather than a miss.
- Only works while ciphertext is readable (`rw` / `rx`). In `noaccess` mode the
  hunter cannot read the ciphertext, so D6 cannot run — a limit of the
  technique, not of the detector.
- Format-aware by construction. It knows the header layout because this lab
  defines it. That is why D1–D5 carry the general argument and D6 is the
  closing proof.

## Confidence aggregation

Per region:

```
confidence = 1 - Π (1 - rule_confidence), capped at 0.99
```

Three independent rules at 0.85, 0.60 and 0.35 give 0.961. The cap exists
because a stack of heuristics is not a proof. Findings are sorted by address
then rule, so a report is stable across runs.

The matrix thresholds at 0.6: a region needs either one strong rule or two
moderate ones to count as caught.

## Sampling and its blind spots

- Default interval 250 ms. A transition faster than that can be missed by D3.
  The sleep window is seconds, so this is comfortable for the lab and wrong for
  a real implant that sleeps in milliseconds.
- Per-tick read budget is 16 MiB across at most 256 regions, 256 KiB per
  region. A 2 GB private region is not fully scanned; entropy is sampled.
- `PAGE_GUARD` is treated as unreadable, because reading it would consume the
  guard and alter the target's behaviour. The hunter does not get to change the
  thing it is measuring.

## Expected matrix outcomes

| Case | D1 | D2 | D3 | D4 | D5 | D6 |
|---|---|---|---|---|---|---|
| `baseline_plain_rw` | ✓ | – | – | – | – | – |
| `obf_rw` | – | ✓ | – | – | – | ✓ |
| `obf_noaccess` | – | – | ✓ | ✓ | ✓ | – |
| `obf_rx` | – | ✓ | ✓ | – | – | ✓* |
| `control_notepad` | – | – | – | – | – | – |

\* D6 needs the ciphertext readable and the header found; `rx` satisfies both.

The interesting cells are the dashes: encryption removes D1, `NOACCESS` removes
D2 and D6, and the region is still caught. That is the thesis.

## Cross-OS note (Linux harness)

The Linux core and hunter use `mmap`/`mprotect` and `/proc/<pid>/mem`. Three
measured differences matter:

- **`/proc/pid/mem` reads `PROT_NONE` pages.** With `ptrace_scope=0`, a same-uid
  reader gets the bytes back even though the VMA is `---p`. The hunter still
  honours the protection attribute and treats the region as unreadable, so
  `noaccess` produces the same D3/D4 outcome as on Windows. This is a deliberate
  choice for parity, not a limitation of the OS.
- **Python cannot zeroise a `bytes` object.** The core decrypts into a
  `bytearray`, writes the region and wipes the buffer, but the interpreter may
  retain copies. The C# core decrypts into the protected page and zeroes its
  scratch, so the Windows build has the stronger guarantee.
- **The marker is never a literal.** The first live run found D1 firing on the
  interpreter's own arena: the marker string existed outside the region. Both
  cores now store it XOR-encoded and write it byte-by-byte, so the only copy is
  the one being protected. That is why D1 fires at t≈0.25 s (awake) and then
  not again until the wake tick.

## What the detector does not do

- It does not scan all processes or all memory. One PID, one region at a time.
- It does not write, change protections, suspend threads or inject anything.
- It does not identify a *malware family*. It identifies a behaviour.
- It does not claim to beat an implant that pages its payload out, uses
  per-page keys, or never exposes a readable ciphertext.

Each of those is a candidate for the "what I'd do next" list, not a hidden
assumption.
