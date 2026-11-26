# Scope

## Purpose

sl33p exists to demonstrate, measure and explain one narrow technique and its
detection. It is a portfolio artifact and a teaching lab, not a capability.

The claim it supports is precise:

> A detector can identify a dormant, self-encrypted heap region in a cooperating
> process, including cases where the pages are unreadable, and can prove the
> payload when the key remains resident.

It does **not** claim to detect Ekko, Cobalt Strike, or any real implant.

## In scope

- One Windows console process that owns one private memory region.
- Writing a marker into that region, sealing it with AES-256-GCM in place,
  changing that region's protection, waiting, restoring, decrypting, verifying.
- Protection states `PAGE_READWRITE`, `PAGE_NOACCESS`, `PAGE_EXECUTE_READ`.
- Waiting via `Thread.Sleep` or a named event.
- A read-only detector using `OpenProcess`, `VirtualQueryEx`,
  `ReadProcessMemory`, entropy analysis, signature scanning, protection
  diffing and CPU-time correlation.
- A Linux reference harness (`src/core-linux`) that runs the same technique
  with `mmap`/`mprotect`, for verification and demonstration on a Linux host.
  It is still self-process only and follows every constraint below.
- A matrix runner, JSON evidence, and an offline HTML report.
- Documentation of the lab, the threat model and the limits.

## Out of scope, and not negotiable

- Process injection of any kind, remote threads, `CreateRemoteThread`,
  `QueueUserAPC`, thread hijacking.
- Call-stack obfuscation, ROP chains, timer-queue tricks, syscall unhooking.
- EDR/AV bypass, anti-debug, anti-VM, sandbox detection.
- Persistence, scheduled tasks, services, registry run keys.
- C2, sockets, DNS, HTTP, named pipes to anything outside the VM.
- Credential access, token theft, privilege escalation, LSASS anything.
- A kernel driver or a signed vulnerable driver.
- Any target other than the VM the binary runs in.
- Any option that would let the tool point at a process it did not start.

## Why the refusal list is short and absolute

The offence module has to stay boring. The moment it can be pointed at another
process, or configured to evade a specific product, it stops being a lab and
starts being a loader with a README. That would put the author in a worse
position than the one the project is meant to demonstrate, and it would make
every defensive finding in the matrix unfalsifiable.

Requests that would cross those lines get refused with a short explanation, not
a compromise version.

## The "benign payload" rule

The region contains a fixed ASCII marker (`SL33P_LAB_MARKER_9f2c1d7e`) and
numbered filler lines. There is no shellcode, no PE image, no configuration, no
URL, no key material belonging to anyone. The marker is public on purpose: it is
what the detector is allowed to look for.

The AES key is generated at runtime, held only in the process, and destroyed on
exit. It is not a secret worth keeping and is not reused between runs.

## Publication guardrails

If this repository is published:

- README leads with lab-only scope and the limitations section stays.
- `docs/threat-model.md` ships with it; the "what this cannot do" section is not
  optional.
- No screenshots of third-party machines, real hostnames, IP addresses or
  personal data.
- The binary is published as source plus a build command, not as a prebuilt
  executable that someone can run without reading it.
- License and README state that use is limited to systems you own and have
  isolated.

## Review triggers

Stop and re-read this file if a change:

- adds a CLI flag that takes a PID, process name, or path from the user;
- adds a network call;
- adds a second process, thread or module;
- adds "make it stealthier" without an accompanying detector and test;
- makes the key recoverable by the *core* rather than resident by necessity.
