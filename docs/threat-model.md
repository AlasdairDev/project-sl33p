# Threat model

Short by design. The useful output of this document is the list of things the
project cannot do, and the controls that keep it that way.

## Assets

| Asset | Why it matters |
|---|---|
| The VM and its snapshots | The only place the code runs; corruption costs a rebuild |
| The host (Aurora DX) and its data | Never a target; the VM is the boundary |
| The repository's credibility | A security project that overclaims is worse than no project |
| The author's name on it | Published artifact, attributable |

## Actors

| Actor | Capability | Intent |
|---|---|---|
| The author | Full control of host and VM | Learn, measure, publish |
| A curious reader | Has the source, not the VM | Decide whether it is a loader |
| A recruiter / reviewer | Reads README first, may run nothing | Judge rigour, not exploits |
| A careless copier | Runs binaries without reading | Could point it at the wrong machine |

## Boundaries

```
host (Aurora DX) ── libvirt ──▶ VM (Windows 11, offline)
                                    │
                                    ├── core process  ──┐
                                    └── hunter process ─┴─ same user, same VM
```

- No network path out of the VM. No interface at all in the lab configuration
  (or a host-only network with forwarding disabled, if a share is needed).
- The hunter opens one process read-only. It never writes memory, never creates
  a thread, never changes a protection.
- No privilege boundary is crossed: core and hunter run at the same integrity
  level as the same user.

## Abuse cases and controls

| Abuse case | Control | Residual risk |
|---|---|---|
| Repo repurposed as an evasion component | No target argument, no config file, fixed 64 KiB region, marker-only payload, `--lab-ack` required, publication guardrails in `scope.md` | Someone could re-implement the same 200 lines; they would not need this repo |
| Hunter aimed at a real process | PID is required and caller-supplied; refuses PID 0/4 and itself; read-only | A user can still point it at any process they can open; it only reads and reports |
| Accidental damage to the host | Everything runs in the VM; no host binaries, no root, session libvirt only | A misconfigured share could expose the repo to the VM; share is read-write by design for the dev loop |
| False accusation from the detector | FP measurement against control apps; confidence, not verdicts; every finding carries evidence | High-entropy .NET heaps remain the main source of noise |
| Overclaiming in the write-up | README states the technique covered and the one excluded; matrix is the only source of claims | A reader may still skim |

## The uncomfortable finding, stated plainly

The core's AES key has to exist in memory while the payload is encrypted. D6
finds a key-shaped blob, validates the GCM tag and decrypts the region. That is
not a flaw to patch away in this design; it is the reason the project is
interesting.

If a future version tried to fix it — key wrapping, key in a different process,
key derived and destroyed — each of those would be a new offensive capability
and would need its own detector, test and scope review. None are planned.

## What this project cannot do

- It cannot hide a call stack. It waits in a normal blocking call.
- It cannot survive a defender reading the VAD or the handle table.
- It cannot defeat a scanner that is allowed to change page protections and
  read the result; it only makes that harder.
- It cannot run without leaving a private `NOACCESS` region in `noaccess` mode.
- It cannot prevent the key from being recovered when the ciphertext is
  readable.

## Non-claims

No part of this repository is a claim about any commercial product, any real
malware family, or any EDR's detection rate. The matrix describes this lab,
these rules, this VM.
