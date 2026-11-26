# Demo script: five minutes

Eight steps. Each has a command, a thing to point at, and one sentence to say.
Screenshot points are marked **[shot]**.

Before you start: `baseline-offline` restored, `owasp-bwa` shut down, terminal
font at 14pt or larger, and the HTML report open in a second window.

---

### 0:00 Frame it (20 s)

> "This is a process that encrypts its own memory while it sleeps. The
> interesting part is not the hiding. It's that a read-only detector still
> finds it, and can prove what it was. Everything is one VM, offline, one
> process."

**[shot]** Desktop showing the VM with no network adapter.

### 0:20 Snapshot and scope (20 s)

```bash
virsh -c qemu:///session snapshot-create-as sl33p-win11 pre-demo --atomic
```

> "Snapshot before the run. If anything looks wrong, I revert and the VM is
> gone in ten seconds."

### 0:40 Baseline (40 s)

```powershell
.\sl33p-core.exe --lab-ack --mode plain --protect rw --sleep 40
python src\hunt\sl33p_hunt.py --pid <pid> --duration 15 --html baseline.html
```

> "No obfuscation. The marker is sitting in a private region, and the hunter
> finds it by signature. This is the control."

**[shot]** `D1-marker 0.99`, marker offset.

### 1:20 Encrypted but readable (60 s)

```powershell
.\sl33p-core.exe --lab-ack --mode encrypt --protect rw --awake 20 --sleep 60
python src\hunt\sl33p_hunt.py --pid <pid> --duration 30 --html rw.html
```

> "I start the hunter during the awake window, because that is where the
> baseline lives. Now it's AES-256-GCM in place. A signature scan finds nothing. Entropy jumps
> from about 4.2 to 7.99 bits per byte, and because the pages stay readable,
> the hunter finds the key sitting next to the ciphertext, validates the GCM
> tag, and decrypts the payload. That's not a guess, that's proof."

**[shot]** `D2-entropy` + `D6-key-recovery`, and the decrypted marker evidence.

### 2:20 Encrypted and unreadable (60 s)

```powershell
.\sl33p-core.exe --lab-ack --mode encrypt --protect noaccess --awake 20 --sleep 60
python src\hunt\sl33p_hunt.py --pid <pid> --duration 30 --html noaccess.html
```

> "This is the strong version: the pages are `PAGE_NOACCESS`. The hunter cannot
> read a single byte: signature and entropy both go blind. It still wins,
> because the OS has to tell you the page protection, and a private region that
> flips to no-access while the process burns no CPU is the behaviour, not the
> bytes."

**[shot]** `D3-protection-flip RW → NOACCESS`, `D4-orphan-noaccess`, `D5-idle-thread`.

### 3:20 The matrix (60 s)

```powershell
python src\matrix\run.py --core .\sl33p-core.exe
```

> "Five scenarios, one runner, blind hunts, scored against ground truth the
> hunter never saw. Four techniques, one control. This is the artifact: not
> 'it works', but 'here is what is caught, what is missed, and how long it
> took'."

**[shot]** `report/out/matrix.html`, the caught/missed grid.

### 4:20 Limitations (30 s)

> "It doesn't hide a call stack, it doesn't leave RAM, and it can't stop the key
> from being found. Every one of those is written down, with the detector that
> would be needed before it could be added."

**[shot]** The limitations table in `README.md`.

### 4:50 Close (10 s)

> "Offence simulates one behaviour. Defence measures it. The code and the
> environment are both in the repo, and the VM is one script away."

---

## If something fails

| Failure | Say this | Do this |
|---|---|---|
| `D6 unavailable` | "cryptography isn't installed in this VM; the entropy and protection rules still carry the case." | keep going, or `pip install cryptography` and re-run |
| VM won't start | "the VM is the lab, so I'll show the recorded evidence instead." | run `--replay lab/captures/demo.json` on the host, label it synthetic |
| Hunter finds nothing | "that's a result. A miss is data." | show the empty findings report and the matrix cell it would change |
| Core exits non-zero | "verification failed on wake, which is exactly what the SHA-256 check is for." | capture stderr, revert snapshot |

Never improvise a claim that the matrix does not support. The project's value is
that the numbers are real.
