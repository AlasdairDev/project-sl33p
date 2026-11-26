# Security policy

sl33p is a lab-only artifact. It simulates one behaviour against one process
that it starts itself, and pairs it with a read-only detector. It is not a tool
for use against systems you do not own or have written permission to test.

## Scope

In scope for this repository:

- the C# core and its Linux reference build
- the Python hunter, rules, and reporting
- the matrix runner and its cases
- the lab documentation

Out of scope, permanently: process injection, remote threads,
persistence, C2, credential access, anti-debug/anti-VM, kernel components, or
any option that points the tool at a process it did not start. Requests to add
those are declined; see `docs/scope.md`.

## Reporting a problem

Open an issue for:

- a bug that makes the lab fail (build error, crash, wrong verification)
- a false positive or false negative in the detector, with the case and evidence
- a documentation error

Do not open an issue asking for evasion improvements. That is not a flaw in this
project; it is a different project.

Please do not include third-party data, credentials, or captures from machines
you do not own.
