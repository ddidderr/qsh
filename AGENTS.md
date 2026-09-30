# Instructions for coding agents

## Security reviews

Before any security review or security fix, read `THREAT_MODEL.md` and follow
its "Rules for reviews". In short:

- A security finding must name an in-scope actor and the boundary it crosses.
  Everything else is a hardening idea: list it separately and do not
  implement it unasked.
- Do not re-report the decided trade-offs listed there unless you have a new
  fact that changes the analysis.
- Prefer the smallest fix that removes the cause. Check any new file, lock,
  thread, queue, or protocol field against local users and authenticated
  clients.
- A review with no in-scope findings is finished.

## Checks

`just check` runs the core CI checks: formatting, pedantic Clippy with
warnings as errors, and the test suite. CI additionally runs root-only and
delegated-cgroup tests, the MSRV build, workflow linting, and a dependency
audit.
