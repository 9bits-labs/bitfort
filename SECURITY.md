# Security policy

This file states how to report a vulnerability in BitFort and what 9bits LLC commits to in
return. It follows the [disclosure policy](https://bitfort.dev/docs/disclosure), which also
covers the website and the other services 9bits runs for BitFort. If the two differ, the
disclosure policy applies.

## Report a vulnerability

Write to [security@bitfort.dev](mailto:security@bitfort.dev). Do not open a public issue, pull
request or discussion for a vulnerability.

Include:

- the output of `bitfort --version`, or the commit you built;
- your platform;
- the steps that reproduce the problem;
- what an attacker gains.

Do not send real secrets or private keys. A vault made with a throwaway identity is enough.

## Scope

- The `bitfort` binary and the source code in this repository.
- The on-disk format: `keys.json`, `chain.json` and `vault.enc`, and their signatures, as
  [`docs/FORMAT.md`](docs/FORMAT.md) specifies them.

What the [threat model](docs/SPEC.md#2-threat-model) lists as not defended, such as a secret
read from a running process or a value already in Git history, is a design decision, not a
vulnerability. Report a problem in the website or in another 9bits service to the same address.

## What 9bits commits to

- An acknowledgement within 3 business days.
- A status update, with an assessment, within 10 business days.
- A fix and a public advisory within 90 days of the report. If a fix needs more time, 9bits
  agrees a new date with you before the 90 days end.

9bits credits you in the advisory if you want it. There is no bug bounty.

Advisories are published in the release notes and as GitHub security advisories on this
repository.

## Safe harbor

9bits takes no legal action against research done in good faith under this policy. Good faith
means that you test only your own installs, that you do not access, change or destroy other
people's data, that you do not degrade the website or the other services 9bits runs, and that
you give 9bits the time above before you disclose.
