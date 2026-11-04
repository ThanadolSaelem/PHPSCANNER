# Sources & version references

PHP2Shell = CVE-2026-109618 and CVE-2026-109619 (PHP core memory-safety, RCE).

Upstream fixed releases used as the branch cutoffs in `cases.py`:

| Branch | First fixed |
|--------|-------------|
| 8.5    | 8.5.12 |
| 8.4    | 8.4.27 |
| 8.3    | 8.3.36 |
| 8.2    | 8.2.35 |

Branches 8.1 and earlier (incl. 7.4, 5.6) are End-of-Life upstream: no official
fix, though a distro LTS may backport one — which is exactly why an external
banner is only ever "possibly affected" until internal evidence confirms.

Primary references:
- PHP release announcements / security releases (php.net).
- PHP runtime config: `expose_php` (php.net manual, ini.core) and header hiding.
- Distro backport nuance: the observed version number need not reflect a
  backported security fix (e.g. Ubuntu/Debian/RHEL package revisions).

The exact version numbers here follow this repository's PHP2Shell model
(`app/scanner/vuln_rules.py: PHP2SHELL_FIXED`). For production use, always
cross-check the current PHP advisory and your distro/vendor advisory — the
numbers here demonstrate the detection taxonomy, they are not a substitute for
the cloud-provider audit document's version conditions.

Fixture / image provenance: the optional `real-php/` overlay uses official
Docker Library `php:*` images (pin to a digest before relying on them) and an
`ubuntu:24.04` distro-package build for the backport case.
