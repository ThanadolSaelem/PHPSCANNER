# PoC lab source notes

Checked 2026-11-04. The Compose image references pin the official Docker Hub manifest-list digest as well as the version tag.

- PHP 8.2.34 Apache tag (affected upstream version): https://hub.docker.com/v2/repositories/library/php/tags/8.2.34-apache
  - Manifest-list digest: `sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86`
- PHP 8.2.35 Apache tag (fixed upstream version): https://hub.docker.com/v2/repositories/library/php/tags/8.2.35-apache
  - Manifest-list digest: `sha256:89e5f7bde208a146519d12100c11e71a1d0119a10703cfc454d1bdca274147ec`
- PHP upstream security release and fixed versions: https://www.php.net/archive/2026.php
- PHP `expose_php` directive and its effect on the `X-Powered-By` header: https://www.php.net/manual/en/ini.core.php
- PHP upstream advisory, CVE-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- PHP upstream advisory, CVE-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CISA alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching

The lab validates passive HTTP identification/version-based screening only. It does not send exploit traffic and cannot validate distro/vendor backports; those require authorized package/runtime evidence from the guest or vendor.
