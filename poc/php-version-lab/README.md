# PHP version screening lab for thscan

This lab provides three harmless HTTP targets for validating **passive version screening only**:

Thai-language instructions and the four-outcome audit mapping: [README_TH.md](README_TH.md).

- `php-affected-visible`: upstream PHP 8.2.34, with `X-Powered-By` enabled (`127.0.0.1:8080`).
- `php-patched-visible`: upstream PHP 8.2.35, with `X-Powered-By` enabled (`127.0.0.1:8081`).
- `php-affected-hidden`: upstream PHP 8.2.34, with `expose_php=Off` (`127.0.0.1:8082`). The page contains a `.php` link, so the scanner can identify a PHP signal while the version remains undisclosed.

The PHP images are official Docker Library images pinned by manifest digest. The vulnerable and fixed version boundary follows the PHP security release for CVE-2026-109618 and CVE-2026-109619. This lab does **not** send exploit payloads and must not be treated as proof of code execution or as a production vulnerability assessment.

## Start and verify

From this directory:

```sh
docker compose up -d
docker compose ps
curl -sSI http://127.0.0.1:8080/ | grep -i '^X-Powered-By:'
curl -sSI http://127.0.0.1:8081/ | grep -i '^X-Powered-By:'
curl -sSI http://127.0.0.1:8082/ | grep -i '^X-Powered-By:' || true
```

The first two targets should disclose PHP versions 8.2.34 and 8.2.35 respectively. The third should not disclose `X-Powered-By`; its response body still links to `/health.php` to exercise the scanner's “PHP present, version unknown” path.

To verify the actual runtimes from inside the containers:

```sh
docker compose exec php-affected-visible php -r 'echo PHP_VERSION, "\n";'
docker compose exec php-patched-visible php -r 'echo PHP_VERSION, "\n";'
docker compose exec php-affected-hidden php -r 'echo PHP_VERSION, "\n";'
```

## Scan with thscan

Run thscan on the same host as Docker. If thscan itself runs in a container, it must be able to reach host-loopback published ports; the repository's Linux Compose setup uses host networking. On Docker Desktop for macOS/Windows, run thscan directly with `run.sh` or `run.bat` as documented in the main README.

In thscan, choose **Fast scan**, target `127.0.0.1`, and custom ports `8080,8081,8082`. Do not enable RCE Verify or LAN fingerprinting for this version-screening exercise. If scope enforcement is enabled, use a separate, temporary local lab configuration that permits only `127.0.0.1/32`; do not widen a production/provider scan scope for this test.

Expected interpretation:

- Port 8080: PHP 8.2.34 is below the upstream 8.2.35 fix and should appear as a version-based affected candidate.
- Port 8081: PHP 8.2.35 is the upstream fixed release for this branch.
- Port 8082: PHP is detectable from the `.php` reference, but the exact version cannot be concluded from the HTTP response and must remain “unable to confirm” rather than being treated as safe.

These outcomes validate the external screening path only. They do not validate distributor backports: a package can retain an older-looking version string while containing a vendor patch. That requires evidence from the authorized guest/package inventory or vendor advisory.

## Stop

```sh
docker compose down
```

All ports are bound to `127.0.0.1`; do not change them to `0.0.0.0` or expose this intentionally affected runtime to a LAN, cloud VPC, or the public Internet.
