#!/usr/bin/env sh
# Lock the fixtures image to the digest your Docker resolved, for a reproducible
# published benchmark. Requires Docker. Edits docker-compose.yml in place.
set -eu
IMG="python:3.13-slim"
docker pull "$IMG" >/dev/null
DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMG")"
[ -n "$DIGEST" ] || { echo "could not resolve digest"; exit 1; }
sed -i.bak "s#image: python:3.13-slim.*#image: ${DIGEST}#" docker-compose.yml
echo "pinned fixtures image -> ${DIGEST}"
