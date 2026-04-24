#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Build & push the Trivy Image Scanner container to a private (or public)
# Docker registry. All sensitive values come from environment variables, so
# this script is safe to commit to source control.
#
# Usage:
#   REGISTRY=registry.example.com \
#   NAMESPACE=team-name \
#   IMAGE=trivy-scan-app \
#   VERSION=1.0.0 \
#       ./scripts/push.sh
#
# Or put the values in a local `.env` file (gitignored) and source it:
#   set -a; . ./.env; set +a; ./scripts/push.sh
#
# All four variables are required. Push will tag both <VERSION> and `latest`.
# -----------------------------------------------------------------------------
set -euo pipefail

: "${REGISTRY:?REGISTRY env var is required (e.g. registry.example.com)}"
: "${NAMESPACE:?NAMESPACE env var is required (e.g. team-name)}"
: "${IMAGE:?IMAGE env var is required (e.g. trivy-scan-app)}"
: "${VERSION:?VERSION env var is required (e.g. 1.0.0)}"

# Strip any accidental scheme/trailing-slash from REGISTRY
REGISTRY="${REGISTRY#https://}"
REGISTRY="${REGISTRY#http://}"
REGISTRY="${REGISTRY%/}"

FULL="${REGISTRY}/${NAMESPACE}/${IMAGE}"

echo "==> Building ${FULL}:${VERSION}  (also tagging :latest)"
docker build \
    -t "${FULL}:${VERSION}" \
    -t "${FULL}:latest" \
    .

echo "==> Pushing ${FULL}:${VERSION}"
docker push "${FULL}:${VERSION}"

echo "==> Pushing ${FULL}:latest"
docker push "${FULL}:latest"

echo
echo "Done. Pull with:"
echo "  docker pull ${FULL}:${VERSION}"
echo "  docker pull ${FULL}:latest"
