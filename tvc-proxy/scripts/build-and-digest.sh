#!/usr/bin/env bash
# Build the TVC proxy image and compute the digests needed for tvc-deploy.json.
#
# Usage:
#   ./scripts/build-and-digest.sh [image-tag]
#
# Outputs:
#   IMAGE_DIGEST  — sha256 of the container image (put in pivotContainerImageUrl)
#   PIVOT_DIGEST  — sha256 of /usr/local/bin/node inside the image (expectedPivotDigest)
#
# Both values are required in tvc-deploy.json for attestation.

set -euo pipefail

IMAGE="${1:-nanoclaw-tvc-proxy:latest}"
CONTAINER_NAME="tvc-proxy-digest-extract-$$"

echo "==> Building image: $IMAGE"
docker build -t "$IMAGE" "$(dirname "$0")/.."

echo ""
echo "==> Image digest:"
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null \
  || docker inspect --format='{{.Id}}' "$IMAGE")
echo "    $IMAGE_DIGEST"

echo ""
echo "==> Extracting pivot (/usr/local/bin/node) digest..."
docker create --name "$CONTAINER_NAME" "$IMAGE" /bin/true >/dev/null
docker cp "$CONTAINER_NAME:/usr/local/bin/node" /tmp/tvc-node-binary 2>/dev/null
docker rm "$CONTAINER_NAME" >/dev/null
PIVOT_DIGEST=$(sha256sum /tmp/tvc-node-binary | awk '{print $1}')
rm /tmp/tvc-node-binary
echo "    $PIVOT_DIGEST"

echo ""
echo "==> Add to tvc-deploy.json:"
echo "    \"pivotContainerImageUrl\": \"<registry>/<repo>:latest@${IMAGE_DIGEST##*@}\","
echo "    \"expectedPivotDigest\":     \"$PIVOT_DIGEST\""
