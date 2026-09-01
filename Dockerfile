# Copyright The prometheus-mcp-fleet Authors.
# SPDX-License-Identifier: Apache-2.0
#
# One Dockerfile builds both components. Select with --build-arg COMPONENT=hub|spoke.
#
# The build is static (CGO_ENABLED=0) and reproducible: -trimpath removes local
# paths and SOURCE_DATE_EPOCH pins the embedded build date, so rebuilding the
# same commit on fresh base images produces byte-identical binaries. That is
# what makes the weekly CVE rebuild verifiable rather than a leap of faith.

# ---- build -----------------------------------------------------------------
FROM mirror.gcr.io/library/golang:1.27-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS build

ARG COMPONENT
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_DATE_EPOCH=0
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Dependencies first so an unrelated source edit does not invalidate the layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "$COMPONENT" || { echo "COMPONENT build-arg is required (hub|spoke)"; exit 1; }; \
    BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"; \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/jacoknapp/prometheus-mcp-fleet/internal/version.Version=${VERSION} \
        -X github.com/jacoknapp/prometheus-mcp-fleet/internal/version.Commit=${COMMIT} \
        -X github.com/jacoknapp/prometheus-mcp-fleet/internal/version.Date=${BUILD_DATE}" \
      -o "/out/${COMPONENT}" "./cmd/${COMPONENT}"

# ---- runtime ---------------------------------------------------------------
# distroless static rather than scratch: we want CA certificates, tzdata and a
# real nonroot passwd entry. Not Chainguard's free tier, which only publishes
# :latest and so cannot be pinned for a reproducible weekly rebuild.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG COMPONENT
ARG VERSION
ARG COMMIT

LABEL org.opencontainers.image.title="prometheus-mcp-fleet-${COMPONENT}" \
      org.opencontainers.image.description="MCP ${COMPONENT} for fleet-wide Prometheus access" \
      org.opencontainers.image.source="https://github.com/jacoknapp/prometheus-mcp-fleet" \
      org.opencontainers.image.documentation="https://github.com/jacoknapp/prometheus-mcp-fleet/tree/main/docs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.vendor="jacoknapp"

# Installed under its component name, not as "app".
#
# The documented way to administer a hub is
# `kubectl exec deploy/pmf-hub -- hub enroll create ...`, and the binary has to
# be called `hub` for that to resolve. It was called `app`, so every such
# command in the documentation failed with "executable file not found in $PATH".
COPY --from=build "/out/${COMPONENT}" "/usr/local/bin/${COMPONENT}"

# The same binary again at a fixed path, because ENTRYPOINT's exec form cannot
# expand a build argument and this image has no shell to expand one. The chart
# therefore starts /usr/local/bin/app without knowing the component, while an
# operator still types the component name on an exec.
COPY --from=build "/out/${COMPONENT}" /usr/local/bin/app

# 65532 is distroless' `nonroot`. The charts set the same value explicitly.
USER 65532:65532
WORKDIR /

ENTRYPOINT ["/usr/local/bin/app"]
