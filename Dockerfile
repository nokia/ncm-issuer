ARG BUILDPLATFORM

# Build the manager binary
FROM --platform=${BUILDPLATFORM} docker.io/golang:1.26.8@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS builder
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
WORKDIR /

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY pkg/ pkg/

# Build
RUN echo "Building on ${BUILDPLATFORM}, target GOOS=${TARGETOS} GOARCH=${TARGETARCH}" && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /builds/manager main.go

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Alpine publishes package fixes faster than it rebuilds this image, so the digest above can pin a
# build whose OS packages already have a fix waiting in the repository. Applying the upgrades keeps
# the published image free of findings a user can act on, at the cost of the package set being
# resolved at build time rather than fixed by the digest alone.
RUN apk --no-cache upgrade

WORKDIR /
COPY --from=builder /builds/manager .
USER 65532:65532
WORKDIR /
ENTRYPOINT ["./manager"]
