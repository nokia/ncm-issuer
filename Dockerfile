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

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

WORKDIR /
COPY --from=builder /builds/manager .
USER 65532:65532
WORKDIR /
ENTRYPOINT ["./manager"]
