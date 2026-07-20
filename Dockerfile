ARG BUILDPLATFORM

# Build the manager binary
FROM --platform=${BUILDPLATFORM} docker.io/golang:1.26.5 AS builder
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

FROM alpine:latest

WORKDIR /
COPY --from=builder /builds/manager .
USER 65532:65532
WORKDIR /
ENTRYPOINT ["./manager"]
