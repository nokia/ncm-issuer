# Build the manager binary
FROM golang:1.22.10 AS builder
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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o builds/manager main.go


FROM scratch

WORKDIR /
COPY --from=builder /builds/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
