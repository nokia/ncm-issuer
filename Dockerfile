# Build the manager binary
FROM golang:1.19.6 AS builder
WORKDIR /

# COPY . ./

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY pkg/cfg pkg/cfg/
COPY pkg/util pkg/util/
COPY pkg/ncmapi pkg/ncmapi/
COPY pkg/provisioner pkg/provisioner/
COPY pkg/controllers pkg/controllers/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 env GO111MODULE=on go build -mod=vendor -o builds/manager main.go


FROM scratch

WORKDIR /
COPY --from=builder /builds/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]