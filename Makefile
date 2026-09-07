APP_NAME ?= ncm-issuer
APP_VERSION ?= $(shell grep -m1 chartVersion main.go | cut -d '"' -f2)
BUILD_VERSION ?= $(shell grep -m1 imageVersion main.go | cut -d '"' -f2)
IMG ?= ${APP_NAME}:${BUILD_VERSION}
REGISTRY ?= ghcr.io/nokia
REMOTE_IMG := ${REGISTRY}/${APP_NAME}:${BUILD_VERSION}
UTILS_NAME ?= ncm-issuer-utils
UTILS_IMG ?= ${UTILS_NAME}:${BUILD_VERSION}
UTILS_REMOTE_IMG := ${REGISTRY}/${UTILS_NAME}:${BUILD_VERSION}
UTILS_CONTEXT ?= ncm-issuer-utils/docker
PLATFORM ?= linux/amd64
ENVTEST_K8S_VERSION ?= 1.36.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS := -ec

all: build

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./pkg/controllers/..." paths="./api/..." output:crd:artifacts:config=config/crd/bases

generate: controller-gen ## Generate deepcopy methods
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

fmt: ## Run go fmt
	go fmt ./...

vet: ## Run go vet
	go vet ./...

# Keyed on the file "go mod vendor" rewrites rather than on the vendor/ directory, which make
# would treat as up to date for ever once it exists, leaving a stale vendor tree behind after a
# dependency bump.
vendor: vendor/modules.txt
vendor/modules.txt: go.mod go.sum
	GOWORK=off go mod vendor

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
test: manifests generate fmt vet envtest ## Run tests
	KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -coverprofile coverage.out

lint: golangci-lint ## Run golangci-lint
	"$(GOLANGCI_LINT)" run

lint-fix: golangci-lint ## Run golangci-lint and fix issues
	"$(GOLANGCI_LINT)" run --fix

lint-config: golangci-lint ## Verify .golangci.yml against the linter's own schema
	"$(GOLANGCI_LINT)" config verify

# actionlint automatically pipes every workflow "run:" script through shellcheck
# when shellcheck is present (it is on CI). The existing e2e workflows have many
# pre-existing shellcheck findings, so "-shellcheck=" turns that pass off and we
# enforce only actionlint's own checks for now. Remove the flag to also lint the
# shell scripts once they have been cleaned up.
lint-actions: actionlint ## Lint GitHub Actions workflows with actionlint
	"$(ACTIONLINT)" -shellcheck=

# A mutable tag such as @v4 can be repointed at any commit, so a pinned SHA is the only immutable
# way to reference a third-party action. "--no-api" checks the reference shape offline, which needs
# no GitHub token and cannot be rate limited. Run "pinact run" to pin anything this reports.
lint-actions-pinned: pinact ## Verify GitHub Actions are pinned to commit SHAs
	"$(PINACT)" run --check --no-api --fix=false

# govulncheck resolves modules itself and does not read vendor/, so -mod=mod keeps it working in a
# tree where "make build" has already vendored. It reports only vulnerabilities on a code path the
# binary can actually reach, so a finding here is worth acting on.
vuln: govulncheck ## Report known vulnerabilities reachable from this module
	GOFLAGS=-mod=mod "$(GOVULNCHECK)" ./...

check-version: ## Verify the version literals in the code, the chart and the release notes agree
	./hack/version.sh check

set-version: ## Set the version everywhere, as in "make set-version VERSION=1.2.4"
	@test -n "$(VERSION)" || { echo 'usage: make set-version VERSION=1.2.4' >&2; exit 1; }
	./hack/version.sh set "$(VERSION)"

check-notices: ## Verify THIRD_PARTY_NOTICES.md matches the direct dependencies in go.mod
	./hack/notices.sh check

##@ Build

build: vendor generate fmt vet ## Build manager binary
	go build -mod=vendor -o bin/manager main.go

run: manifests generate fmt vet ## Run controller locally
	go run ./main.go

docker-push: ## Push docker image
	docker push "${IMG}"

define DOCKER_ERROR_MESSAGE
Docker CLI not found. Please install Docker for your system.
Official website: https://docs.docker.com/get-docker/
endef

define BUILDX_ERROR_MESSAGE
ERROR: Docker Buildx plugin not found or not working.

Please ensure Docker Buildx is installed and configured for your environment:
  - For Docker Desktop (Mac/Windows/Linux): Buildx is usually included, ensure your Docker Desktop is up to date.
  - For manual Docker Engine installs on Linux (e.g. Rocky, Ubuntu): you might need to install the 'docker-buildx-plugin'.
    Examples: 'sudo apt-get install docker-buildx-plugin' (Debian/Ubuntu)
              'sudo dnf install docker-buildx-plugin' (Fedora/Rocky)
  - For Colima/Lima on macOS with Docker CLI installed via Homebrew: install with: 'brew install docker-buildx'
  - For GitHub Actions CI: use 'docker/setup-buildx-action@v3' in your workflow YAML.

After installation or configuration changes, you might need to:
  - Restart your terminal session.
  - Restart the Docker daemon or Colima.

You can verify your Buildx setup by running: 'docker buildx version'
If issues persist, consult the Docker and Buildx documentation.
endef

HAS_DOCKER := $(shell command -v docker 2> /dev/null)
ifeq ($(HAS_DOCKER),)
HAS_BUILDX := false
else
HAS_BUILDX := $(shell docker buildx version > /dev/null 2>&1 && echo true || echo false)
endif

check-buildx:
ifeq ($(HAS_DOCKER),)
	$(error $(DOCKER_ERROR_MESSAGE))
endif
ifeq ($(HAS_BUILDX),false)
	$(error $(BUILDX_ERROR_MESSAGE))
endif

docker-build: check-buildx
	docker buildx build --platform ${PLATFORM} . -t "${REMOTE_IMG}" --load --progress=plain
	docker tag ${REMOTE_IMG} ${IMG}

docker-save: docker-build
	rm -rf "builds/$(APP_NAME)-images" && mkdir -p "builds/$(APP_NAME)-images"
	docker save "${REMOTE_IMG}" "${IMG}" | gzip > "builds/$(APP_NAME)-images/${APP_NAME}-${BUILD_VERSION}.tgz"

docker-build-utils: check-buildx ## Build troubleshooting sidecar (utils) image
	docker buildx build --platform ${PLATFORM} ${UTILS_CONTEXT} -t "${UTILS_REMOTE_IMG}" --load --progress=plain
	docker tag ${UTILS_REMOTE_IMG} ${UTILS_IMG}

docker-push-utils: ## Push troubleshooting sidecar (utils) image
	docker push "${UTILS_IMG}"

docker-save-utils: docker-build-utils ## Build and save troubleshooting sidecar (utils) image tarball
	rm -rf "builds/$(UTILS_NAME)-images" && mkdir -p "builds/$(UTILS_NAME)-images"
	docker save "${UTILS_REMOTE_IMG}" "${UTILS_IMG}" | gzip > "builds/$(UTILS_NAME)-images/${UTILS_NAME}-${BUILD_VERSION}.tgz"

##@ Deployment

install: manifests kustomize ## Install CRDs
	"$(KUSTOMIZE)" build config/crd | kubectl apply -f -

uninstall: manifests kustomize ## Uninstall CRDs
	"$(KUSTOMIZE)" build config/crd | kubectl delete -f -

deploy: manifests kustomize ## Deploy controller
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | kubectl apply -f -

undeploy: ## Undeploy controller
	"$(KUSTOMIZE)" build config/default | kubectl delete -f -

##@ Build dependencies

## Location to install dependencies to
# LOCALBIN ?= $(shell pwd)/bin
LOCALBIN ?= bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
ACTIONLINT ?= $(LOCALBIN)/actionlint
PINACT ?= $(LOCALBIN)/pinact
GOVULNCHECK ?= $(LOCALBIN)/govulncheck

## Tool Versions
KUSTOMIZE_VERSION           ?= v5.6.0
CONTROLLER_TOOLS_VERSION    ?= v0.19.0
ENVTEST_VERSION             ?= release-0.24
GOLANGCI_LINT_VERSION       ?= v2.13.2
ACTIONLINT_VERSION          ?= v1.7.12
PINACT_VERSION              ?= v4.1.1
GOVULNCHECK_VERSION         ?= v1.7.0

# Each stamp file name carries the version it was installed for, so bumping a tool version
# reinstalls the binary instead of leaving an older one in place. $(LOCALBIN) is an order-only
# prerequisite because installing any one tool updates the directory mtime, which would
# otherwise invalidate every other tool's stamp.
KUSTOMIZE_STAMP      = $(LOCALBIN)/.kustomize-$(KUSTOMIZE_VERSION).stamp
CONTROLLER_GEN_STAMP = $(LOCALBIN)/.controller-gen-$(CONTROLLER_TOOLS_VERSION).stamp
ENVTEST_STAMP        = $(LOCALBIN)/.setup-envtest-$(ENVTEST_VERSION).stamp
GOLANGCI_LINT_STAMP  = $(LOCALBIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION).stamp
ACTIONLINT_STAMP     = $(LOCALBIN)/.actionlint-$(ACTIONLINT_VERSION).stamp
PINACT_STAMP         = $(LOCALBIN)/.pinact-$(PINACT_VERSION).stamp
GOVULNCHECK_STAMP    = $(LOCALBIN)/.govulncheck-$(GOVULNCHECK_VERSION).stamp

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
kustomize: $(KUSTOMIZE_STAMP)
$(KUSTOMIZE_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing kustomize $(KUSTOMIZE_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)
	touch "$@"

controller-gen: $(CONTROLLER_GEN_STAMP)
$(CONTROLLER_GEN_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing controller-gen $(CONTROLLER_TOOLS_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
	touch "$@"

envtest: $(ENVTEST_STAMP)
$(ENVTEST_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing envtest $(ENVTEST_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
	touch "$@"

golangci-lint: $(GOLANGCI_LINT_STAMP)
$(GOLANGCI_LINT_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	touch "$@"

actionlint: $(ACTIONLINT_STAMP)
$(ACTIONLINT_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing actionlint $(ACTIONLINT_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	touch "$@"

pinact: $(PINACT_STAMP)
$(PINACT_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing pinact $(PINACT_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install github.com/suzuki-shunsuke/pinact/v4/cmd/pinact@$(PINACT_VERSION)
	touch "$@"

govulncheck: $(GOVULNCHECK_STAMP)
$(GOVULNCHECK_STAMP): | $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	echo "Installing govulncheck $(GOVULNCHECK_VERSION) into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	touch "$@"

pack-app: docker-save
	rm -rf "builds/$(APP_NAME)" && mkdir -p "builds/$(APP_NAME)/images" "builds/$(APP_NAME)/charts/$(APP_NAME)/"
	cp -rf builds/$(APP_NAME)-images/*.tgz "builds/$(APP_NAME)/images/"
	cp -rf helm/* "builds/$(APP_NAME)/charts/$(APP_NAME)/"
	cp -rf RELEASE_NOTES.md "builds/$(APP_NAME)/"
	cp -rf README.md "builds/$(APP_NAME)/"
	cd builds && tar czvf "../${APP_NAME}-${APP_VERSION}-${BUILD_VERSION}.tar.gz" "$(APP_NAME)"

clean:
	rm -rf builds
	rm -rf ncm-issuer*.tar.gz
