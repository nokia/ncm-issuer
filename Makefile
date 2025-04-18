APP_NAME ?= ncm-issuer
APP_VERSION ?= $(shell grep -m1 chartVersion main.go | cut -d '"' -f2)
BUILD_VERSION ?= $(shell grep -m1 imageVersion main.go | cut -d '"' -f2)
IMG ?= ${APP_NAME}:${BUILD_VERSION}
ENVTEST_K8S_VERSION ?= 1.29

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
	go vet ./... > govet-report.out

vendor:
	GOWORK=off go mod vendor

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
test: manifests generate fmt vet envtest ## Run tests
	KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -coverprofile coverage.out -v > coverage_report.out
	KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -json > report.json

lint: golangci-lint ## Run golangci-lint & yamllint
	"$(GOLANGCI_LINT)" run

lint-fix: golangci-lint ## Run golangci-lint and fix issues
	"$(GOLANGCI_LINT)" run --fix

##@ Build

build: vendor generate fmt vet ## Build manager binary
	go build -mod=vendor -o bin/manager main.go

run: manifests generate fmt vet ## Run controller locally
	go run ./main.go

docker-push: ## Push docker image
	docker push "${IMG}"

docker-build:
	docker build . -t "${IMG}"

docker-save: docker-build
	rm -rf "builds/$(APP_NAME)-images" && mkdir -p "builds/$(APP_NAME)-images"
	docker save "${IMG}" | gzip > "builds/$(APP_NAME)-images/${IMG}.tgz"

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

## Tool Versions
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.15.0
ENVTEST_VERSION ?= release-0.15
GOLANGCI_LINT_VERSION ?= v1.64.8

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
kustomize: $(KUSTOMIZE)
$(KUSTOMIZE): $(LOCALBIN)
	echo "Installing kustomize into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

controller-gen: $(CONTROLLER_GEN)
$(CONTROLLER_GEN): $(LOCALBIN)
	echo "Installing controller-gen into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

envtest: $(ENVTEST)
$(ENVTEST): $(LOCALBIN)
	echo "Installing envtest into $(LOCALBIN)"
	GOBIN="$(abspath $(LOCALBIN))" go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)

golangci-lint: $(GOLANGCI_LINT)
$(GOLANGCI_LINT): $(LOCALBIN)
	mkdir -p "$(LOCALBIN)"
	if [ ! -f "$(GOLANGCI_LINT)" ]; then \
		echo "Installing golangci-lint into $(LOCALBIN)"; \
		GOBIN="$(abspath $(LOCALBIN))" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}; \
	fi

pack-app: docker-save
	rm -rf "builds/$(APP_NAME)" && mkdir -p "builds/$(APP_NAME)/images" "builds/$(APP_NAME)/charts/$(APP_NAME)/"
	cp -rf builds/$(APP_NAME)-images/*.tgz "builds/$(APP_NAME)/images/"
	cp -rf helm/* "builds/$(APP_NAME)/charts/$(APP_NAME)/"
	cp -rf release_notes.txt "builds/$(APP_NAME)/"
	cd builds && tar czvf "../${APP_NAME}-${APP_VERSION}-${BUILD_VERSION}.tar.gz" "$(APP_NAME)"

clean:
	rm -rf builds
	rm -rf ncm-issuer*.tar.gz
