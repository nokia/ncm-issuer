# Installation

## Prerequisites

Prerequisites for using ncm-issuer:

* [NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) release 23 or later,
* [Kubernetes](https://kubernetes.io) version 1.25 - 1.35,
* [cert-manager](https://cert-manager.io/) version 1.0.0 or later,
* Kubernetes container runtime like Docker, containerd or CRI-O,
* [Helm](https://helm.sh/docs/intro/install/) v3.

## Resource requirements

The following resource requirements are based on the default configuration for ncm-issuer:

| Resource Type | Configuration | CPU | Memory | Disk (per node) |
|:--------------|:--------------|:----|:-------|:----------------|
| **Minimum** | Single replica, no sidecar | 400m (0.4 cores) | 500Mi | 500 MB |
| **With sidecar** | Single replica, troubleshooting sidecar enabled | 800m (0.8 cores) | 1000Mi (1 Gi) | 1 GB |
| **High Availability** | Multiple replicas (leader election enabled) | 400m × replicas | 500Mi × replicas | 500 MB + (100 MB × replicas) |

**Container Image Sizes:**
* ncm-issuer: ~18 MB
* ncm-issuer-utils (optional sidecar): ~170 MB

**Note**: These requirements are for the ncm-issuer component only. Additional resources are required for cert-manager, which is a separate dependency. The actual resource consumption may vary based on:
* Number of Issuer/ClusterIssuer resources
* Certificate request frequency
* NCM API response times
* Logging verbosity level

## Installing with Helm

The easiest way to install ncm-issuer in Kubernetes cluster is to use Helm.
The image will be automatically downloaded from public repository.

<figure markdown>
  ![installation](../assets/installation.gif)
</figure>

Add the Helm repository:

  ```bash
  helm repo add nokia https://nokia.github.io/ncm-issuer/charts
  ```

Update your local Helm chart repository cache:

  ```bash
  helm repo update
  ```

Install ncm-issuer using the command:

  ```bash
  helm install \
  ncm-issuer nokia/ncm-issuer \
  --create-namespace --namespace ncm-issuer
  ```

On the other hand, if you did not add Helm repository, but downloaded the packaged version of ncm-issuer use:

  ```bash
  helm install \
  ncm-issuer \
  --create-namespace --namespace ncm-issuer \
  ncm-issuer/charts/ncm-issuer
  ```

## Using own (local or remote) registry

In case you want to use your own registry, just change the value pointing to a specific registry
in the `values.yaml` file in directory that contains Helm files. Then just repeat the steps
mentioned above.

  ```bash
  sed -i "s|docker.io/misiektoja|<your-registry>|g" values.yaml
  ```

!!! note
    Using this command will also change the registry pointing to the image location of sidecar.
    Bear this in mind if you want to use sidecar as well.

However, if you do not know where to get image from, because you cloned the repository
just use the command:

  ```bash
  make docker-build
  ```

or (if you also want to save image)

  ```bash
  make docker-save
  ```

Saved image should appear in the path `./builds/ncm-issuer-images/`.
