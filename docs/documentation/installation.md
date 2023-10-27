# Installation

### Prerequisites

Prerequisites for using ncm-issuer:

* [NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) release 21 or later,
* [Kubernetes](https://kubernetes.io) version 1.18 - 1.27,
* [cert-manager](https://cert-manager.io/) version 1.0.0 or later,
* [Docker](https://docs.docker.com/engine/install/) version 20.10.0 or later,
* [Helm](https://helm.sh/docs/intro/install/) v3.

!!! note
    Install docker-re instead of default if you are using CentOS, RedHat or Fedora!

### Installing with Helm

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
