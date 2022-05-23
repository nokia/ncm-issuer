<p align="center">
<a href="https://github.com/nokia/ncm-issuer/actions">
<img alt="Tests Status" src="https://github.com/nokia/ncm-issuer/workflows/Tests/badge.svg"/>
</a>
	
 <a href="https://goreportcard.com/report/github.com/nokia/ncm-issuer">
 <img alt="Tests Status" src="https://goreportcard.com/badge/github.com/nokia/ncm-issuer"/>
 </a>

 </p>
 <p align="center">
 <img src="https://i.postimg.cc/2SjTLZ8H/render1653315525910.gif"/>
</p>

# NCM Issuer
NCM Issuer cert-manager plugin allows to integrate with [Nokia Netguard Certificate Manager (NCM)](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) PKI system.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## Requirements
### To build:

- **[Golang](https://go.dev/doc/install)** 1.16.15
- **[Make](https://www.gnu.org/software/make/)**
- **[Docker](https://docs.docker.com/engine/install/)**  >= 20.10.0
> **IMPORTANT:** if you use CentOS/RedHat/Fedora do not use the default one, but install docker-ce

### To use:
- **[NCM 21 release](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)** (or higher)
- **[kubernetes](https://kubernetes.io/)** 1.18-1.21
- **[cert-manager](https://cert-manager.io/docs/installation/)** >= 1.0.0
- **[Helm](https://helm.sh/docs/intro/install/)** v3

## Build from source
Building process generates a docker image that can be loaded at target machine.

1. Download the source code
2. Vendor dependencies
   ```
   $ go mod vendor
   ```
4. Create an image
   ```
   $ make docker_build_img
   ```
6. Save the image
   ```
   $ make save
   ```

The image of NCM Issuer will be saved in ./builds/ncm-issuer-images/ directory.

## Installation
NCM Issuer uses Helm chart in installation process. You can read more about Helm [here](https://helm.sh/).

1. Load an image with NCM Issuer
   ```
   $ docker load -i IMAGE_NAME
   ```
2. Create a namespace for NCM Issuer resources
   ```
   $ kubectl create namespace ncm-issuer
   ```
3. Install package using Helm
   ```
   $ helm install -n ncm-issuer ncm-issuer /helm/.
   ```

To check if the package has been installed properly type:
```
$ helm list -A | grep -i ncm-issuer
```

Output of this command should look like this:
```
ncm-issuer ncm-issuer 1 2022-04-12 17:36:12.120909878 +0200 CEST deployed ncm-issuer-1.0.0 1.0.1
```

Great! Everything is working right now!

## Configuration
NCM Issuer requires to create some k8s secrets with credentials to NCM REST API and TLS client configuration.

### NCM REST API credentials
```
$ kubectl create secret generic SECRET_NAME -n NAMESPACE --from-literal=username=USERNAME --from-literal=usrPassword=PASSWORD
```

### TLS without client auth
```
$ kubectl create -n NAMESPACE secret generic SECRET_NAME --from-file=cacert=CA_FOR_REST_API.pem
```

### TLS with client auth
```
$ kubectl create -n NAMESPACE secret generic SECRET_NAME --from-file=cacert=CA_FOR_REST_API.pem --from-file=key=CLIENT_AUTH_PKEY.pem --from-file=cert=CLIENT_AUTH_CERT.pem
```


You can check if the secret has been properly created by running this command:
```
$ kubectl -n NAMESPACE describe secrets SECRET_NAME
```

## Usage
NCM Issuer extends [cert-manager](https://cert-manager.io/) functionalities, but way of usage stays the same. There are additional fields in .yaml file (Issuer definition) that are needed to be filled.

### Create an issuer

Issuer .yaml file with all available options:
```
apiVersion: certmanager.ncm.nokia.com/v1
kind: Issuer (or ClusterIssuer)
metadata:
	name: ISSUER_NAME
	namespace: NAMESPACE_NAME
spec:
	secretName: SECRET_NAME_WITH_REST_CREDS
	tlsSecretName: SECRET_NAME_WITH_TLS_CERT
	CASNAME: CERTIFICATE_NAME_FROM_NCM
	CASHREF: HREF_FROM_NCM
	ncmSERVER: ADDR_TO_NCM
	profileId: PROFILE_ID
	reenrollmentOnRenew: false (or true)
	useProfileIDForRenew: false (or true)
	noRoot: false (or true)
```
For **kind** variable use either Issuer for namespaced one or ClusterIssuer for cluster level issuer.

For **name** variable use some descriptive name of your choice for your issuing CA. This name will be used by your CNFs / applications.

For **namespace** use the one you have created before.

For **secretName** use the secret name with NCM REST API endpoint credentials.

For **tlsSecretName** use the secret name with TLS certificate.

For **CASNAME** use the CA name from NCM web UI visible under 'CA Hierarchy'. Please do not use CA's CN or DN, but CA name as plainly visible in the UI.

For **ncmSERVER** please use your NCM REST API service URL.

If the **profileId** field is defined, then the profile ID will be set in enrollment requests, so it is included in the issued certificates.

Setting the **useProfileIDForRenew** field to “true” is necessary to include the defined profileID value in the */update* request during the renewal process. Otherwise, certificate update operations won’t include it.

Setting the **reenrollmentOnRenew** field to “true” will force new enrollment of the certificate when renewal process is executed. In this case NCM Issuer uses the NCM */requests* REST API endpoint to get a renewed certificate. By default (when this field is not included or set to “false”) the */update* NCM REST API endpoint is used to renew the certificate (it is the default recommended setting).

The **noRoot** field is responsible for controlling the value of ca.crt secret. By default (when this field is not included or set to “false”) Root CA of the certificate is saved to the ca.crt. If noRoot field is set to “true” then issuer of the certificate is saved there.

To create an issuer from created .yaml file type:
```
$ kubectl apply -f issuer.yaml
```

### Enroll a certificate
To enroll a certificate just follow instructions from [cert-manager site](https://cert-manager.io/docs/usage/). The enroll process is exactly the same!
