# Issuing your first certificate

## Create an Issuer

Once the deployment is up and running, you are ready to create your first `Issuer`!

<figure markdown>
  ![installation](../../assets/creating-issuer.gif)
</figure>

The following is an example `Issuer` created for the namespace `example-ncm-ns`:

  ```bash
  cat << EOF | kubectl apply -f -
  apiVersion: certmanager.ncm.nokia.com/v1
  kind: Issuer
  metadata:
    name: example-ncm-issuer
    namespace: example-ncm-ns
  spec:
    caName: ncm-ca
    provisioner:
      mainAPI: https://nokia-ncm.local
      authRef:
        name: ncm-rest-auth
        namespace: example-ncm-ns
  EOF
  ```

After creating the `Issuer`, we should now be able to check its status:

  ```bash
  kubectl get ncmissuers -n example-ncm-ns
  
  NAME                 AGE   READY   REASON     MESSAGE
  example-ncm-issuer   3s    True    Verified   Signing CA verified and ready to sign certificates
  ```

The above output tells us that our `Issuer` is ready to sign certificates!

## Signing certificate

Once the `Issuer` was successfully created, it is now time to sign the first certificate:

<figure markdown>
  ![installation](../../assets/signing-certificate.gif)
</figure>

  ```bash
  cat << EOF | kubectl apply -f -
  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: example-ncm-certificate
    namespace: example-ncm-ns
  spec:
    commonName: example-ncm-certificate-nokia-ncm.local
    dnsNames:
    - example-ncm-certificate-nokia-ncm.local
    subject:
      countries:
      - PL
      organizationalUnits:
      - Security
      organizations:
      - Nokia
    usages:
    - server auth
    - data encipherment
    secretName: example-ncm-certificate-nokia-ncm-tls
    issuerRef:
      group: certmanager.ncm.nokia.com
      kind: Issuer
      name: example-ncm-issuer
  EOF
  ```

Then we can check the status of our newly issued certificate:

  ```bash
  kubectl get certificates -n example-ncm-ns
  
  NAME                      READY   SECRET                                  AGE
  example-ncm-certificate   True    example-ncm-certificate-nokia-ncm-tls   17s
  ```

and whether it has corresponding `secret` referenced:

  ```bash
  kubectl get secrets -n example-ncm-ns
  
  NAME                                    TYPE                                  DATA   AGE
  default-token-g2f47                     kubernetes.io/service-account-token   3      18m
  example-ncm-certificate-details         Opaque                                1      22s
  example-ncm-certificate-nokia-ncm-tls   kubernetes.io/tls                     3      22s
  ```

Additionally, in NCM GUI we can also find our newly issued certificate.