# Configuration

To make the ncm-issuer work properly, it is necessary to create few Kubernetes secrets
that contains credentials to NCM REST API and optional TLS configuration.

<figure markdown>
  ![installation](../assets/configuration.gif)
</figure>

## NCM REST API credentials

  ```bash
  kubectl create secret generic \
  <secret-name> \
  -n <namespace> \
  --from-literal=username=<username> \
  --from-literal=usrPassword=<password>
  ```

## TLS without client authentication

    ```bash
    kubectl create secret generic \
    <secret-name> \
    -n <namespace> \
    --from-file=cacert=<ca-for-tls.pem>
    ```

## TLS with client authentication

  ```bash
  kubectl create secret generic \
  <secret-name> \
  -n <namespace> \
  --from-file=cacert=<ca-for-tls.pem> \
  --from-file=key=<client-auth-pkey.pem> \
  --from-file=cert=<client-auth-cert.pem>
  ```

!!! tip
    To make sure that specific secret have been created correctly, you can check this
    by using command:
    
    ```bash
    kubectl -n <namespace> describe secrets <secret-name>
    ```