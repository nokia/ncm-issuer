# Troubleshooting

## Getting ncm-issuer logs

In case of any problem, besides checking the status of created resources,
you can also check the `ncm-issuer` pod logs:

  ```bash
  kubectl -n ncm-issuer logs -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
  ```

If you deployed troubleshooting sidecar as well, you can check the `ncm-issuer` pod logs this way:

  ```bash
  kubectl -n ncm-issuer logs -c ncm-issuer -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
  ```

## Setting logging verbosity level

In the case of increasing logging verbosity level change the `logging.logLevel` in `values.yaml` to
wanted value and update your deployment. To get all possible log messages, simply set the
`logging.logLevel` to **3**, you can also additionally change the `logging.stacktraceLevel` to
`error`.

## Enabling troubleshooting sidecar

There is also the possibility of using sidecar for debugging purposes - just change the value of
`sidecar.enabled` to **true** in `values.yaml` and update your deployment.