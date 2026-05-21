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

From `1.2.1` onwards the sidecar runs under a non-root user (`runAsUser: 998`) with a
narrow capability set: every Linux capability is dropped and only `NET_RAW`, `NET_ADMIN`
and `SYS_PTRACE` are added back so `tcpdump` and `strace` can be used. The matching
file capabilities are baked into the `ncm-issuer-utils` image (`cap_net_raw,cap_net_admin+ep`
on `/usr/sbin/tcpdump` and `cap_sys_ptrace+ep` on `/usr/bin/strace`), so a `kubectl exec`
into the sidecar lets you run those tools directly without `sudo`. `allowPrivilegeEscalation`
is intentionally left at `true` on the sidecar so the kernel honours those file capabilities
on `execve()`; setting it to `false` would set `no_new_privs=1` and silently break both tools.

If your cluster enforces the Pod Security Standards "restricted" profile at the namespace
level the sidecar will be rejected at admission because of `allowPrivilegeEscalation: true`.
In that case either keep `sidecar.enabled: false` in those namespaces, or relabel the
namespace to "baseline" specifically for ncm-issuer.

## Issuer stuck in `Ready=False` with `NCM API health check failed`

From `1.2.1` onwards, the `Issuer` (and `ClusterIssuer`) `Ready` condition is
gated on a synchronous health probe of the NCM REST API during reconciliation.
If you see something like:

  ```bash
  kubectl get ncmissuers -n example-ncm-ns
  NAME                 AGE   READY   REASON   MESSAGE
  example-ncm-issuer   5s    False   Error    NCM API health check failed: ...
  ```

it means the controller could reach the Kubernetes apiserver but the
authenticated `GET /v1/cas` probe against the configured `mainAPI` (and
`backupAPI` if set) did not return `2xx`. Typical causes:

- wrong `mainAPI` / `backupAPI` URL or unreachable NCM host
- invalid or missing credentials in the auth `secret`
- TLS misconfiguration (missing CA bundle when the NCM uses HTTPS)
- egress/proxy not configured (see the next section)

Check the `ncm-issuer` pod logs for the exact probe failure. The issuer will
be retried by the controller automatically. There is no manual action needed
besides fixing the underlying connectivity or configuration.

## Using an outbound HTTP(S) proxy

If your cluster has no direct internet/egress connectivity to the NCM instance, configure an HTTP(S) proxy.

If you install using Helm, set standard proxy environment variables via chart values:

```yaml
proxy:
  httpsProxy: "http://proxy.example:3128"
  httpProxy: "http://proxy.example:3128"
  noProxy: "localhost,127.0.0.1,.cluster.local"
```

Under the hood this sets `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` (and lowercase equivalents) which are
honored by Go's HTTP client (including HTTPS via CONNECT).
