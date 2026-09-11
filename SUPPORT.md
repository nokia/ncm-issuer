<!-- markdownlint-disable MD013 -->
# Getting help

## Start with the documentation

Most enrollment and renewal problems are covered already:

* [Installation](https://nokia.github.io/ncm-issuer/docs/documentation/installation/) and [configuration](https://nokia.github.io/ncm-issuer/docs/documentation/configuration/)
* [Issuer](https://nokia.github.io/ncm-issuer/docs/documentation/CRDs/issuer/) and [ClusterIssuer](https://nokia.github.io/ncm-issuer/docs/documentation/CRDs/cluster-issuer/) reference
* [Troubleshooting](https://nokia.github.io/ncm-issuer/docs/documentation/troubleshooting/)

## Where to ask

| You want to | Use |
| --- | --- |
| Ask a question or discuss an idea | [GitHub Discussions](https://github.com/nokia/ncm-issuer/discussions) |
| Report a reproducible bug | [GitHub Issues](https://github.com/nokia/ncm-issuer/issues) |
| Request a feature | [GitHub Issues](https://github.com/nokia/ncm-issuer/issues) |
| Report a security vulnerability | [SECURITY.md](SECURITY.md), never a public issue |
| Raise a production problem under a Nokia contract | Your usual Nokia support or account contact |

GitHub issues and discussions are handled by maintainers on a best-effort basis and carry no service level agreement. Nokia customers who need a committed response time should use their support contract.

Questions about NCM itself, rather than this controller, go to Nokia support rather than this repository.

## Before you open an issue

Search the [open and closed issues](https://github.com/nokia/ncm-issuer/issues?q=is%3Aissue) first. If nothing matches, include:

* the ncm-issuer chart and image versions,
* the cert-manager and Kubernetes versions,
* what you expected and what happened instead,
* the `Issuer` or `ClusterIssuer` spec with secrets and hostnames removed,
* the relevant controller logs.

Collect the logs with:

```bash
kubectl -n ncm-issuer logs -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
```

Raise `logging.logLevel` to `3` in `values.yaml` and redeploy if the default output is not detailed enough. The [troubleshooting guide](https://nokia.github.io/ncm-issuer/docs/documentation/troubleshooting/) explains the other options.

Redact certificates, private keys, API credentials and internal hostnames before posting.

## Supported versions

Fixes land on the latest release line. Reproduce your problem on the most recent [release](https://github.com/nokia/ncm-issuer/releases) before reporting it.

## Contributing a fix

See [CONTRIBUTING.md](CONTRIBUTING.md).
