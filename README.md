# Notary Operators (Kubernetes and Machine)

[Notary](https://github.com/canonical/notary/) is certificate management software.
The Notary Operators automate its lifecycle on Kubernetes and Juju machines and
provide certificates through the `tls-certificates` integration.

- [`k8s/`](k8s/README.md): the Kubernetes charm, published as `notary-k8s`.
- [`machine/`](machine/README.md): the machine charm, published as `notary`.

For more information, including guides, integrations, and configuration options,
see the [Kubernetes charm](https://charmhub.io/notary-k8s) and
[machine charm](https://charmhub.io/notary) on Charmhub.

## Workloads

- OCI image: [ghcr.io/canonical/notary](https://github.com/canonical/notary)
- Snap: [notary](https://snapcraft.io/notary)

## Project & Community

Notary Operators are open source projects that welcome contributions, suggestions,
fixes, and feedback.

- Contribute using [CONTRIBUTING.md](CONTRIBUTING.md) and the [Juju SDK docs](https://juju.is/docs/sdk).
- Raise issues or feature requests on [GitHub](https://github.com/canonical/notary-k8s-operator/issues).
- Meet the community on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com&via=matrix.org).
