# Notary Operator (Kubernetes)

[Notary](https://github.com/canonical/notary/) is certificate management software.

The Kubernetes charm runs the Notary OCI image and provides certificates through
the [tls-certificates](https://charmhub.io/integrations/tls-certificates) integration.

For guides, integrations, and configuration options, see
[Notary K8s on Charmhub](https://charmhub.io/notary-k8s).

For Terraform deployments, use the [Kubernetes module](terraform/README.md).

See [Manage certificates](../docs/how-to/manage-certificates.md) for signing modes
and certificate distribution, and the [repository overview](../README.md) for
workloads and community links.
