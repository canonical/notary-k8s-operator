# Notary Operator (Machine)

[Notary](https://github.com/canonical/notary/) is certificate management software.

The machine charm runs the Notary snap and provides certificates through
the [tls-certificates](https://charmhub.io/integrations/tls-certificates) integration.

For guides, integrations, and configuration options, see
[Notary on Charmhub](https://charmhub.io/notary).

For Terraform deployments, use the [machine module](terraform/README.md).

Start with [Deploy Notary on machines](../docs/how-to/deploy-machine.md).
The [documentation index](../docs/index.md) separates machine and Kubernetes
deployment guidance from shared operations.

See [Manage certificates](../docs/how-to/manage-certificates.md) for signing modes
and certificate distribution, and the [repository overview](../README.md) for
workloads and community links.