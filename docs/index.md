# Notary Charms documentation

Notary manages certificate requests and their associated certificates. The
Notary charms provide certificates to Juju applications through the
`tls-certificates` integration.

## Choose your platform

| | Kubernetes | Machine |
| --- | --- | --- |
| Charm | [`notary-k8s`](https://charmhub.io/notary-k8s) | [`notary`](https://charmhub.io/notary) |
| Juju model | Kubernetes model | Machine model |
| Workload | Notary OCI image managed by Pebble | Notary snap |
| Deployment guide | [Deploy on Kubernetes](how-to/deploy-k8s.md) | [Deploy on machines](how-to/deploy-machine.md) |
| Terraform | [Kubernetes module](../k8s/terraform/README.md) | [Machine module](../machine/terraform/README.md) |

## Shared operations

These guides apply to both charms. Platform-specific behavior and commands are
labelled within each guide.

- [Manage certificates](how-to/manage-certificates.md): signing modes and
  certificate distribution, including Kubernetes notices and machine polling.
- [Back up and restore](how-to/backup-restore.md): S3 configuration and same-unit
  recovery for single-member deployments.

## Reference

- [Certificate-expiry alerts](reference/certificate-expiry-alerts.md): shared
  Prometheus alert thresholds and limitations.