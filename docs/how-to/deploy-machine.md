# Deploy Notary on machines

Use the `notary` charm in a Juju machine model. It installs and runs the Notary
snap. For a Juju Kubernetes model, follow
[Deploy Notary on Kubernetes](deploy-k8s.md) instead.

## Prerequisites

- A bootstrapped Juju controller with access to a machine cloud.
- A machine model selected with `juju switch`, able to provision Ubuntu 24.04
  machines and install snaps from the Snap Store.

## Deploy

```shell
juju deploy notary --channel 1/edge --base ubuntu@24.04 --trust
juju status --watch 5s
```

Wait for the application to become active before integrating certificate
requirers. This example uses the edge channel; check the
[Charmhub listing](https://charmhub.io/notary) for available releases.

## Next steps

- [Manage certificates](manage-certificates.md): choose a signing endpoint for
  your requirers. Certificates signed through the API or UI are distributed
  during `update-status`, normally within five minutes. The guide explains how
  to adjust that interval.
- [Back up and restore](backup-restore.md): select the machine application name
  and configure S3 storage.
- [Certificate-expiry alerts](../reference/certificate-expiry-alerts.md):
  monitor certificate validity through the `metrics` integration.

For Terraform deployments, use the
[machine module](../../machine/terraform/README.md).