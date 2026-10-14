# Deploy Notary on Kubernetes

Use the `notary-k8s` charm in a Juju Kubernetes model. It runs the Notary OCI image
under Pebble. For a Juju machine model, follow
[Deploy Notary on machines](deploy-machine.md) instead.

## Prerequisites

- A bootstrapped Juju controller with access to a Kubernetes cluster.
- A Kubernetes model selected with `juju switch`.

## Deploy

```shell
juju deploy notary-k8s --channel 1/edge --trust
juju status --watch 5s
```

Wait for the application to become active before integrating certificate
requirers. This example uses the edge channel; check the
[Charmhub listing](https://charmhub.io/notary-k8s) for available releases.

## Next steps

- [Manage certificates](manage-certificates.md): choose a signing endpoint for
  your requirers. Certificates signed through the API or UI are distributed
  when the charm handles Notary's Pebble custom notice.
- [Back up and restore](backup-restore.md): select the Kubernetes application
  name and configure S3 storage.
- [Certificate-expiry alerts](../reference/certificate-expiry-alerts.md):
  monitor certificate validity through the `metrics` integration.

For Terraform deployments, use the
[Kubernetes module](../../k8s/terraform/README.md).