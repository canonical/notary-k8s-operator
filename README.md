# Notary Operator (Kubernetes)

[Notary](https://github.com/canonical/notary/) is a certificate management software. Use it to manage certificate requests in your organization.

The Notary operator for Kubernetes automates the lifecycle operations of Notary. It is a provider of the [tls-certificates](https://charmhub.io/integrations/tls-certificates) integration allowing for the management of certificates in the Juju ecosystem.

[Get started with Notary K8s Operator.](https://charmhub.io/notary-k8s)

## OCI Image

Notary K8s Operator uses the following OCI image:
- [ghcr.io/canonical/notary](https://github.com/canonical/notary)

## High Availability

Notary K8s Operator supports scaling out to multiple units. Units form a
dqlite cluster over the `notary-peers` peer relation. The first Juju leader
records a bootstrap unit before starting Notary. The current Juju leader
coordinates one-time join tokens through a reachable member's direct HTTPS API,
even when its own Notary has not joined yet. Notary manages database elections
and replication independently of Juju leadership. Each departing unit removes
itself from the cluster before stopping.

```shell
juju deploy notary-k8s --trust -n 3
```

- Deploy at least 3 units and wait for three dqlite voters to tolerate one unit
  failing; membership alone does not imply voter promotion is complete.
- Scale down one unit at a time, waiting for the remaining units to become active.
- Units replicate the database over the dqlite port (`9000`) using mutual TLS
  with a cluster certificate managed by Notary. This traffic goes directly
  between pods; only the HTTPS API port (`2111`) is exposed through the Juju
  service. Cluster members use stable unit DNS names across pod replacements.
- Without the `access-certificates` integration, all units sign their
  certificates with one shared self-signed CA, so clients can trust every
  member with a single CA certificate.
- Forced removal, lost database storage, and recovery after quorum loss require
  operator intervention; the charm does not automatically repair cluster membership.
- Bootstrap authorization is not reassigned on Juju leadership changes. Missing
  peer reports never reset a recorded bootstrap decision. If initial bootstrap
  is interrupted and its designated unit cannot return, operator intervention
  is required rather than automatically creating another cluster.

## Project & Community

Notary K8s Operator is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](/CONTRIBUTING.md) and the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/notary-k8s-operator/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com&via=matrix.org&via=mozilla.org)
