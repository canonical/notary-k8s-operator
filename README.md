# Notary Operator (Kubernetes)

[Notary](https://github.com/canonical/notary/) is a certificate management software. Use it to manage certificate requests in your organization.

The Notary operator for Kubernetes automates the lifecycle operations of Notary. It is a provider of the [tls-certificates](https://charmhub.io/integrations/tls-certificates) integration allowing for the management of certificates in the Juju ecosystem.

[Get started with Notary K8s Operator.](https://charmhub.io/notary-k8s)

## Certificate Signing Modes

- `managed-certificates` forwards requests for approval and signing through the Notary API or UI.
- `self-signed-certificates` automatically signs requests using the Notary Charm CA.
- `acme-certificates` automatically signs requests using the configured ACME server. Set `email`, `server`, `plugin`, and `plugin-config-secret-id` before using this endpoint.

Each CSR is assigned to one signing mode, recorded in an application-owned Juju secret.
Generate a new CSR when moving between endpoints. Existing Notary requests without a recorded
mode are treated as managed requests; automatic signing requires a fresh CSR after upgrading
from a charm without mode tracking. CA certificate requests (`is_ca=true`) are not supported
and receive an explicit relation error instead of a leaf certificate.

The charm replaces its expired signing CA for subsequent requests. It does not replace an
explicitly disabled CA: re-enable that CA in Notary to resume issuance. Previously issued
certificates are not re-signed automatically; requirers must request renewal.

The charm reconciles its ACME server's URL, email, DNS plugin, and credential-key list with
configuration. Credential values are refreshed when the Juju secret changes; Notary does not
expose those values for drift detection. Manage credentials through the Juju secret, not the UI.

## OCI Image

Notary K8s Operator uses the following OCI image:
- [ghcr.io/canonical/notary](https://github.com/canonical/notary)

## Project & Community

Notary K8s Operator is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](/CONTRIBUTING.md) and the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/notary-k8s-operator/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com&via=matrix.org&via=mozilla.org)
