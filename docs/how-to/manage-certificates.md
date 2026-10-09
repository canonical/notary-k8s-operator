# Manage certificates

Both Notary charms provide the same certificate-signing modes. Certificate
distribution differs between Kubernetes and machines as described below.

## Choose a signing mode

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

## Certificate updates

When a certificate request is signed outside the charm, for example through the Notary API or
UI, the machine charm publishes the resulting certificate on its next Juju `update-status` hook.
The default Juju interval is five minutes.

The Kubernetes charm receives an immediate Pebble custom notice from Notary. That notification
mechanism is unavailable to the machine charm because the Notary snap does not run under Pebble.
The machine charm therefore polls Notary during `update-status` reconciliation.

To reduce this delay for a model, set a shorter update-status interval:

```bash
juju model-config update-status-hook-interval=1m
```

Choose an interval that balances prompt certificate distribution with the additional API requests
made by each unit.