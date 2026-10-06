# Notary Machine Charm

This charm runs the Notary snap on Juju machines and provides the same certificate-signing
relations as the Kubernetes charm.

## Certificate Updates

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