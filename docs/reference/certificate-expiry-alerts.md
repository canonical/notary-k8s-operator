# Certificate-expiry alerts

Both Notary charms publish these Prometheus alert rules through the `metrics`
integration. They require a Notary workload that exposes
`certificate_not_before_timestamp_seconds` and
`certificate_not_after_timestamp_seconds`. Workloads without these metrics do not
trigger the alerts.

## Thresholds

The rules calculate the fraction of certificate validity elapsed from its start
and end timestamps at each Prometheus evaluation.

| Alert | Validity elapsed | Severity |
| --- | --- | --- |
| `NotaryCertificateValidity65Percent` | At least 65%, below 90% | Warning |
| `NotaryCertificateValidity90Percent` | At least 90%, below 95% | Critical |
| `NotaryCertificateValidity95Percent` | At least 95%, below 100% | Critical |
| `NotaryCertificateExpired` | At least 100% | Critical |

Bands do not overlap for a given certificate and scrape target. Each alert
identifies the request through `csr_id`, preserves deployment and scrape labels,
and reports time remaining or time since expiry. CSR IDs are unique only within
a Notary deployment.