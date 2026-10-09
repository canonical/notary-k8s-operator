# Monitor certificate expiry

Both Notary charms publish the same certificate-expiry alert rules through their
`metrics` integration. Connect this endpoint to Prometheus in COS, directly for
Kubernetes or through a supported cross-model integration for the machine charm.

## Interpret the alerts

These rules require a Notary workload release containing the timestamp metrics
introduced in [Notary PR #392](https://github.com/canonical/notary/pull/392).
Merging the PR does not update deployed OCI images or snaps. Older workloads
without these metrics will not trigger these alerts.

| Alert | Validity elapsed | Severity |
| --- | --- | --- |
| `NotaryCertificateValidity65Percent` | At least 65%, below 90% | Warning |
| `NotaryCertificateValidity90Percent` | At least 90%, below 95% | Critical |
| `NotaryCertificateValidity95Percent` | At least 95%, below 100% | Critical |
| `NotaryCertificateExpired` | At least 100% | Critical |

The rules calculate elapsed validity at each Prometheus evaluation using
`certificate_not_before_timestamp_seconds` and
`certificate_not_after_timestamp_seconds`:

```text
(time() - not_before) / (not_after - not_before)
```

Each alert identifies the Notary request through `csr_id` and preserves deployment
and scrape labels. Notifications show time remaining, or time since expiry.
Future certificates and certificates with non-positive validity periods do not
trigger these rules. Missing metrics do not trigger alerts; monitor scrape health
separately.

There is no fixed pending period: an alert fires at the first evaluation matching
its band. Timestamp-based calculations advance without waiting for Notary's
120-second metric collection, but new certificates, revocations and removals still
depend on collection and scraping. Rule evaluation and Alertmanager notification
timing must also suit the shortest certificate lifetimes you use. Very short
validity windows may pass between evaluations.

The bands do not overlap for a given certificate and scrape target, so no
threshold inhibition is needed. A previous band resolves as the next fires;
different certificates can trigger different bands simultaneously. If multiple
Notary replicas are scraped, group notifications by deployment, `csr_id` and
`alertname` rather than by replica to avoid duplicate notifications. Replicas can
temporarily disagree while collecting lifecycle changes.

These alerts describe certificates recorded in Notary, not confirmed automatic
renewal failures. A recorded certificate may have a replacement, and these metrics
do not establish which certificate a service is using. Check the affected service
and replacement certificates before concluding that renewal failed.

## Validate a release with Juju and COS

Use disposable test models and test certificates, not production certificates.
Repeat for both the Kubernetes and machine charms using artifacts built from the
release candidate.

1. Deploy Notary and COS, integrate the Notary `metrics` endpoint with Prometheus,
   and connect Prometheus to Alertmanager. For separate models, use a Juju offer.
2. Confirm the Notary HTTPS `/metrics` target is up in Prometheus and both timestamp
   metrics are present for a test certificate. Confirm all four rules are loaded
   without errors and alerts carry the expected `juju_model_uuid`,
   `juju_application` and `csr_id` labels.
3. Use the workload's supported API or UI to create controlled test certificates
   and observe the 65%, 90%, 95% and expiry transitions. Verify only one band is
   active per certificate and scrape target, including at exact boundaries.
4. Route notifications to a test receiver. Verify the CSR identifier, severity and
   readable time remaining. Check both short- and long-lived certificates and
   verify alerts from different deployments remain distinct.
5. Revoke or remove test certificates using supported lifecycle operations.
   Verify their series disappear, the alerts resolve and the test receiver
   receives resolved notifications when configured to do so.
6. Record charm revisions, workload versions, COS revisions, observed metrics and
   notification results. Remove only the disposable models created for this test.

Static rule validation does not replace this deployed check. Terraform formatting
and validation likewise do not establish that a real deployment succeeds.