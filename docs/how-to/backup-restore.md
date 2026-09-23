# S3 storage for Notary backups

Relate Notary to an S3 integrator:

```shell
juju deploy s3-integrator
juju config s3-integrator endpoint=https://s3.example.com bucket=notary-backups region=us-east-1 path=notary
juju run s3-integrator/leader sync-s3-credentials access-key=ACCESS_KEY secret-key=SECRET_KEY
juju integrate notary-k8s:s3-parameters s3-integrator:s3-credentials
```

The credentials need permission to check the bucket and to upload, list, and
retrieve objects in the configured path. The backup action creates a missing
bucket if the credentials also grant bucket creation permission. Otherwise,
provision the bucket beforehand. The charm uses the
relation's endpoint, bucket, region, path, credentials, and optional `tls-ca-chain`.
TLS verification is always enabled; configure the integrator's CA chain for a
private S3 endpoint. Juju charm HTTP/HTTPS proxies are honored.

S3 is optional. An incomplete relation reports blocked status without stopping
certificate issuance. Credentials are read from the relation for each operation,
so rotation takes effect without restarting Notary.

## Create a backup

```shell
juju run notary-k8s/leader create-backup
```

Save the returned `backup-id`. Backups are stored beneath the S3 relation's `path`
with a unique `notary-backup-` name. A missing bucket is created before Notary is stopped.

This action supports **single-unit, single-member deployments**. It checks both
Juju's planned units and Notary's actual membership before proceeding. There is
brief downtime while the offline `notary backup` command creates the archive.
Notary is restarted before uploading to S3, including when archive creation fails.
Temporary files are removed when the operation ends. A failed restart makes the
action fail; inspect `juju debug-log` and the workload before retrying.

Archives contain the database and dqlite cluster keys. Restrict access to the
bucket. They retain the original member identity and are intended for restoring
the same unit, address, application, and model. They do not include Juju secrets
or externally managed encryption keys. Retain the charm's admin login secret and
any encryption keys alongside your disaster recovery procedures.

## List backups

```shell
juju run notary-k8s/leader list-backups
```

The `backup-ids` result is a JSON array of full object keys, suitable for passing
unchanged to `restore-backup`. Listing reads every S3 result page and includes
Notary archives beneath the configured path. An empty bucket returns `[]`;
access errors or missing buckets fail the action. Listing also works when the
Notary workload is unavailable, and does not interrupt service.

## Restore a backup

```shell
juju run notary-k8s/leader restore-backup backup-id=notary/notary-backup-EXAMPLE.tar.gz
```

Use the exact key from `list-backups`. Restoring **replaces the database** with
its earlier contents. Only archives created by this charm on the same unit,
model, application, and dqlite address are accepted. The unit must still have
single-member cluster state on disk; removing Juju peers alone does not make a
multi-member cluster eligible. Cross-deployment restore and recovery from lost
cluster quorum require a separate recovery procedure and are not implemented by
this action.

The charm downloads the archive, checks its SHA-256 and identity metadata, and
validates its archive paths and cluster identity before stopping Notary. It
stages files with restrictive permissions and preserves the previous database
until the restore command and service start succeed. On failure it attempts to
roll back and restart the original database. If rollback itself fails, the old
database remains in `/var/lib/notary/database/.pre-restore-*`; inspect logs and
recover it before retrying. A workload that was stopped before the action stays
stopped. After success, `restored` contains the backup ID.

Ensure the admin credentials in the charm's Juju secret still match the restored
database. If they changed since the backup, restore the matching secret content.
These actions require the dqlite-aware Notary CLI (`backup` and `restore` with
`--db-path`); the older API-based backup CLI is incompatible. Allow free disk
space for the downloaded archive, the restored database, and a rollback copy.

## Integration test

With a bootstrapped Juju Kubernetes controller and a pre-provisioned test bucket,
set `S3_TEST_ENDPOINT`, `S3_TEST_BUCKET`, `S3_TEST_ACCESS_KEY`, and
`S3_TEST_SECRET_KEY` (optionally `S3_TEST_REGION`), then run:

```shell
PYTHONPATH=lib:src uv run pytest tests/integration/test_backup.py --charm_path=/path/to/notary.charm
```

The endpoint must be reachable from the deployed charm, and the runner must be
able to reach the Notary unit API. The test creates certificate requests before
and after backup and verifies that restore retains only the earlier request.
It uses a unique S3 prefix; delete that prefix after testing.
