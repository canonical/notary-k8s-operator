# S3 storage for Notary backups

Relate Notary to an S3 integrator:

```shell
juju deploy s3-integrator
juju config s3-integrator endpoint=https://s3.example.com bucket=notary-backups region=us-east-1 path=notary
juju run s3-integrator/leader sync-s3-credentials access-key=ACCESS_KEY secret-key=SECRET_KEY
juju integrate notary-k8s:s3-parameters s3-integrator:s3-credentials
```

Provision the bucket before running backup actions. The credentials need permission
to upload, list, and retrieve objects in the configured path. The charm uses the
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
with a unique `notary-backup-` name. The bucket must already exist.

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
