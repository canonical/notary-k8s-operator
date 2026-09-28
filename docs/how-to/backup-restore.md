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
