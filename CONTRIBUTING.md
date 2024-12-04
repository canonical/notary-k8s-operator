# Contributing

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

This project uses `uv`. You can install it on Ubuntu with:

```shell
sudo snap install --classic astral-uv
```

You can create an environment for development with `uv`:

```shell
uv sync
source .venv/bin/activate
```

## Testing

This project uses `tox` for managing test environments.
It can be installed with:

```shell
uv tool install tox --with tox-uv
```

There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e static        # static type checking
tox run -e unit          # unit tests
tox                      # runs 'format', 'lint', 'static', and 'unit' environments
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

## Running the integration tests

To run the integration tests, the charm must first be built.
A local Juju environment with a bootstrapped Kubernetes cluster
is also required. Once the requirements are met, run the tests
with:

```shell
tox -e integration -- --charm_path=notary-k8s_amd64.charm
```

## Deploy the charm

Deploy the local charm by using:

```shell
juju deploy ./notary-k8s_ubuntu-22.04-amd64.charm --resource notary-image=ghcr.io/canonical/notary
```
