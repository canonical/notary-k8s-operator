# Notary Terraform module

This folder contains a base [Terraform][Terraform] module for the `notary` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto a machine environment managed by [Juju][Juju]. It can be deployed on its
own or used as a building block for higher level modules.

## Getting Started

### Pre-requisites

- A machine environment
- A Juju controller bootstrapped onto the machine environment
- The Juju client
- Terraform

### Deploying Notary

Create a directory for your deployment and add the following to `versions.tf`:

```hcl
terraform {
  required_providers {
    juju = {
      source  = "juju/juju"
      version = ">= 1.0"
    }
  }
}
```

Configure the Juju provider for your controller, then create `main.tf`:

```hcl
resource "juju_model" "demo" {
  name = "demo"
}

module "notary" {
  source = "git::https://github.com/canonical/notary-k8s-operator.git//machine/terraform"
  model  = juju_model.demo.uuid
}
```

Pin the module source to a release tag or commit using `?ref=` for reproducible deployments.
Initialize the provider and deploy the module:

```shell
terraform init
terraform apply
```

## How-to

### Create integrations

For a certificate-requiring application already declared as `module.some-app`, add the
following to `main.tf`, using that application's certificate endpoint:

```hcl
resource "juju_integration" "certificates" {
  model_uuid = juju_model.demo.uuid

  application {
    name     = module.some-app.app_name
    endpoint = "certificates"
  }

  application {
    name     = module.notary.app_name
    endpoint = module.notary.provides.self-signed-certificates
  }
}
```

See the [available integrations][notary-integrations] for other endpoints.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Exposes deployment options and charm configuration.
- **outputs.tf** - Exposes the application name and integration endpoint names.
- **versions.tf** - Defines the required Terraform provider.

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[notary-integrations]: https://charmhub.io/notary/integrations
