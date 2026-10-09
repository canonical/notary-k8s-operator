resource "juju_application" "notary" {
  name       = var.app_name
  model_uuid = var.model

  charm {
    name     = "notary"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config             = var.config
  constraints        = var.constraints
  units              = var.units
  trust              = var.trust
  storage_directives = var.storage_directives
}
