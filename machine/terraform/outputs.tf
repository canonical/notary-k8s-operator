output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.notary.name
}

output "requires" {
  description = "Requirer endpoints available for integrations."
  value = {
    access-certificates = "access-certificates"
    ingress             = "ingress"
    logging             = "logging"
    s3-parameters       = "s3-parameters"
    tracing             = "tracing"
  }
}

output "provides" {
  description = "Provider endpoints available for integrations."
  value = {
    acme-certificates          = "acme-certificates"
    grafana-dashboard          = "grafana-dashboard"
    managed-certificates       = "managed-certificates"
    metrics                    = "metrics"
    self-signed-certificates   = "self-signed-certificates"
    send-access-ca-certificate = "send-access-ca-certificate"
  }
}
