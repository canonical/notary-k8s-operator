variable "app_name" {
  description = "Name of the application in the Juju model."
  type        = string
  default     = "notary-k8s"
}

variable "model" {
  description = "UUID of the Juju model in which to deploy."
  type        = string
}

variable "channel" {
  description = "Charm channel to deploy."
  type        = string
  default     = "1/edge"
}

variable "revision" {
  description = "Charm revision to deploy; null selects the channel's current revision."
  type        = number
  default     = null
}

variable "base" {
  description = "Operating system base for the charm."
  type        = string
  default     = "ubuntu@24.04"
}

variable "config" {
  description = "Charm configuration. See https://charmhub.io/notary-k8s/configure."
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Juju constraints for the application."
  type        = string
  default     = "arch=amd64"
}

variable "units" {
  description = "Number of units to deploy."
  type        = number
  default     = 1
}

variable "trust" {
  description = "Whether to grant the application access to cloud credentials."
  type        = bool
  default     = false
}

variable "storage_directives" {
  description = "Storage directives for the config and database stores."
  type        = map(string)
  default     = {}
}
