#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

"""Charm the application."""

import logging

import ops
import requests
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV3,
)

logger = logging.getLogger(__name__)


class GocertCharm(ops.CharmBase):
    """Charmed Gocert."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        self.tls = TLSCertificatesProvidesV3(self, relationship_name="certificates")
        framework.observe(self.on["gocert"].pebble_ready, self._on_gocert_pebble_ready)
        framework.observe(self.on["gocert"].pebble_custom_notice, self._on_gocert_notify)
        framework.observe(self.tls.on.certificate_creation_request, self._on_new_certificate)
        framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_gocert_pebble_ready(self, event: ops.PebbleReadyEvent):
        """Handle pebble-ready event."""
        container = event.workload
        try:
            container.pull("/etc/config/config.yaml")
        except ops.pebble.PathError:
            config_file = open("src/configs/config.yaml").read()
            cert_file = open("src/configs/cert.pem").read()
            key_file = open("src/configs/key.pem").read()
            container.make_dir(path="/etc/config", make_parents=True)
            container.push(path="/etc/config/config.yaml", source=config_file)
            container.push(path="/etc/config/cert.pem", source=cert_file)
            container.push(path="/etc/config/key.pem", source=key_file)
            container.add_layer("gocert", self._pebble_layer, combine=True)
            container.replan()
        self.unit.status = ops.ActiveStatus()

    def _on_new_certificate(self, event: CertificateCreationRequestEvent):
        csr = event.certificate_signing_request
        requests.post(
            url="https://localhost:2111/api/v1/certificate_requests",
            data=csr,
            headers={"Content-Type": "text/plain"},
            verify=False,
        )

    def _on_gocert_notify(self, event: ops.PebbleCustomNoticeEvent):
        r = requests.get(url="https://localhost:2111/api/v1/certificate_requests", verify=False)
        response_data = r.json()
        for relation in self.model.relations["certificates"]:
            unfulfilled_csrs = self.tls.get_outstanding_certificate_requests(
                relation_id=relation.id
            )
            for row in response_data:
                csr = row.get("CSR")
                cert = row.get("Certificate")
                for relation_csr in unfulfilled_csrs:
                    if csr == relation_csr.csr:
                        self.tls.set_relation_certificate(
                            certificate_signing_request=csr,
                            certificate=cert,
                            ca="",
                            chain=[cert],
                            relation_id=relation.id,
                        )

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        self.unit.status = ops.ActiveStatus()

    @property
    def _pebble_layer(self) -> ops.pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "gocert layer",
            "description": "pebble config layer for gocert",
            "services": {
                "gocert": {
                    "override": "replace",
                    "summary": "gocert",
                    "command": "gocert -config /etc/config/config.yaml",
                    "startup": "enabled",
                }
            },
        }


if __name__ == "__main__":  # pragma: nocover
    ops.main(GocertCharm)  # type: ignore
