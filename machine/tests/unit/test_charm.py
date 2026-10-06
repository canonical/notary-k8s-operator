from datetime import timedelta
from unittest.mock import Mock, PropertyMock, patch

from charmlibs.interfaces.tls_certificates import (
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from scenario import Context, Network, Relation, Secret, State, Storage

from charm import (
    MANAGED_CERTIFICATES_RELATION_NAME,
    NOTARY_LOGIN_SECRET_LABEL,
    LoginSecret,
    NotaryCharm,
)
from notary import CertificateRequest

TLS_LIB_PATH = "charmlibs.interfaces.tls_certificates"


def test_given_externally_signed_managed_csr_when_update_status_then_certificate_is_published():
    context = Context(NotaryCharm)
    private_key = generate_private_key()
    csr = generate_csr(private_key, "requirer.example")
    ca_private_key = generate_private_key()
    ca = generate_ca(ca_private_key, timedelta(days=365), "test-ca")
    certificate = generate_certificate(csr, ca, ca_private_key, timedelta(days=365))
    request = RequirerCertificateRequest(1, csr, False)
    state = State(
        storages={Storage(name="config"), Storage(name="database")},
        networks={Network("juju-info")},
        leader=True,
        relations={Relation(id=1, endpoint=MANAGED_CERTIFICATES_RELATION_NAME)},
        secrets={
            Secret(
                {"email": "admin@example.com", "password": "password", "token": "token"},
                label=NOTARY_LOGIN_SECRET_LABEL,
                owner="app",
            )
        },
    )
    client = Mock(
        list_certificate_requests=Mock(
            return_value=[CertificateRequest(1, str(csr), [str(certificate), str(ca)], "Active")]
        )
    )

    with (
        patch("charm.Notary", return_value=client),
        patch.object(
            NotaryCharm,
            "_ca_certificate_path",
            new_callable=PropertyMock,
            return_value="/tmp/notary-test-ca.pem",
        ),
        patch.object(NotaryCharm, "_ensure_workload"),
        patch.object(NotaryCharm, "_sync_peer_relation_data"),
        patch.object(NotaryCharm, "_coordinate_bootstrap"),
        patch.object(NotaryCharm, "_configure_access_certificates"),
        patch.object(NotaryCharm, "_cluster_prerequisites_met", return_value=True),
        patch.object(NotaryCharm, "_configure_notary_config_file"),
        patch.object(NotaryCharm, "_certificates_available", return_value=True),
        patch("machine.NotarySnap.is_running", return_value=True),
        patch.object(NotaryCharm, "_configure_charm_authorization"),
        patch.object(NotaryCharm, "_reconcile_cluster_membership"),
        patch.object(NotaryCharm, "_send_ca_cert"),
        patch.object(NotaryCharm, "_configure_juju_workload_version"),
        patch.object(
            NotaryCharm, "_get_or_create_admin_account", return_value=LoginSecret("", "", "token")
        ),
        patch(
            f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests",
            return_value=[request],
        ),
        patch(
            f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_issued_certificates", return_value=[]
        ),
        patch(
            f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate"
        ) as set_relation_certificate,
    ):
        context.run(context.on.update_status(), state)

    set_relation_certificate.assert_called_once()
    provided = set_relation_certificate.call_args.args[0]
    assert provided.certificate == certificate
    assert provided.ca == ca
