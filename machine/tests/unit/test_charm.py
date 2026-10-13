from datetime import timedelta
from typing import Literal
from unittest.mock import Mock, PropertyMock, patch

import pytest
import requests
from charmlibs.interfaces.tls_certificates import (
    CertificateRequestErrorCode,
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
    SELF_SIGNED_CERTIFICATES_RELATION_NAME,
    LoginSecret,
    NotaryCharm,
)
from notary import CertificateRequest, Notary, NotaryClientError

TLS_LIB_PATH = "charmlibs.interfaces.tls_certificates"


@pytest.mark.parametrize(
    "status, name", [("Rejected", "REQUEST_REJECTED"), ("Revoked", "CERTIFICATE_REVOKED")]
)
def test_given_unsuccessful_request_when_sync_then_request_error_recorded(
    status: Literal["Rejected", "Revoked"], name: str
):
    context = Context(NotaryCharm)
    csr = generate_csr(generate_private_key(), "request.example")
    request = RequirerCertificateRequest(1, csr, False)
    provider = Mock()
    with context(context.on.collect_unit_status(), State(leader=True)) as manager:
        manager.charm._push_notary_results_to_requirers(
            provider, [request], [CertificateRequest(1, str(csr), [], status)]
        )

    provider.set_relation_certificate.assert_not_called()
    provider.set_relation_error.assert_called_once()
    provider_error = provider.set_relation_error.call_args.kwargs["provider_error"]
    assert provider_error.relation_id == request.relation_id
    assert provider_error.certificate_signing_request == csr
    assert provider_error.error.code == CertificateRequestErrorCode.OTHER
    assert provider_error.error.name == name


@pytest.mark.parametrize("duplicates_on_refresh", [False, True])
def test_given_duplicate_requests_when_sync_then_error_recorded_and_other_request_signed(
    duplicates_on_refresh: bool,
):
    context = Context(NotaryCharm)
    csr = generate_csr(generate_private_key(), "duplicate.example")
    other_csr = generate_csr(generate_private_key(), "other.example")
    request = RequirerCertificateRequest(1, csr, False)
    other_request = RequirerCertificateRequest(2, other_csr, False)
    provider = Mock(relationship_name=SELF_SIGNED_CERTIFICATES_RELATION_NAME)
    provider.get_certificate_requests.return_value = [request, other_request]
    provider.get_issued_certificates.return_value = []
    entries = [
        CertificateRequest(1, str(csr), [], "Active" if duplicates_on_refresh else "Outstanding"),
        CertificateRequest(3, str(other_csr), [], "Outstanding"),
    ]
    duplicates = [*entries, CertificateRequest(2, str(csr), [], "Outstanding")]
    client = Mock()
    client.list_certificate_requests.side_effect = [
        entries if duplicates_on_refresh else duplicates,
        duplicates,
    ]
    signing = Mock(return_value=True)
    with (
        patch.object(NotaryCharm, "client", new_callable=PropertyMock, return_value=client),
        patch.object(NotaryCharm, "_claim_certificate_request", return_value=True),
        context(context.on.collect_unit_status(), State(leader=True)) as manager,
    ):
        manager.charm._sync_certificate_requirers(provider, "token", signing=signing)

    signing.assert_called_once_with(3)
    client.create_certificate_request.assert_not_called()
    provider.set_relation_certificate.assert_not_called()
    provider.set_relation_error.assert_called_once()
    provider_error = provider.set_relation_error.call_args.kwargs["provider_error"]
    assert provider_error.relation_id == request.relation_id
    assert provider_error.certificate_signing_request == csr
    assert provider_error.error.code == CertificateRequestErrorCode.OTHER
    assert provider_error.error.name == "DUPLICATE_REQUEST"


@pytest.mark.parametrize("reason", [None, "Certificate request was rejected by Notary"])
def test_given_submission_failure_when_sync_then_request_error_recorded(reason: str | None):
    context = Context(NotaryCharm)
    csr = generate_csr(generate_private_key(), "request.example")
    request = RequirerCertificateRequest(1, csr, False)
    provider = Mock(relationship_name=MANAGED_CERTIFICATES_RELATION_NAME)
    provider.get_certificate_requests.return_value = [request]
    client = Mock()
    client.list_certificate_requests.return_value = []
    client.create_certificate_request.return_value = None
    if reason:
        client.create_certificate_request.side_effect = NotaryClientError(reason)
    with (
        patch.object(NotaryCharm, "client", new_callable=PropertyMock, return_value=client),
        context(context.on.collect_unit_status(), State(leader=True)) as manager,
    ):
        manager.charm._sync_certificate_requirers(provider, "token")

    provider.set_relation_certificate.assert_not_called()
    provider.set_relation_error.assert_called_once()
    provider_error = provider.set_relation_error.call_args.kwargs["provider_error"]
    assert provider_error.relation_id == request.relation_id
    assert provider_error.certificate_signing_request == csr
    assert provider_error.error.code == CertificateRequestErrorCode.OTHER
    assert provider_error.error.name == "REQUEST_SUBMISSION_FAILED"
    assert provider_error.error.reason == (reason or "Notary returned no certificate request")
    assert provider_error.error.provider == "notary"


@pytest.mark.parametrize(
    "available, code, name, reason",
    [
        (True, CertificateRequestErrorCode.OTHER, "SIGNING_FAILED", None),
        (
            True,
            CertificateRequestErrorCode.OTHER,
            "SIGNING_FAILED",
            "Certificate authority is disabled",
        ),
        (False, CertificateRequestErrorCode.SERVER_NOT_AVAILABLE, "SIGNING_UNAVAILABLE", None),
    ],
)
def test_given_signing_failure_when_sync_then_request_error_recorded(
    available: bool, code: CertificateRequestErrorCode, name: str, reason: str | None
):
    context = Context(NotaryCharm)
    csr = generate_csr(generate_private_key(), "request.example")
    request = RequirerCertificateRequest(1, csr, False)
    provider = Mock(relationship_name=SELF_SIGNED_CERTIFICATES_RELATION_NAME)
    signing = Mock(return_value=False) if available else None
    if signing and reason:
        signing.side_effect = NotaryClientError(reason)
    with context(context.on.collect_unit_status(), State(leader=True)) as manager:
        assert not manager.charm._sign_requirer_request(provider, request, 1, signing)

    provider.set_relation_certificate.assert_not_called()
    provider.set_relation_error.assert_called_once()
    provider_error = provider.set_relation_error.call_args.kwargs["provider_error"]
    assert provider_error.relation_id == request.relation_id
    assert provider_error.certificate_signing_request == csr
    assert provider_error.error.code == code
    assert provider_error.error.name == name
    assert provider_error.error.provider == "notary"
    assert provider_error.error.reason == (
        reason
        or (
            "Notary did not complete certificate signing"
            if available
            else "Signing CA or ACME configuration is unavailable"
        )
    )


@pytest.mark.parametrize("operation", ["submission", "signing"])
@pytest.mark.parametrize("status", [200, 400, 500])
def test_certificate_client_preserves_errors_without_logging_payloads(
    operation: str, status: int, caplog: pytest.LogCaptureFixture
):
    client = object.__new__(Notary)
    client.__init__("https://notary.example")
    response = requests.Response()
    response.status_code = status
    response._content = b'{"data":{"id":7},"message":"private-api-message"}'
    with patch.object(client.session, "request", return_value=response):
        if status >= 400:
            with pytest.raises(NotaryClientError, match="private-api-message"):
                if operation == "submission":
                    client.create_certificate_request("private-csr", "private-token")
                else:
                    client.sign_certificate_request(7, "private-token")
        elif operation == "submission":
            result = client.create_certificate_request("private-csr", "private-token")
            assert result and result.id == 7
        else:
            assert client.sign_certificate_request(7, "private-token")
    assert "private-" not in caplog.text


@pytest.mark.parametrize("operation", ["submission", "signing", "login"])
def test_client_transport_failure_does_not_expose_private_data(
    operation: str, caplog: pytest.LogCaptureFixture
):
    client = object.__new__(Notary)
    client.__init__("https://notary.example")
    with patch.object(client.session, "request", side_effect=requests.Timeout("private-password")):
        if operation == "login":
            assert client.login("private-email", "private-password") is None
        else:
            with pytest.raises(NotaryClientError, match=r"^Unable to contact Notary \(Timeout\)$"):
                if operation == "submission":
                    client.create_certificate_request("private-csr", "private-token")
                else:
                    client.sign_certificate_request(7, "private-token")
    assert "private-" not in caplog.text


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
