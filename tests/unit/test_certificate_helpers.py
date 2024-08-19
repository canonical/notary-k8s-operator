# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from cryptography import x509

from certificates_helpers import certificate_issuer_has_common_name, generate_certificate


def test_given_sans_when_generate_certificate_then_certificate_contains_expected_attributes():
    common_name = "banana.com"
    sans_ips = ["1.2.3.4"]
    ca_common_name = "apple.com"

    certificate, ca_certificate, private_key = generate_certificate(
        common_name=common_name,
        sans_dns=["banana.com"],
        sans_ips=sans_ips,
        ca_common_name=ca_common_name,
        validity=365,
    )

    loaded_cert = x509.load_pem_x509_certificate(certificate.encode())

    # Validate the common name
    cert_common_name = loaded_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
        0
    ].value
    assert common_name == cert_common_name

    # Validate the SANs IPs
    sans = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    sans_ips_from_cert = [ip.compressed for ip in sans.value.get_values_for_type(x509.IPAddress)]
    assert sans_ips == sans_ips_from_cert

    # Validate the SANs DNS
    sans_dns_from_cert = list(sans.value.get_values_for_type(x509.DNSName))
    assert ["banana.com"] == sans_dns_from_cert


def test_given_cert_issuer_has_common_name_when_certificate_issuer_has_common_name_then_return_true():
    common_name = "banana.com"
    sans_ips = ["1.2.3.4"]
    ca_common_name = "apple.com"

    certificate, ca_certificate, private_key = generate_certificate(
        common_name=common_name,
        sans_dns=["banana.com"],
        sans_ips=sans_ips,
        ca_common_name=ca_common_name,
        validity=365,
    )

    assert certificate_issuer_has_common_name(certificate, ca_common_name)
