# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for generating self signed certificates."""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_certificate(
    common_name: str,
    sans_ips: list[str],
    ca_common_name: str,
    validity: int,
) -> Tuple[str, str, str]:
    """Generate a certificate and private key.

    Args:
        common_name (str): Common name for the certificate
        sans_ips (list[str]): List of Subject Alternative Names (IPs)
        ca_common_name (str): Common name for the CA certificate
        validity (int): Certificate validity time (in days). The same value
            is used for the CA certificate.

    Returns:
        Tuple[str, str, str]: Certificate, CA Certificate, Private Key
    """
    private_key = _generate_private_key()
    ca_key = _generate_private_key()
    ca_certificate = _generate_ca_certificate(
        private_key=ca_key, common_name=ca_common_name, validity=validity
    )
    certificate = _generate_certificate(
        private_key=private_key,
        common_name=common_name,
        sans_ips=sans_ips,
        ca_cert=ca_certificate,
        ca_key=ca_key,
        validity=validity,
    )
    return certificate, ca_certificate, private_key


def certificate_issuer_has_common_name(certificate: str, common_name: str) -> bool:
    """Check if a certificate has a specific common name."""
    try:
        loaded_certificate = x509.load_pem_x509_certificate(certificate.encode())
        issuer_common_name = loaded_certificate.issuer.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0]
    except (ValueError, TypeError):
        logger.warning("Failed to load certificate")
        return False
    return issuer_common_name.value == common_name


def _generate_private_key() -> str:
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_bytes.decode().strip()


def _generate_certificate(
    private_key: str,
    common_name: str,
    sans_ips: List[str],
    ca_cert: str,
    ca_key: str,
    validity: int,
) -> str:
    """Generate a self-signed certificate directly."""
    private_key_obj = serialization.load_pem_private_key(private_key.encode(), password=None)
    assert isinstance(private_key_obj, rsa.RSAPrivateKey)
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert.encode())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert_obj.issuer)
        .public_key(private_key_obj.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(san)) for san in sans_ips]
            ),
            critical=False,
        )
    )
    cert = cert_builder.sign(
        private_key=serialization.load_pem_private_key(ca_key.encode(), password=None),  # type: ignore[reportArgumentType]
        algorithm=hashes.SHA256(),
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def _generate_ca_certificate(
    private_key: str,
    common_name: str,
    validity: int,
) -> str:
    """Generate a CA Certificate.

    Args:
        private_key (bytes): Private key
        common_name (str): Certificate common name.
        validity (int): Certificate validity time (in days)
        country (str): Certificate Issuing country

    Returns:
        str: CA Certificate
    """
    private_key_object = serialization.load_pem_private_key(private_key.encode(), password=None)
    assert isinstance(private_key_object, rsa.RSAPrivateKey)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()
