# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for generating self signed certificates."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_certificate(
    common_name: str,
    ca_common_name: str,
    validity: int,
) -> Tuple[str, str, str]:
    """Generate a certificate and private key.

    Args:
        common_name (str): Common name for the certificate
        ca_common_name (str): Common name for the CA certificate
        validity (int): Certificate validity time (in days). The same value
            is used for the CA certificate.
    """
    private_key = _generate_private_key()
    csr = _generate_csr(private_key=private_key, common_name=common_name)
    ca_key = _generate_private_key()
    ca = _generate_ca(private_key=ca_key, common_name=ca_common_name, validity=validity)
    certificate = _generate_certificate(csr=csr, ca=ca, ca_key=ca_key, validity=validity)
    return certificate, ca, private_key


def certificate_issuer_has_common_name(certificate: str, common_name: str) -> bool:
    """Check if a certificate has a specific common name."""
    try:
        loaded_certificate = x509.load_pem_x509_certificate(certificate.encode())
        issuer_common_name = loaded_certificate.issuer.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0]
    except (ValueError, TypeError):
        return False
    return issuer_common_name.value == common_name


def _generate_private_key() -> str:
    """Generate a private key.

    Returns:
        str: Private Key
    """
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


def _generate_csr(
    private_key: str,
    common_name: str,
) -> str:
    """Generate a CSR using private key and subject.

    Args:
        private_key (str): Private key
        common_name (str): CSR common name.

    Returns:
        str: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key.encode(), password=None)
    unique_identifier = uuid.uuid4()
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    subject_name.append(
        x509.NameAttribute(x509.NameOID.X500_UNIQUE_IDENTIFIER, str(unique_identifier))
    )
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM).decode().strip()


def _generate_certificate(
    csr: str,
    ca: str,
    ca_key: str,
    validity: int,
) -> str:
    """Generate a TLS certificate based on a CSR.

    Args:
        csr (str): CSR
        ca (str): CA Certificate
        ca_key (str): CA private key
        validity (int): Certificate validity (in days)

    Returns:
        str: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr.encode())
    csr_subject = csr_object.subject
    csr_common_name = csr_subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    issuer = x509.load_pem_x509_certificate(ca.encode()).issuer
    private_key = serialization.load_pem_private_key(ca_key.encode(), password=None)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, csr_common_name),
        ]
    )

    if validity > 0:
        not_valid_before = datetime.now(timezone.utc)
        not_valid_after = datetime.now(timezone.utc) + timedelta(days=validity)
    else:
        not_valid_before = datetime.now(timezone.utc) + timedelta(days=validity)
        not_valid_after = datetime.now(timezone.utc) - timedelta(seconds=1)
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )

    certificate_builder._version = x509.Version.v3
    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def _generate_ca(
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
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
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
