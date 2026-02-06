from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pathlib import Path

CA_DIR = Path("data/ca")

def ca_exists():
    return (CA_DIR / "intermediate.crt").exists()

def init_ca():
    CA_DIR.mkdir(parents=True, exist_ok=True)

    root_key = rsa.generate_private_key(65537, 4096)
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mTLS Root CA")
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
        .sign(root_key, hashes.SHA256())
    )

    (CA_DIR / "root.key").write_bytes(
        root_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )
    (CA_DIR / "root.crt").write_bytes(
        root_cert.public_bytes(serialization.Encoding.PEM)
    )

    inter_key = rsa.generate_private_key(65537, 4096)
    inter_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mTLS Intermediate CA")
    ])

    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(root_key, hashes.SHA256())
    )

    (CA_DIR / "intermediate.key").write_bytes(
        inter_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )
    (CA_DIR / "intermediate.crt").write_bytes(
        inter_cert.public_bytes(serialization.Encoding.PEM)
    )
