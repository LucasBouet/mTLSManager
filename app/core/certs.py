from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pathlib import Path

CA_DIR = Path("data/ca")
CERT_DIR = Path("data/certs")

def create_client_cert(cn: str):
    CERT_DIR.mkdir(exist_ok=True)

    ca_key = serialization.load_pem_private_key(
        (CA_DIR / "intermediate.key").read_bytes(),
        password=None
    )
    ca_cert = x509.load_pem_x509_certificate(
        (CA_DIR / "intermediate.crt").read_bytes()
    )

    key = rsa.generate_private_key(65537, 2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn)
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = CERT_DIR / f"{cn}.crt"
    key_path = CERT_DIR / f"{cn}.key"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )

    return cert.serial_number, cert_path, key_path
