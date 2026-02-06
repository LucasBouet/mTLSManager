from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pathlib import Path

CA_DIR = Path("data/ca")
SERVER_DIR = Path("data/servers")

def create_server_cert(domain: str):
    SERVER_DIR.mkdir(exist_ok=True)

    ca_key = serialization.load_pem_private_key(
        (CA_DIR / "intermediate.key").read_bytes(),
        password=None
    )

    ca_cert = x509.load_pem_x509_certificate(
        (CA_DIR / "intermediate.crt").read_bytes()
    )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain)
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName(domain),
        x509.DNSName(f"*.{domain}")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=825))  # browser-safe
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = SERVER_DIR / f"{domain}.crt"
    key_path = SERVER_DIR / f"{domain}.key"
    chain_path = SERVER_DIR / f"{domain}.fullchain.crt"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )

    # fullchain = server cert + intermediate
    chain_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    return {
        "cert": cert_path,
        "key": key_path,
        "fullchain": chain_path,
        "serial": cert.serial_number
    }
