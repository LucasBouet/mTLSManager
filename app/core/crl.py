from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
from pathlib import Path

CA_DIR = Path("data/ca")

def generate_crl(serials):
    ca_key = serialization.load_pem_private_key(
        (CA_DIR / "intermediate.key").read_bytes(),
        password=None
    )
    ca_cert = x509.load_pem_x509_certificate(
        (CA_DIR / "intermediate.crt").read_bytes()
    )

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(datetime.utcnow())
        .next_update(datetime.utcnow() + timedelta(days=7))
    )

    for serial in serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial))
            .revocation_date(datetime.utcnow())
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(ca_key, hashes.SHA256())
    (CA_DIR / "crl.pem").write_bytes(
        crl.public_bytes(serialization.Encoding.PEM)
    )
