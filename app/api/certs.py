from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import SessionLocal
from app.models.cert import ClientCert
from app.core.certs import create_client_cert, create_client_p12
from app.core.crl import generate_crl
from fastapi.responses import FileResponse

router = APIRouter(prefix="/certs")

def db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/")
def create(cn: str, db: Session = Depends(db)):
    if db.query(ClientCert).filter_by(common_name=cn).first():
        raise HTTPException(400, "Cert already exists")

    serial, _, _ = create_client_cert(cn)
    cert = ClientCert(
        common_name=cn,
        serial_number=str(serial),
        revoked=False
    )
    db.add(cert)
    db.commit()
    return {"cn": cn, "serial": serial}

@router.get("/")
def list(db: Session = Depends(db)):
    return db.query(ClientCert).all()

@router.post("/{cn}/revoke")
def revoke(cn: str, db: Session = Depends(db)):
    cert = db.query(ClientCert).filter_by(common_name=cn).first()
    if not cert:
        raise HTTPException(404, "Not found")

    cert.revoked = True
    db.commit()

    revoked = [
        c.serial_number for c in db.query(ClientCert).filter_by(revoked=True)
    ]
    generate_crl(revoked)

    return {"status": "revoked"}

@router.post("/{cn}/p12")
def generate_p12(
    cn: str,
    password: str | None = None,
):
    try:
        p12_path = create_client_p12(cn, password)
    except FileNotFoundError:
        raise HTTPException(404, "Certificate not found")

    return {
        "status": "created",
        "file": str(p12_path),
        "password_protected": bool(password)
    }

@router.get("/{cn}/p12")
def download_p12(cn: str):
    p12_path = f"data/certs/{cn}.p12"

    return FileResponse(
        p12_path,
        media_type="application/x-pkcs12",
        filename=f"{cn}.p12"
    )
