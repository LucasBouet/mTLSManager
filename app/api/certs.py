from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import SessionLocal
from app.models.cert import ClientCert
from app.core.certs import create_client_cert
from app.core.crl import generate_crl

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
