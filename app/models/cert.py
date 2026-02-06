from sqlalchemy import Column, Integer, String, Boolean
from app.db import Base

class ClientCert(Base):
    __tablename__ = "client_certs"

    id = Column(Integer, primary_key=True)
    common_name = Column(String, unique=True)
    serial_number = Column(String, unique=True)
    revoked = Column(Boolean, default=False)
