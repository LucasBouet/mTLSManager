from fastapi import FastAPI
from app.api import ca, certs
from app.db import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="mTLS Manager v1")

app.include_router(ca.router)
app.include_router(certs.router)
