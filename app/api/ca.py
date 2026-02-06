from fastapi import APIRouter, HTTPException
from app.core.ca import init_ca, ca_exists

router = APIRouter(prefix="/ca")

@router.post("/init")
def init():
    if ca_exists():
        raise HTTPException(400, "CA already initialized")
    init_ca()
    return {"status": "CA initialized"}
