from fastapi import APIRouter, HTTPException
from app.core.server_certs import create_server_cert

router = APIRouter(prefix="/servers")

@router.post("/")
def create(domain: str):
    if "." not in domain:
        raise HTTPException(400, "Invalid domain")

    result = create_server_cert(domain)

    return {
        "domain": domain,
        "files": {
            "cert": str(result["cert"]),
            "key": str(result["key"]),
            "fullchain": str(result["fullchain"])
        },
        "serial": str(result["serial"])
    }
