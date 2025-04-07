import os
import requests
from fastapi import FastAPI, HTTPException, status
from jose import jwt, JWTError
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request

load_dotenv()
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")
KEYCLOAK_ISSUER = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
KEYCLOAK_CERTS_URL = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
PROTHETIC_ROLE = "prothetic_user"

app = FastAPI()
origins = ["http://localhost:3000"]  # your web app origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(token: str) -> dict:
    try:
        response = requests.get(KEYCLOAK_CERTS_URL)
        response.raise_for_status()
        jwks = response.json()
    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot fetch Keycloak public keys: {e}"
        )

    try:
        payload = jwt.decode(
            token=token,
            key=jwks,
            algorithms=["RS256"],
            issuer="http://localhost:8080/realms/reports-realm",
            options={"verify_aud": False}
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}"
        )

    return payload

def require_prothetic_user(token: str) -> None:
    payload = verify_token(token)
    realm_access = payload.get("realm_access", {})
    roles = realm_access.get("roles", [])

    if PROTHETIC_ROLE not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User does not have the required '{PROTHETIC_ROLE}' role."
        )

@app.get("/reports")
def get_reports(request: Request):
    authorization = request.headers.get("authorization")

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )


    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Must be 'Bearer <token>'."
        )

    token = parts[1]
    require_prothetic_user(token)

    return {
        "message": "Hello, prothetic_user!",
        "report_data": {
            "report_name": "Sample Usage Report",
            "contents": ["entry1", "entry2", "entry3"]
        }
    }
