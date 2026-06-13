from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet 
from cryptography import x509
import base64
import json
import jwt
import datetime
import os

app = FastAPI()

SECRET_KEY = "my-super-secret-key"
ALGORITHM = "HS256"
security = HTTPBearer()


fake_users_db = {
    "Alice": {
        "password": "user123",
        "role": "user"
    },
    "admin": {
        "password": "admin123",
        "role": "admin"
    }
}


class UserData(BaseModel):
    user: str
    role: str


class SignedData(BaseModel):
    data: UserData
    signature: str


class LoginData(BaseModel):
    username: str
    password: str


class SensitiveData(BaseModel):
    user: str
    role: str
    secret_message: str


class EncryptedData(BaseModel):
    encrypted_data: str


def load_private_key():
    with open("keys/private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


def load_public_key():
    with open("keys/public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )
    

def load_certificate():
    with open("keys/certificate.pem", "rb") as cert_file:
        return cert_file.read().decode("utf-8")
    

def load_public_key_from_certificate():
    with open("keys/certificate.pem", "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read())

    return certificate.public_key()
    

def get_or_create_encryption_key():
    key_path = "keys/encryption_key.key"

    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)

    with open(key_path, "rb") as key_file:
        return key_file.read()


def get_fernet():
    key = get_or_create_encryption_key()
    return Fernet(key)


def convert_data_to_bytes(data: UserData):
    data_dict = data.model_dump()
    data_json = json.dumps(data_dict, sort_keys=True)
    return data_json.encode("utf-8")


@app.post("/send-data")
def receive_data(data: UserData):
    return {
        "message": "Data received without protection",
        "user": data.user,
        "role": data.role
    }


@app.post("/sign-data")
def sign_data(data: UserData):
    private_key = load_private_key()
    data_bytes = convert_data_to_bytes(data)

    signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_base64 = base64.b64encode(signature).decode("utf-8")

    return {
        "data": data,
        "signature": signature_base64
    }


@app.post("/verify-data")
def verify_data(signed_data: SignedData):
    public_key = load_public_key_from_certificate()

    data_bytes = convert_data_to_bytes(signed_data.data)
    signature = base64.b64decode(signed_data.signature)

    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return {
            "message": "Signature is valid. Data is authentic and unchanged.",
            "verification_method": "Public key extracted from certificate",
            "data": signed_data.data
        }

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid signature. Data may have been modified or the certificate/key does not match."
        )
    

@app.get("/certificate")
def get_certificate():
    certificate = load_certificate()

    return {
        "message": "Self-signed certificate loaded successfully",
        "certificate_owner": "Trusted Data Sender",
        "algorithm": "RSA with SHA-256",
        "purpose": "This certificate contains the public key used to verify digital signatures.",
        "certificate": certificate
    }


@app.post("/encrypt-data")
def encrypt_data(data: SensitiveData):
    fernet = get_fernet()

    data_dict = data.model_dump()
    data_json = json.dumps(data_dict, sort_keys=True)
    encrypted_data = fernet.encrypt(data_json.encode("utf-8"))

    return {
        "message": "Data encrypted successfully",
        "algorithm": "Fernet symmetric encryption",
        "encrypted_data": encrypted_data.decode("utf-8")
    }


@app.post("/decrypt-data")
def decrypt_data(
    encrypted_input: EncryptedData,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    payload = verify_jwt_token(credentials)
    fernet = get_fernet()

    try:
        decrypted_bytes = fernet.decrypt(encrypted_input.encrypted_data.encode("utf-8"))
        decrypted_json = decrypted_bytes.decode("utf-8")
        decrypted_data = json.loads(decrypted_json)

        return {
            "message": "Data decrypted successfully",
            "access_granted_to": payload["username"],
            "role": payload["role"],
            "decrypted_data": decrypted_data
        }

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid encrypted data or decryption failed"
        )


@app.post("/login")
def login(login_data: LoginData):
    user = fake_users_db.get(login_data.username)

    if not user or user["password"] != login_data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    payload = {
        "username": login_data.username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }


def verify_jwt_token(credentials: HTTPAuthorizationCredentials):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/protected-data")
def protected_data(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt_token(credentials)

    return {
        "message": "Access granted to protected data",
        "user": payload["username"],
        "role": payload["role"]
    }


@app.get("/admin-data")
def admin_data(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt_token(credentials)

    if payload["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied. Admin role required."
        )

    return {
        "message": "Welcome admin. Access granted.",
        "user": payload["username"],
        "role": payload["role"]
    }