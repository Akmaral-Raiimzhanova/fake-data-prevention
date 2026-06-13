from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os


# Create keys folder if it does not exist
os.makedirs("keys", exist_ok=True)


# 1. Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Extract public key from private key
public_key = private_key.public_key()


# 3. Save private key
with open("keys/private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


# 4. Save public key
with open("keys/public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


# 5. Create self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sicily"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Messina"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Data Prevention Project"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Trusted Data Sender"),
])

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .sign(private_key, hashes.SHA256())
)


# 6. Save certificate
with open("keys/certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))


print("Private key, public key, and certificate generated successfully.")