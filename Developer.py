import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# === 1. Генерация ключей (сделать один раз и сохранить) ===
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # сохранить private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # сохранить public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated!")


# === 2. Генерация лицензии ===
def generate_license(hwid, expiration_date):
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    license_data = {
        "hwid": hwid,
        "expiration": expiration_date
    }

    data_bytes = json.dumps(license_data).encode()

    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    license_data["signature"] = base64.b64encode(signature).decode()

    with open("license.json", "w") as f:
        json.dump(license_data, f, indent=4)

    print("License generated!")


# === Пример использования ===
if __name__ == "__main__":
    # generate_keys()  # запустить 1 раз

    hwid = input("Enter HWID: ")
    expiration = "2027-01-01"

    generate_license(hwid, expiration)