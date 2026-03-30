import json
import base64
import hashlib
import uuid
import wmi
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# === 1. Генерация HWID ===
def get_hwid():
    c = wmi.WMI()

    try:
        cpu_id = c.Win32_Processor()[0].ProcessorId.strip()
    except:
        cpu_id = "unknown_cpu"

    try:
        disk_serial = c.Win32_DiskDrive()[0].SerialNumber.strip()
    except:
        disk_serial = "unknown_disk"

    try:
        motherboard = c.Win32_BaseBoard()[0].SerialNumber.strip()
    except:
        motherboard = "unknown_board"

    try:
        mac = hex(uuid.getnode())
    except:
        mac = "unknown_mac"

    raw_string = cpu_id + disk_serial + motherboard + mac
    hwid = hashlib.sha256(raw_string.encode()).hexdigest()

    return hwid


# === 2. Проверка лицензии ===
PUBLIC_KEY = b"""
/*
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkP6svES7LstL1dNWoxT/
xbXERVHk1Bqoa1bIzAW3X0qflAnCL1QiYS/sN3W7V2dSZr4Q+3uMkWeUwG9i1n2Y
agdyh06dOdP3Ia9mNBWTqLk5M8uwVVxEuQWkQLwGYyXwGvA20Z3/PuWjf8gL2U5Z
lwwtON0sBDPWJvLE+stGxBNGQGQ5/8pVXs7xQHs8e7JYz+qeTdcUn3bIOqbZtUt6
IuNfgmSk+B11vwDVEHwkfJq11dFWH6wRDl8G6m8O3i6HtqLB22wQUKdY2JVU3VMH
FQRg/jRQRCiyjUxL7KYeuaCPRi7d52zcRawNK089lxMXtk+xExji1yI0kkDaBW90
CwIDAQAB
-----END PUBLIC KEY-----
*/
"""

def verify_license(current_hwid):
    try:
        with open("license.json", "r") as f:
            license_data = json.load(f)

        signature = base64.b64decode(license_data.pop("signature"))
        data_bytes = json.dumps(license_data).encode()

        public_key = serialization.load_pem_public_key(PUBLIC_KEY)

        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        if license_data["hwid"] != current_hwid:
            print("License is not valid for this computer")
            return False

        exp_date = datetime.strptime(license_data["expiration"], "%Y-%m-%d")
        if datetime.now() > exp_date:
            print("License expired")
            return False

        print("License is valid!")
        return True

    except Exception as e:
        print("License check failed:", e)
        return False


# === Точка входа ===
if __name__ == "__main__":
    print("Your HWID:", get_hwid())
    print()

    if verify_license(get_hwid()):
        print("Program is running...")
    else:
        print("Access denied.")
