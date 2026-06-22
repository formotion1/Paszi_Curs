import json
import base64
import hashlib
import uuid
import wmi
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# === Получение данных оборудования ===
def get_hardware_info():
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

    return cpu_id, disk_serial, motherboard, mac


# === Генерация HWID ===
def generate_hwid(cpu_id, disk_serial, motherboard, mac):
    raw_string = cpu_id + disk_serial + motherboard + mac
    return hashlib.sha256(raw_string.encode()).hexdigest()


# === Обёртка (для совместимости) ===
def get_hwid():
    cpu_id, disk_serial, motherboard, mac = get_hardware_info()
    return generate_hwid(cpu_id, disk_serial, motherboard, mac)


# === Проверка лицензии ===
def verify_license(current_hwid):
    try:
        with open("license.json", "r") as f:
            license_data = json.load(f)

        signature = base64.b64decode(license_data.pop("signature"))
        data_bytes = json.dumps(license_data).encode()

        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

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
    cpu_id, disk_serial, motherboard, mac = get_hardware_info()

    print()
    print("=== Данные для формирования HWID ===")
    print()
    print("Серийный номер материнской платы:", motherboard)
    print("ID процессора:", cpu_id)
    print("Серийный номер диска:", disk_serial)
    print("MAC-адрес:", mac)
    print()

    hwid = generate_hwid(cpu_id, disk_serial, motherboard, mac)

    print("Your HWID:", hwid)
    print()

    if verify_license(hwid):
        print("Program is running...")
    else:
        print("Access denied.")