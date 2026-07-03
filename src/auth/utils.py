import json
import os

from datetime import datetime, timezone, timedelta


def check_keys_device() -> bool:
    files = ["device.json", "keys.json"]
    if not all(os.path.exists(f) for f in files):
        return False
    with open("device.json", "r") as f:
        data = json.load(f)
        if "device_id" not in data or "install_id" not in data or "pin_hash" not in data:
            return False
    with open("keys.json", "r") as f:
        data = json.load(f)
        if "private_key" not in data or "public_key" not in data:
            return False
    return True

def check_session() -> bool:
    if not os.path.exists("session.json"):
        return False
    with open("session.json", "r") as f:
        data = json.load(f)
        if "x509" not in data or "token_sn" not in data or "user_id_hash" not in data:
            return False
    return True

def save_session(x509: str, token_sn: str, user_id_hash: str) -> None:
    with open("session.json", "w") as f:
        json.dump({"x509": x509, "token_sn": token_sn, "user_id_hash": user_id_hash}, f, indent=4)


def get_session() -> tuple[str, str, str]:
    with open("session.json", "r") as f:
        data = json.load(f)
    x509 = data["x509"]
    token_sn = data["token_sn"]
    user_id_hash = data["user_id_hash"]
    return x509, token_sn, user_id_hash


def save_device(device_id: str, install_id: str, pin_hash: str) -> None:
    with open("device.json", "w") as f:
        json.dump({"device_id": device_id, "install_id": install_id, "pin_hash": pin_hash}, f, indent=4)

def save_keys(private_key: str, public_key: str) -> None:
    with open("keys.json", "w") as f:
        json.dump({"private_key": private_key, "public_key": public_key}, f, indent=4)


def get_device():
    with open("device.json", "r") as f:
        data = json.load(f)
    device_id = data["device_id"]
    install_id = data["install_id"]
    pin_hash = data.get("pin_hash", "")
    return device_id, install_id, pin_hash


def get_current_time() -> str:
    tz = timezone(timedelta(hours=5))
    dt = datetime.now(tz)
    formatted_dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + dt.strftime('%z')
    return formatted_dt
