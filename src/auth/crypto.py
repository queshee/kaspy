import base64
import hashlib
import json
import uuid
from random import randint
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generate_keypair_base64() -> tuple[str, str]:
    private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    public_key: ec.EllipticCurvePublicKey = private_key.public_key()
    
    private_key: str = base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    ).decode('utf-8')
    
    public_key: str = base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode('utf-8')
    
    return private_key, public_key

def get_pk(public_key: str) -> str:
    pub_key_der = base64.b64decode(public_key)
    uncompressed_point = pub_key_der[-65:]
    return base64.b64encode(uncompressed_point).decode("utf-8")

def get_pk_tag(public_key: str) -> str:
    pk = get_pk(public_key)
    return hashlib.md5(pk.encode('utf-8')).hexdigest()

def get_pin_hash() -> str:
    with open("keys.json", "r") as f:
        data = json.load(f)
    return data["pin_hash"]

def get_keys() -> tuple[str, str]:
    with open("keys.json", "r") as f:
        data = json.load(f)
    return data["private_key"], data["public_key"]

def generate_pin_hash(pin: str = str(randint(1000, 9999))) -> str:
    return hashlib.sha256(pin.encode('utf-8')).hexdigest()
    
def generate_upper_uuid() -> str:
    return str(uuid.uuid4()).upper()

def sign_data(data: str, private_key: str | None = None) -> str:
    if private_key is None:
        private_key = get_keys()[0]
    private_bytes = base64.b64decode(private_key)
    pk = serialization.load_der_private_key(private_bytes, password=None)
    signature = pk.sign(data.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def compute_x_su(url: str) -> str:
    return hashlib.md5(url.lower().encode('utf-8')).hexdigest()

def compute_x_sign(url: str, headers: dict, x_sh: str): 
    parts = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    formatted_x_shs: list[str] = x_sh.split(",")
    for sh in formatted_x_shs:
        if sh == "url":
            parsed = urlparse(url)
            path_and_query = parsed.path
            if parsed.query:
                path_and_query += f"?{parsed.query}"
            parts.append(path_and_query if parsed.query else url)
        else:
            parts.append(str(lower_headers.get(sh.lower(), "")))
    string_to_sign: str = "".join(parts)
    return sign_data(string_to_sign)
        

