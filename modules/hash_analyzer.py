import re
import hashlib
import hmac
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

ph = PasswordHasher()

def identify_hash(value: str) -> dict:
    value = (value or "").strip()
    if value.startswith("$argon2id$"):
        return {"algorithm": "Argon2id", "risk": "Low", "confidence": "High",
                "note": "Encoded Argon2id hash detected. Review its memory, time and parallelism parameters."}
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return {"algorithm": "bcrypt", "risk": "Low", "confidence": "High",
                "note": "bcrypt-formatted hash detected. Check the work factor."}
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return {"algorithm": "MD5 (possible)", "risk": "Critical", "confidence": "Low",
                "note": "Length/hex pattern only; many formats can look like this. MD5 is unsuitable for password storage."}
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return {"algorithm": "SHA-1 (possible)", "risk": "High", "confidence": "Low",
                "note": "Length/hex pattern only; this is not definitive identification. SHA-1 is unsuitable for password storage."}
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return {"algorithm": "SHA-256 (possible)", "risk": "High", "confidence": "Low",
                "note": "Length/hex pattern only; SHA-256 is fast and not appropriate alone for password storage."}
    return {"algorithm": "Unknown / unsupported", "risk": "Unknown", "confidence": "Low",
            "note": "Could not identify this format. Identification by appearance is inherently limited."}

def verify_password(password: str, encoded_hash: str) -> dict:
    encoded_hash = (encoded_hash or "").strip()
    try:
        if encoded_hash.startswith("$argon2id$"):
            ph.verify(encoded_hash, password)
            return {"supported": True, "matches": True, "message": "Password matches the Argon2id hash."}
        if encoded_hash.startswith(("$2a$", "$2b$", "$2y$")):
            matches = bcrypt.checkpw(password.encode("utf-8"), encoded_hash.encode("utf-8"))
            return {"supported": True, "matches": bool(matches),
                    "message": "Password matches the bcrypt hash." if matches else "Password does not match the bcrypt hash."}
        return {"supported": False, "matches": None,
                "message": "Verification is supported only for Argon2id and bcrypt encoded hashes in this version."}
    except (VerifyMismatchError, VerificationError, ValueError):
        return {"supported": True, "matches": False, "message": "Password does not match or the hash is invalid."}

def create_demo_hash(password: str, algorithm: str) -> str:
    if algorithm == "Argon2id":
        return ph.hash(password)
    if algorithm == "bcrypt":
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    raise ValueError("Only Argon2id and bcrypt demo hashes can be generated.")

HASH_STRENGTH_COMPARISON = [
    {"algorithm":"Argon2id","password_storage":"Recommended modern adaptive KDF","relative_strength":"Very high","risk":"Low","notes":"Memory-hard; tune memory/time/parallelism for deployment."},
    {"algorithm":"bcrypt","password_storage":"Acceptable legacy adaptive KDF","relative_strength":"High","risk":"Low to medium","notes":"Adaptive work factor; consider migration planning where appropriate."},
    {"algorithm":"PBKDF2-HMAC-SHA256","password_storage":"Acceptable when configured strongly","relative_strength":"High","risk":"Configuration-dependent","notes":"Iteration count and salt must be appropriate."},
    {"algorithm":"SHA-256 / SHA-1 / MD5","password_storage":"Not suitable alone for password storage","relative_strength":"Low for password storage","risk":"High / Critical","notes":"Fast general-purpose hashes; use a salted adaptive password hashing scheme instead."},
]

def compare_hash_strengths():
    """Return a static educational comparison, not a benchmark."""
    return HASH_STRENGTH_COMPARISON
