"""Keyed, non-reversible password-history fingerprints."""
import hashlib, hmac
from datetime import datetime, timezone

def make_fingerprint(secret: str, scope: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"),(scope+":"+value).encode("utf-8"),hashlib.sha256).hexdigest()

def check_history(conn, secret: str, account: str, password: str, history_count: int=5) -> dict:
    account_fp=make_fingerprint(secret,"account",account.strip().lower())
    password_fp=make_fingerprint(secret,"password",password)
    cross=bool(conn.execute("SELECT 1 FROM password_fingerprints WHERE password_fp=? AND account_fp<>? LIMIT 1",(password_fp,account_fp)).fetchone())
    rows=conn.execute("SELECT password_fp FROM password_fingerprints WHERE account_fp=? ORDER BY id DESC LIMIT ?",(account_fp,max(1,int(history_count)))).fetchall()
    return {"reused_across_accounts":cross,"previously_used_by_account":any(r["password_fp"]==password_fp for r in rows),"account_fp":account_fp,"password_fp":password_fp}

def store_history(conn, secret: str, account: str, password: str):
    account_fp=make_fingerprint(secret,"account",account.strip().lower())
    password_fp=make_fingerprint(secret,"password",password)
    conn.execute("DELETE FROM password_fingerprints WHERE account_fp=? AND password_fp=?",(account_fp,password_fp))
    conn.execute("INSERT INTO password_fingerprints(account_fp,password_fp,created_at) VALUES(?,?,?)",(account_fp,password_fp,datetime.now(timezone.utc).isoformat()))
