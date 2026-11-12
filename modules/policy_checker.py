import re
from datetime import datetime, timezone

def check_policy(password: str, policy: dict, password_age_days=None) -> dict:
    checks={"Minimum length":len(password)>=int(policy.get("min_length",12)),"Uppercase letter":(not policy.get("uppercase")) or bool(re.search(r"[A-Z]",password)),"Lowercase letter":(not policy.get("lowercase")) or bool(re.search(r"[a-z]",password)),"Number":(not policy.get("number")) or bool(re.search(r"\d",password)),"Special character":(not policy.get("special")) or bool(re.search(r"[^A-Za-z0-9]",password))}
    max_age=policy.get("max_age_days")
    if max_age is not None and password_age_days is not None: checks["Password age within configured maximum"] = int(password_age_days)<=int(max_age)
    passed=sum(checks.values())
    return {"checks":checks,"passed":passed,"total":len(checks),"compliant":all(checks.values()),"max_age_days":max_age}
