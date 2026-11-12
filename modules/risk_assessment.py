def calculate_risk(strength: dict, policy: dict, hash_info: dict | None = None, password_age_days: int | None = None, reuse_detected=False) -> dict:
    risk=0; reasons=[]
    score=strength.get("score",0)
    if score<=1: risk+=30; reasons.append("Weak password-strength estimate")
    elif score==2: risk+=18; reasons.append("Fair password-strength estimate")
    elif score==3: risk+=7
    if strength.get("common"): risk+=20; reasons.append("Password matched the local common-password blocklist")
    patterns=strength.get("patterns",{})
    if patterns.get("dictionary_word"): risk+=10; reasons.append("Dictionary-based password pattern detected")
    if patterns.get("repeated_characters"): risk+=8; reasons.append("Repeated character pattern detected")
    if patterns.get("sequential_pattern"): risk+=8; reasons.append("Sequential pattern detected")
    failed=policy.get("total",0)-policy.get("passed",0)
    if failed: risk+=min(25,failed*5); reasons.append(f"{failed} password policy requirement(s) failed")
    max_age=policy.get("max_age_days")
    if password_age_days is not None and max_age is not None and password_age_days>int(max_age): risk+=10; reasons.append("Password age exceeds the configured review threshold")
    if reuse_detected: risk+=25; reasons.append("Password reuse detected across assessed accounts or history")
    if hash_info:
        hr=hash_info.get("risk")
        if hr=="Critical": risk+=20; reasons.append("Potentially deprecated hash format")
        elif hr=="High": risk+=15; reasons.append("Fast or deprecated hash format is unsuitable for password storage")
        elif hr=="Unknown": risk+=5; reasons.append("Hash format could not be assessed")
    risk=min(100,risk)
    level="Low" if risk<=20 else "Medium" if risk<=40 else "High" if risk<=70 else "Critical"
    return {"score":risk,"level":level,"reasons":reasons}
