import math, re
try:
    from zxcvbn import zxcvbn
except ImportError:  # lightweight fallback for offline test environments
    def zxcvbn(password):
        p = password or ""
        score = 0 if len(p) < 8 else 1 if len(p) < 10 else 2 if len(p) < 12 else 3 if len(set(p)) > 8 else 2
        return {"score": score, "feedback": {"suggestions": ["Use a longer, less predictable passphrase."] if score < 3 else []}, "crack_times_display": {"offline_slow_hashing_1e4_per_second": "unavailable without zxcvbn"}}

COMMON_PASSWORDS = {"password", "password123", "123456", "123456789", "qwerty", "qwerty123", "admin", "admin123", "letmein", "welcome", "iloveyou", "abc123", "111111", "123123", "changeme", "password1", "P@ssw0rd", "qwertyuiop"}
SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm")

def estimate_entropy(password: str) -> float:
    if not password: return 0.0
    pool = sum(n for pattern, n in [(r"[a-z]",26),(r"[A-Z]",26),(r"\d",10),(r"[^A-Za-z0-9]",33)] if re.search(pattern,password))
    return round(len(password)*math.log2(pool),1) if pool else 0.0

def pattern_findings(password: str) -> dict:
    p=password.lower()
    repeated=bool(re.search(r"(.)\1{2,}",p))
    sequential=False
    for seq in SEQUENCES:
        if any(seq[i:i+4] in p or seq[i:i+4][::-1] in p for i in range(len(seq)-3)):
            sequential=True; break
    dictionary=any(word in p for word in ("password","welcome","admin","qwerty","letmein","iloveyou"))
    return {"repeated_characters":repeated,"sequential_pattern":sequential,"dictionary_word":dictionary}

def analyze_password(password: str) -> dict:
    password=password if isinstance(password,str) else ""
    result=zxcvbn(password)
    score=int(result["score"])
    common=password.lower() in {x.lower() for x in COMMON_PASSWORDS}
    patterns=pattern_findings(password)
    checks={"length_12":len(password)>=12,"uppercase":bool(re.search(r"[A-Z]",password)),"lowercase":bool(re.search(r"[a-z]",password)),"number":bool(re.search(r"\d",password)),"special":bool(re.search(r"[^A-Za-z0-9]",password)),"not_common":not common,"no_repeated_runs":not patterns["repeated_characters"],"no_sequential_pattern":not patterns["sequential_pattern"]}
    labels=["Very weak","Weak","Fair","Strong","Very strong"]
    suggestions=list(result.get("feedback",{}).get("suggestions",[]))
    if common: suggestions.insert(0,"This password appears on the local common-password blocklist.")
    if patterns["dictionary_word"]: suggestions.append("Avoid predictable dictionary words and common password terms.")
    if patterns["repeated_characters"]: suggestions.append("Avoid repeated character runs.")
    if patterns["sequential_pattern"]: suggestions.append("Avoid keyboard or alphabetic/numeric sequences.")
    if len(password)<12: suggestions.append("Use a longer password or passphrase.")
    return {"score":score,"label":labels[score],"entropy_bits":estimate_entropy(password),"checks":checks,"common":common,"patterns":patterns,"length":len(password),"crack_time":result.get("crack_times_display",{}).get("offline_slow_hashing_1e4_per_second","unknown"),"suggestions":list(dict.fromkeys(suggestions))}
