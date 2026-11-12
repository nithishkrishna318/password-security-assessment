def build_recommendations(strength: dict, policy: dict, hash_info: dict | None = None,
                          risk: dict | None = None) -> list[str]:
    items = []
    if strength.get("score", 0) < 3:
        items.append("Replace weak passwords with unique, longer passphrases.")
    if strength.get("common"):
        items.append("Block this password because it appears in the local common-password list.")
    if not policy.get("compliant", False):
        items.append("Update the password to satisfy the configured organization policy.")
    if hash_info and hash_info.get("risk") in ("High", "Critical"):
        items.append("Migrate password storage to a salted, adaptive password hash such as Argon2id.")
    items.extend([
        "Enable multi-factor authentication for important accounts.",
        "Use a reputable password manager to generate and store unique passwords."
    ])
    return list(dict.fromkeys(items))
