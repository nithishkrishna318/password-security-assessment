import unittest, sqlite3
from modules.password_history import check_history, store_history
from modules.password_strength import analyze_password, pattern_findings, estimate_entropy
from modules.policy_checker import check_policy
from modules.risk_assessment import calculate_risk

class PasswordAssessmentTests(unittest.TestCase):
    def test_entropy_empty(self): self.assertEqual(estimate_entropy(""),0.0)
    def test_common_password_flagged(self): self.assertTrue(analyze_password("password123")["common"])
    def test_repeated_pattern_detected(self): self.assertTrue(pattern_findings("Abc1111!xyz")["repeated_characters"])
    def test_sequence_detected(self): self.assertTrue(pattern_findings("Abc12345!xyz")["sequential_pattern"])
    def test_dictionary_detected(self): self.assertTrue(pattern_findings("Welcome!2026")["dictionary_word"])
    def test_policy_age_violation(self):
        result=check_policy("ValidPassword!2026",{"min_length":12,"uppercase":True,"lowercase":True,"number":True,"special":True,"max_age_days":90},120)
        self.assertFalse(result["compliant"])
        self.assertIn("Password age within configured maximum",result["checks"])
    def test_reuse_increases_risk(self):
        s=analyze_password("ThisIsALongUniquePassphrase!2026")
        p=check_policy("ThisIsALongUniquePassphrase!2026",{"min_length":12,"uppercase":True,"lowercase":True,"number":True,"special":True})
        normal=calculate_risk(s,p)
        reused=calculate_risk(s,p,reuse_detected=True)
        self.assertGreater(reused["score"],normal["score"])
    def test_risk_has_four_levels(self):
        self.assertIn(calculate_risk({"score":0,"common":True,"patterns":{}},{"passed":0,"total":5})["level"],["Low","Medium","High","Critical"])
    def test_password_history_detects_previous_password(self):
        c=sqlite3.connect(":memory:"); c.row_factory=sqlite3.Row
        c.execute("CREATE TABLE password_fingerprints(id INTEGER PRIMARY KEY,account_fp TEXT,password_fp TEXT,created_at TEXT)")
        store_history(c,"test-secret","alice","UniqueSynthetic!2026")
        result=check_history(c,"test-secret","alice","UniqueSynthetic!2026",5)
        self.assertTrue(result["previously_used_by_account"])
    def test_password_history_detects_cross_account_reuse(self):
        c=sqlite3.connect(":memory:"); c.row_factory=sqlite3.Row
        c.execute("CREATE TABLE password_fingerprints(id INTEGER PRIMARY KEY,account_fp TEXT,password_fp TEXT,created_at TEXT)")
        store_history(c,"test-secret","alice","UniqueSynthetic!2026")
        result=check_history(c,"test-secret","bob","UniqueSynthetic!2026",5)
        self.assertTrue(result["reused_across_accounts"])

if __name__=="__main__": unittest.main()
