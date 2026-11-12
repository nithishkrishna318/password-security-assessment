import csv, io, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from modules.password_strength import analyze_password
from modules.hash_analyzer import identify_hash, verify_password, create_demo_hash, compare_hash_strengths
from modules.policy_checker import check_policy
from modules.risk_assessment import calculate_risk
from modules.recommendations import build_recommendations
from modules.password_history import make_fingerprint, check_history, store_history
from reports.pdf_report import create_pdf
from reports.excel_report import create_excel

app=Flask(__name__); app.config.from_object(Config)
DEFAULT_POLICY={"min_length":12,"uppercase":True,"lowercase":True,"number":True,"special":True,"max_age_days":180,"history_count":5}
LATEST_REPORT={}
COMPLIANCE_CONTROLS=[
 {"framework":"NIST SP 800-63B","control":"Password length, blocklist screening, compromised-password resistance","feature":"Strength analysis, configurable length policy, local common-password screening","status":"Partially implemented","note":"Local educational blocklist only; not a complete breached-password service."},
 {"framework":"OWASP Authentication Cheat Sheet","control":"Authentication, MFA, password policy, login protection","feature":"Admin login, password change, MFA recommendations, password policy settings","status":"Partially implemented","note":"No actual MFA enrollment or production-grade login throttling."},
 {"framework":"OWASP Password Storage Cheat Sheet","control":"Adaptive password hashing, salts, secure verification","feature":"Argon2id/bcrypt demo hash generation and verification","status":"Implemented for demo hash utilities","note":"Does not inspect an external organization's live password database."},
 {"framework":"ISO/IEC 27001:2022","control":"Access control, authentication information, logging and monitoring","feature":"Admin-only access, password controls, audit logs, security events","status":"Partially implemented","note":"Conceptual mapping only; not an ISO certification or full ISMS assessment."},
 {"framework":"CIS Controls v8","control":"Account management, access control management, audit log management","feature":"Account assessment, access restriction, audit/event records","status":"Partially implemented","note":"Selected project controls only; not a complete CIS Controls assessment."},
]

def db():
    c=sqlite3.connect(app.config["DATABASE"]); c.row_factory=sqlite3.Row; return c

def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL)")
        cols=[r[1] for r in c.execute("PRAGMA table_info(admins)").fetchall()]
        if "role" not in cols: c.execute("ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        c.execute("CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,strength_score INTEGER NOT NULL,risk_score INTEGER NOT NULL,risk_level TEXT NOT NULL,policy_compliant INTEGER NOT NULL,hash_algorithm TEXT,source TEXT DEFAULT 'single')")
        c.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS password_fingerprints(id INTEGER PRIMARY KEY AUTOINCREMENT,account_fp TEXT NOT NULL,password_fp TEXT NOT NULL,created_at TEXT NOT NULL,assessment_id INTEGER,UNIQUE(account_fp,password_fp))")
        c.execute("CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,severity TEXT NOT NULL,event_type TEXT NOT NULL,details TEXT NOT NULL)")
        if not c.execute("SELECT id FROM admins LIMIT 1").fetchone(): c.execute("INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)",("admin",generate_password_hash("ChangeMe123!"),"admin"))
        if not c.execute("SELECT 1 FROM settings WHERE key='policy'").fetchone(): c.execute("INSERT INTO settings VALUES('policy',?)",(json.dumps(DEFAULT_POLICY),))

def log_event(event_type,details,severity="INFO"):
    with db() as c: c.execute("INSERT INTO security_events(created_at,severity,event_type,details) VALUES(?,?,?,?)",(datetime.now(timezone.utc).isoformat(),severity,event_type,str(details)[:500]))

def audit(report,source="single"):
    with db() as c:
        cur=c.execute("INSERT INTO audit_logs(created_at,strength_score,risk_score,risk_level,policy_compliant,hash_algorithm,source) VALUES(?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),report["strength"]["score"],report["risk"]["score"],report["risk"]["level"],int(report["policy"]["compliant"]),(report.get("hash_info") or {}).get("algorithm","Not assessed"),source))
        return cur.lastrowid

def login_required(fn):
    @wraps(fn)
    def wrapper(*a,**kw):
        if not session.get("admin_id"): return redirect(url_for("login"))
        return fn(*a,**kw)
    return wrapper

def get_policy():
    with db() as c: r=c.execute("SELECT value FROM settings WHERE key='policy'").fetchone()
    return json.loads(r["value"]) if r else DEFAULT_POLICY.copy()

def history_check(account,password):
    with db() as c:
        return check_history(c,app.config["SECRET_KEY"],account,password,get_policy().get("history_count",5))

def store_fingerprint(account,password):
    if not account or not password: return
    with db() as c: store_history(c,app.config["SECRET_KEY"],account,password)

def assess_one(password,age=None,hash_value="",account="",persist=True):
    strength=analyze_password(password); policy=check_policy(password,get_policy(),age)
    hash_info=identify_hash(hash_value) if hash_value else None
    hist=history_check(account,password) if account else {"reused_across_accounts":False,"previously_used_by_account":False}
    reused=hist["reused_across_accounts"] or hist["previously_used_by_account"]
    risk=calculate_risk(strength,policy,hash_info,age,reused)
    recommendations=build_recommendations(strength,policy,hash_info,risk)
    if hist["reused_across_accounts"]: recommendations.append("Investigate cross-account password reuse and require a unique credential.")
    if hist["previously_used_by_account"]: recommendations.append("This account appears to have reused a password from its stored history.")
    report={"strength":strength,"policy":policy,"hash_info":hash_info,"risk":risk,"recommendations":list(dict.fromkeys(recommendations)),"reuse":hist}
    if persist and account: store_fingerprint(account,password)
    return report

@app.route("/")
def index(): return redirect(url_for("dashboard") if session.get("admin_id") else url_for("login"))
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        with db() as c: user=c.execute("SELECT * FROM admins WHERE username=?",(u,)).fetchone()
        if user and check_password_hash(user["password_hash"],p):
            session.clear(); session["admin_id"]=user["id"]; session["username"]=user["username"]; log_event("LOGIN_SUCCESS",f"User {u} logged in"); return redirect(url_for("dashboard"))
        log_event("LOGIN_FAILURE",f"Failed login for username {u}","WARNING"); flash("Invalid username or password.","error")
    return render_template("login.html")
@app.route("/logout")
def logout():
    if session.get("username"): log_event("LOGOUT",f"User {session['username']} logged out")
    session.clear(); return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    with db() as c:
        rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall(); totals=c.execute("SELECT COUNT(*) total,SUM(CASE WHEN risk_level IN ('High','Critical') THEN 1 ELSE 0 END) risky,SUM(policy_compliant) compliant FROM audit_logs").fetchone(); events=c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html",history=[dict(x) for x in rows],totals=dict(totals),latest=LATEST_REPORT,events=[dict(x) for x in events])
@app.route("/assess",methods=["GET","POST"])
@login_required
def assess():
    result=None
    if request.method=="POST":
        password=request.form.get("password",""); account=request.form.get("account","sample-account").strip() or "sample-account"; hv=request.form.get("hash_value","").strip(); raw=request.form.get("password_age_days","").strip()
        if not password: flash("Enter a sample password to assess.","error")
        else:
            age=int(raw) if raw.isdigit() else None; result=assess_one(password,age,hv,account,True); LATEST_REPORT.clear(); LATEST_REPORT.update(result); audit(result); log_event("PASSWORD_ASSESSMENT","An account password assessment was completed","WARNING" if result['risk']['level'] in ("High","Critical") else "INFO")
            if result["reuse"]["previously_used_by_account"] or result["reuse"]["reused_across_accounts"]: flash("Password reuse/history match detected.","error")
    return render_template("assess.html",result=result,policy=get_policy())
@app.route("/batch",methods=["GET","POST"])
@login_required
def batch():
    rows=[]
    if request.method=="POST":
        f=request.files.get("csv_file")
        if not f or not f.filename.lower().endswith(".csv"): flash("Upload a CSV file.","error")
        else:
            try:
                reader=csv.DictReader(io.StringIO(f.stream.read().decode("utf-8-sig")))
                required={"username","password"}
                if not required.issubset(set(reader.fieldnames or [])): raise ValueError("CSV must contain username and password columns; optional columns: password_age_days, hash.")
                seen={}
                for row in reader:
                    username=(row.get("username") or "").strip(); password=row.get("password") or ""
                    if not username or not password: continue
                    age=int(row["password_age_days"]) if (row.get("password_age_days") or "").isdigit() else None
                    report=assess_one(password,age,row.get("hash") or "",username,False)
                    pfp=make_fingerprint(app.config["SECRET_KEY"],"password",password)
                    if pfp in seen and seen[pfp]!=username: report["reuse"]["reused_across_accounts"]=True; report["risk"]=calculate_risk(report["strength"],report["policy"],report["hash_info"],age,True); report["risk"]["reasons"].append("Password reused within this CSV batch")
                    seen[pfp]=username
                    rows.append({"username":username,"strength":report["strength"],"policy":report["policy"],"risk":report["risk"],"hash_info":report["hash_info"],"recommendations":report["recommendations"],"reuse":report["reuse"]})
                    store_fingerprint(username,password); audit(report,"batch")
                log_event("BATCH_ASSESSMENT",f"Batch assessment processed {len(rows)} accounts")
                session["batch_results"]=[{k:v for k,v in r.items() if k!="username"} | {"username":r["username"]} for r in rows]
            except Exception as e: flash(f"Could not process CSV: {e}","error")
    return render_template("batch.html",rows=rows)
@app.route("/policy",methods=["GET","POST"])
@login_required
def policy():
    if request.method=="POST":
        try:
            updated={"min_length":max(8,min(128,int(request.form.get("min_length",12)))),"uppercase":request.form.get("uppercase")=="on","lowercase":request.form.get("lowercase")=="on","number":request.form.get("number")=="on","special":request.form.get("special")=="on","max_age_days":max(0,min(3650,int(request.form.get("max_age_days",180)))) or None,"history_count":max(1,min(20,int(request.form.get("history_count",5))))}
            with db() as c: c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('policy',?)",(json.dumps(updated),))
            log_event("POLICY_UPDATED","Password policy configuration changed"); flash("Password policy saved.","success"); return redirect(url_for("policy"))
        except ValueError: flash("Enter valid numeric policy values.","error")
    return render_template("policy.html",policy=get_policy())
@app.route("/hash-tools",methods=["GET","POST"])
@login_required
def hash_tools():
    result=None; generated=None
    if request.method=="POST":
        action=request.form.get("action"); hv=request.form.get("hash_value","").strip()
        if action=="identify": result=identify_hash(hv)
        elif action=="verify": result=verify_password(request.form.get("candidate_password",""),hv)
        elif action=="generate":
            candidate=request.form.get("candidate_password",""); algorithm=request.form.get("algorithm","Argon2id")
            if candidate: generated=create_demo_hash(candidate,algorithm)
            else: flash("Enter a sample password.","error")
    return render_template("hash_tools.html",result=result,generated=generated,comparison=compare_hash_strengths())
@app.route("/compliance")
@login_required
def compliance(): return render_template("compliance.html",controls=COMPLIANCE_CONTROLS)
@app.route("/monitoring")
@login_required
def monitoring():
    severity=request.args.get("severity","")
    with db() as c:
        if severity: events=c.execute("SELECT * FROM security_events WHERE severity=? ORDER BY id DESC LIMIT 250",(severity,)).fetchall()
        else: events=c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 250").fetchall()
    return render_template("monitoring.html",events=[dict(x) for x in events],severity=severity)
@app.route("/reports")
@login_required
def reports():
    with db() as c: rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 250").fetchall()
    return render_template("reports.html",history=[dict(x) for x in rows])
REPORT_TYPES={"security":"Password Security Report","policy":"Password Policy Compliance Report","strength":"Password Strength Report","hash":"Hash Algorithm Report","risk":"Risk Assessment Report","executive":"Executive Summary Report"}
def report_payload(kind):
    with db() as c:
        rows=[dict(r) for r in c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500").fetchall()]
        events=[dict(r) for r in c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 100").fetchall()]
    total=len(rows); risky=sum(r["risk_level"] in ("High","Critical") for r in rows); compliant=sum(r["policy_compliant"] for r in rows)
    risk_counts={level:sum(r["risk_level"]==level for r in rows) for level in ("Low","Medium","High","Critical")}
    hash_counts={}
    for r in rows: hash_counts[r.get("hash_algorithm") or "Not assessed"]=hash_counts.get(r.get("hash_algorithm") or "Not assessed",0)+1
    focus={
      "security":[("Assessment count",total),("High/Critical findings",risky),("Policy compliant",compliant)],
      "policy":[("Compliant assessments",compliant),("Non-compliant assessments",total-compliant),("Compliance rate (%)",round(compliant/total*100,1) if total else 0)],
      "strength":[("Average strength score (0-4)",round(sum(r["strength_score"] for r in rows)/total,2) if total else 0),("Weak / very weak assessments",sum(r["strength_score"]<=1 for r in rows)),("Strong / very strong assessments",sum(r["strength_score"]>=3 for r in rows))],
      "hash":[(f"{name} assessments",count) for name,count in sorted(hash_counts.items())],
      "risk":[(f"{name} risk assessments",count) for name,count in risk_counts.items()],
      "executive":[("Total assessments",total),("High/Critical risk rate (%)",round(risky/total*100,1) if total else 0),("Policy compliance rate (%)",round(compliant/total*100,1) if total else 0),("Recent security events",len(events))]
    }
    return {"report_type":REPORT_TYPES[kind],"kind":kind,"generated_at":datetime.now(timezone.utc).isoformat(),"summary":{"total_assessments":total,"high_critical":risky,"compliant":compliant,"non_compliant":total-compliant,"risk_rate":round(risky/total*100,1) if total else 0},"focus_metrics":focus[kind],"risk_distribution":risk_counts,"hash_distribution":hash_counts,"history":rows,"events":events,"latest":LATEST_REPORT,"compliance":COMPLIANCE_CONTROLS}
@app.route("/export/<kind>/<fmt>")
@login_required
def export_report(kind,fmt):
    if kind not in REPORT_TYPES or fmt not in ("pdf","excel"): return "Unknown report format",404
    payload=report_payload(kind); out=Path(app.root_path)/"instance"/"exports"; out.mkdir(parents=True,exist_ok=True); path=out/f"{kind}_report.{ 'pdf' if fmt=='pdf' else 'xlsx'}"
    (create_pdf if fmt=="pdf" else create_excel)(path,payload)
    log_event("REPORT_EXPORT",f"Exported {REPORT_TYPES[kind]} as {fmt.upper()}")
    return send_file(path,as_attachment=True,download_name=path.name)
@app.route("/export/<fmt>")
@login_required
def legacy_export(fmt):
    if not LATEST_REPORT: flash("Run an assessment first.","error"); return redirect(url_for("assess"))
    path=Path(app.root_path)/"instance"/"exports"/f"latest_assessment.{ 'pdf' if fmt=='pdf' else 'xlsx'}"; path.parent.mkdir(parents=True,exist_ok=True)
    (create_pdf if fmt=="pdf" else create_excel)(path,{"latest":LATEST_REPORT,"report_type":"Latest Password Assessment","summary":{},"history":[]})
    return send_file(path,as_attachment=True,download_name=path.name)
@app.route("/change-password",methods=["GET","POST"])
@login_required
def change_password():
    if request.method=="POST":
        current=request.form.get("current_password",""); new=request.form.get("new_password","")
        with db() as c: user=c.execute("SELECT * FROM admins WHERE id=?",(session["admin_id"],)).fetchone()
        if not check_password_hash(user["password_hash"],current): flash("Current password is incorrect.","error")
        elif len(new)<12: flash("New password must be at least 12 characters.","error")
        else:
            with db() as c: c.execute("UPDATE admins SET password_hash=? WHERE id=?",(generate_password_hash(new),session["admin_id"]))
            log_event("ADMIN_PASSWORD_CHANGED",f"Admin {session.get('username')} changed login password"); flash("Password updated.","success"); return redirect(url_for("dashboard"))
    return render_template("change_password.html")
@app.errorhandler(413)
def too_large(_): flash("Request too large.","error"); return redirect(url_for("batch"))
with app.app_context(): init_db()
if __name__=="__main__": app.run(host="127.0.0.1",port=5000,debug=False)
