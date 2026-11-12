from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from xml.sax.saxutils import escape

def create_pdf(path, report):
    doc=SimpleDocTemplate(str(path),pagesize=A4,rightMargin=15*mm,leftMargin=15*mm,topMargin=15*mm,bottomMargin=15*mm)
    styles=getSampleStyleSheet(); title=escape(report.get("report_type","Password Security Report")); summary=report.get("summary",{}); latest=report.get("latest",{})
    story=[Paragraph(title,styles["Title"]),Spacer(1,6),Paragraph("Generated: "+escape(report.get("generated_at","Local project report")),styles["Normal"]),Spacer(1,10)]
    rows=[["Metric","Value"],["Total assessments",str(summary.get("total_assessments",1 if latest else 0))],["High/Critical findings",str(summary.get("high_critical",latest.get("risk",{}).get("level","N/A")))],["Policy compliant",str(summary.get("compliant","N/A"))],["Non-compliant",str(summary.get("non_compliant","N/A"))],["High/Critical rate",str(summary.get("risk_rate","N/A"))+"%"]]
    t=Table(rows,colWidths=[65*mm,95*mm]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#18243a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#cbd5e1")),("PADDING",(0,0),(-1,-1),6)])); story += [t,Spacer(1,12)]
    if report.get("focus_metrics"):
        story.append(Paragraph("Report-specific findings",styles["Heading2"]))
        fm=[["Metric","Result"]]+[[str(k),str(v)] for k,v in report["focus_metrics"]]
        ft=Table(fm,colWidths=[85*mm,75*mm]); ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#334155")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.HexColor("#cbd5e1")),("PADDING",(0,0),(-1,-1),5)])); story.append(ft); story.append(Spacer(1,8))
    if latest:
        story.append(Paragraph("Latest assessment detail",styles["Heading2"]))
        detail=[["Risk",f"{latest.get('risk',{}).get('level','N/A')} ({latest.get('risk',{}).get('score','N/A')}/100)"],["Strength",latest.get("strength",{}).get("label","N/A")],["Entropy estimate",str(latest.get("strength",{}).get("entropy_bits","N/A"))+" bits"],["Policy compliant",str(latest.get("policy",{}).get("compliant","N/A"))],["Hash algorithm",(latest.get("hash_info") or {}).get("algorithm","Not assessed")]]
        story.append(Table([[escape(str(a)),escape(str(b))] for a,b in detail],colWidths=[65*mm,95*mm])); story.append(Spacer(1,8))
    story.append(Paragraph("Assessment records",styles["Heading2"]))
    data=[["Date (UTC)","Source","Strength","Risk","Policy"]]
    for r in report.get("history",[])[:100]: data.append([r.get("created_at","")[:19],r.get("source","single"),str(r.get("strength_score","")),f"{r.get('risk_level','')} ({r.get('risk_score','')})", "Pass" if r.get("policy_compliant") else "Fail"])
    if len(data)==1: data.append(["No historical records","","","",""])
    table=Table(data,repeatRows=1,colWidths=[38*mm,22*mm,20*mm,35*mm,25*mm]); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#334155")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.HexColor("#cbd5e1")),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)])); story.append(table)
    if report.get("compliance"):
        story += [Spacer(1,10),Paragraph("Compliance mapping (project-level, not certification)",styles["Heading2"])]
        for c in report["compliance"]: story.append(Paragraph(f"<b>{escape(c['framework'])}</b> — {escape(c['status'])}: {escape(c['note'])}",styles["BodyText"]))
    story += [Spacer(1,10),Paragraph("Limitations: This educational prototype uses a project-defined risk model and selected control mappings. It is not a formal audit, certification, or guarantee of security.",styles["Italic"])]
    doc.build(story)
