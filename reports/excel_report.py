from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

def create_excel(path, report):
    wb=Workbook(); ws=wb.active; ws.title="Summary"; ws.append([report.get("report_type","Password Security Report")]); ws.append(["Metric","Value"])
    for k,v in report.get("summary",{}).items(): ws.append([k.replace("_"," ").title(),v])
    if report.get("focus_metrics"):
        fm=wb.create_sheet("Report Findings"); fm.append(["Metric","Result"])
        for k,v in report["focus_metrics"]: fm.append([k,v])
    latest=report.get("latest",{})
    if latest:
        ws.append([]); ws.append(["Latest assessment", "Value"])
        for k,v in [("Risk level",latest.get("risk",{}).get("level")),("Risk score",latest.get("risk",{}).get("score")),("Strength",latest.get("strength",{}).get("label")),("Entropy estimate",latest.get("strength",{}).get("entropy_bits")),("Policy compliant",latest.get("policy",{}).get("compliant")),("Hash algorithm",(latest.get("hash_info") or {}).get("algorithm","Not assessed"))]: ws.append([k,v])
    hist=wb.create_sheet("Assessment History"); hist.append(["Created UTC","Source","Strength score","Risk score","Risk level","Policy compliant","Hash algorithm"])
    for r in report.get("history",[]): hist.append([r.get("created_at"),r.get("source"),r.get("strength_score"),r.get("risk_score"),r.get("risk_level"),bool(r.get("policy_compliant")),r.get("hash_algorithm")])
    ev=wb.create_sheet("Security Events"); ev.append(["Created UTC","Severity","Event","Details"])
    for r in report.get("events",[]): ev.append([r.get("created_at"),r.get("severity"),r.get("event_type"),r.get("details")])
    comp=wb.create_sheet("Compliance Mapping"); comp.append(["Framework","Control","Project feature","Status","Limitation"])
    for c in report.get("compliance",[]): comp.append([c["framework"],c["control"],c["feature"],c["status"],c["note"]])
    for sheet in wb.worksheets:
        sheet.freeze_panes="A2"; sheet.auto_filter.ref=sheet.dimensions
        for cell in sheet[1]: cell.font=Font(bold=True,color="FFFFFF"); cell.fill=PatternFill("solid",fgColor="18243A")
        for col in sheet.columns:
            letter=col[0].column_letter; sheet.column_dimensions[letter].width=min(55,max(16,max(len(str(c.value or "")) for c in col)+2))
            for cell in col: cell.alignment=Alignment(vertical="top",wrap_text=True)
    wb.save(path)
