import os
import sys
import subprocess

try:
    import docx
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "python-docx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import docx

from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)

def create_audit_document():
    print("Generating Project_Technical_Audit.docx...")
    doc = docx.Document()
    
    # margins
    for s in doc.sections:
        s.top_margin = Inches(1)
        s.bottom_margin = Inches(1)
        s.left_margin = Inches(1)
        s.right_margin = Inches(1)
        
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(11)
    style_normal.font.color.rgb = RGBColor(0x33, 0x41, 0x55)
    
    # Title Page
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run("FORENSIC TECHNICAL AUDIT & ARCHITECTURAL DOCUMENTATION")
    title_run.font.size = Pt(20)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)
    title_p.paragraph_format.space_before = Pt(36)
    title_p.paragraph_format.space_after = Pt(6)
    
    subtitle_p = doc.add_paragraph()
    subtitle_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_run = subtitle_p.add_run("Software Supply-Chain Threat Detection Gatekeeper (AI C-M-G-B-T Framework)")
    sub_run.font.size = Pt(13)
    sub_run.font.italic = True
    sub_run.font.color.rgb = RGBColor(0x47, 0x55, 0x69)
    subtitle_p.paragraph_format.space_after = Pt(24)
    
    p_div = doc.add_paragraph()
    p_div.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_div.add_run("━" * 45).font.color.rgb = RGBColor(0xcb, 0xd5, 0xe1)
    p_div.paragraph_format.space_after = Pt(24)
    
    def add_h1(text):
        p = doc.add_paragraph()
        r = p.add_run(text)
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)
        p.paragraph_format.space_before = Pt(20)
        p.paragraph_format.space_after = Pt(6)
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        r = p.add_run(text)
        r.font.size = Pt(12.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x1e, 0x3a, 0x8a)
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        return p

    def add_p(text, bold_prefix=None):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            rb = p.add_run(bold_prefix)
            rb.bold = True
            rb.font.color.rgb = RGBColor(0x1e, 0x29, 0x3b)
        p.add_run(text)
        return p

    def add_bullet(text, bold_prefix=None):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            rb = p.add_run(bold_prefix)
            rb.bold = True
            rb.font.color.rgb = RGBColor(0x1e, 0x29, 0x3b)
        p.add_run(text)
        return p

    def add_code(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(6)
        r = p.add_run(text)
        r.font.name = 'Courier New'
        r.font.size = Pt(10)
        r.font.bold = True
        return p

    # --- CONTENTS ---
    add_h1("1. Executive Summary")
    add_p(
        "This project implements a Pre-Installation Quarantine Gatekeeper designed to intercept Python dependency installations "
        "(usually initiated via pip install -r requirements.txt) and analyze packages across five dimensions: Source Code (C), Metadata (M), "
        "Graph Topology (G), Behavioral Telemetry (B), and Temporal Release Sequences (T). The core contribution is a hybrid deep-learning prediction "
        "engine composed of a Heterogeneous Graph Attention Network (HGAT GNN) mapping transit dependency risks and a Temporal LSTM checking "
        "release frequency drift anomalies. A visual dashboard provides interactive confirmation before host packages are updated."
    )
    
    add_h1("2. Codebase Staging and Transitive Dependencies Resolution")
    add_p(
        "The file sbom/generator.py extracts direct dependencies from requirements.txt or pipdeptree. "
        "It maps local distribution paths using importlib.metadata. Non-local dependencies are downloaded as tarballs or wheels from PyPI "
        "intooutputs/scan_temp/downloads/ and extracted locally for static scanning."
    )
    add_bullet(
        "If a package is not installed on the system, its transitive dependencies default to an empty list, which is a major system limitation.",
        bold_prefix="Dependency Limitation: "
    )
    
    add_h1("3. Dynamic Telemetry & Sandbox Simulation")
    add_p(
        "The script runtime_behaviour/monitor.py constructs a dynamic monkeypatch wrapper that intercepts calls to os.system, subprocess.Popen, "
        "builtins.__import__, open, socket.connect, eval, and exec. "
    )
    add_bullet(
        "In the primary HTTP backend server handler (main.py, lines 260-268), this dynamic sandbox tracing is bypassed. "
        "A dictionary of zeroed values is passed instead to avoid blocking HTTP threads and mitigate sandbox escapes.",
        bold_prefix="Security Note: "
    )
    
    add_h1("4. Mathematical Formulas Used in Code")
    
    add_h2("4.1 Shannon Entropy")
    add_p("Calculated over raw file strings inside static_analysis/analyzer.py:")
    add_code("H(X) = - sum_{i=1}^{n} P(x_i) * log_2 P(x_i)")
    
    add_h2("4.2 GAT GNN Attention Coefficient")
    add_p("Calculated inside PyTorch Geometric's GATConv layers in ml_engine/hgat_model.py:")
    add_code("alpha_ij = exp( LeakyReLU( a^T * [ W * h_i || W * h_j ] ) ) / sum_k( exp( LeakyReLU( a^T * [ W * h_i || W * h_k ] ) ) )")
    
    add_h2("4.3 Risk-Adjusted Dependency Value (RADV)")
    add_p("Computes alert priorities in ml_engine/predictor.py:")
    add_code("RADV(p) = CompositeRisk(p) * log_10( BlastRadius(p) + 10 )")
    
    add_h2("4.4 LSTM Sequence Gating")
    add_code(
        "f_t = sigmoid( W_f * [h_{t-1}, x_t] + b_f )\n"
        "i_t = sigmoid( W_i * [h_{t-1}, x_t] + b_i )\n"
        "C_tilde_t = tanh( W_c * [h_{t-1}, x_t] + b_c )\n"
        "C_t = f_t * C_{t-1} + i_t * C_tilde_t\n"
        "o_t = sigmoid( W_o * [h_{t-1}, x_t] + b_o )\n"
        "h_t = o_t * tanh( C_t )"
    )

    add_h1("5. Real vs. Simulated Components")
    add_p(
        "Vulnerability queries are real (OSV.dev + Excel caching). Static analysis is real (AST visitor, Shannon entropy, Bandit, Semgrep). "
        "However, LSTM temporal input arrays are generated synthetically in trainer.py/predictor.py using static loops. "
        "Additionally, Time-To-Detection (TTD) is simulated directly from risk scores (ttd = max(1.0, 2.0 + (1.0 - composite_risk) * 48.0)) "
        "instead of utilizing real timestamps."
    )
    
    add_h1("6. Presentation Guides")
    add_h2("6.1 2-Minute Viva Answer")
    add_p(
        "Our project implements a Pre-Installation Quarantine Gatekeeper for Python packages. When a developer provides a requirements file, "
        "the system downloads the packages into a staging folder without installing them. It runs static analysis (measuring Shannon entropy, "
        "AST node features, and running Bandit/Semgrep) and queries OSV.dev for known CVEs. These features are represented in a dependency graph. "
        "We train a Heterogeneous Graph Attention Network (HGAT GNN) to calculate risk propagation and a Temporal LSTM to detect release anomalies. "
        "The unified risk score and a risk-adjusted metric (RADV) are rendered in a glassmorphic dashboard. This allows administrators to verify "
        "dependencies before approving host installation, preventing typosquatting and maintainer account takeover attacks."
    )
    
    out_dir = "outputs"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "Project_Technical_Audit.docx")
    doc.save(out_path)
    print(f"[SUCCESS] Word document generated successfully at: {os.path.abspath(out_path)}")

if __name__ == "__main__":
    create_audit_document()
