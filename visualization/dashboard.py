import os
import json
import networkx as nx

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software Supply Chain Threat Intelligence Dashboard</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js" integrity="sha384-su5kReKyYlIFrI62mbQRKXHzFobMa7BHp1cK6julLPbnYcCW9NIZKJiTODjLPeDh" crossorigin="anonymous"></script>
    <style>
        :root {{
            --bg-base: #0a0b10;
            --bg-card: rgba(20, 22, 34, 0.7);
            --border-glow: rgba(99, 102, 241, 0.15);
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.4);
            --warning: #f59e0b;
            --success: #10b981;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            overflow-x: hidden;
            background-image: radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.05) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(239, 68, 68, 0.05) 0%, transparent 40%);
        }}

        header {{
            padding: 24px 40px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(10, 11, 16, 0.8);
            backdrop-filter: blur(12px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .logo {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .logo-tag {{
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 99px;
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid var(--primary);
            color: #a5b4fc;
        }}

        .project-score-badge {{
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid var(--border-glow);
            background: var(--bg-card);
            text-align: right;
        }}

        .project-score-val {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 20px;
            font-weight: 700;
        }}

        .grid-container {{
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 24px;
            padding: 40px;
            max-width: 1600px;
            margin: 0 auto;
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 24px;
            backdrop-filter: blur(8px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .card-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 18px;
            font-weight: 700;
            border-left: 3px solid var(--primary);
            padding-left: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .graph-container {{
            height: 500px;
            width: 100%;
            border-radius: 12px;
            background: rgba(5, 5, 8, 0.6);
            overflow: hidden;
            position: relative;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }}

        svg {{
            width: 100%;
            height: 100%;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            color: var(--text-muted);
            font-weight: 600;
            padding: 12px 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 13px;
        }}

        td {{
            padding: 14px 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            font-size: 14px;
        }}

        .badge {{
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
        }}

        .badge-danger {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .badge-warning {{
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .badge-success {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        .attack-path-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .attack-path-item {{
            background: rgba(239, 68, 68, 0.04);
            border: 1px solid rgba(239, 68, 68, 0.1);
            border-radius: 8px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .attack-path-route {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 13px;
            color: #fca5a5;
        }}

        .xai-block {{
            background: rgba(255, 255, 255, 0.02);
            border-radius: 8px;
            padding: 12px;
            font-size: 13px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .progress-bar-container {{
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            height: 6px;
            border-radius: 99px;
            overflow: hidden;
        }}

        .progress-bar-fill {{
            height: 100%;
            background: var(--primary);
            border-radius: 99px;
        }}

        .legend {{
            position: absolute;
            bottom: 12px;
            left: 12px;
            background: rgba(10, 11, 16, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 10px;
            border-radius: 8px;
            font-size: 11px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .legend-color {{
            width: 10px;
            height: 10px;
            border-radius: 99px;
        }}

        .btn-control {{
            background: rgba(129, 140, 248, 0.1);
            border: 1px solid rgba(129, 140, 248, 0.3);
            color: #a5b4fc;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-control:hover {
            background: rgba(129, 140, 248, 0.25);
            border-color: #818cf8;
            color: #ffffff;
        }

        /* Remediation Card Styles */
        .remediation-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            transition: all 0.2s ease;
        }
        .remediation-card:hover {
            background: rgba(99, 102, 241, 0.05);
            border-color: var(--primary);
            box-shadow: 0 4px 20px rgba(99, 102, 241, 0.15);
        }
        .remediation-cmd-box {
            background: rgba(10, 11, 16, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 6px;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 12px;
            color: #a5b4fc;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .btn-copy-fix {
            background: rgba(99, 102, 241, 0.2);
            border: 1px solid var(--primary);
            color: #ffffff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-copy-fix:hover {
            background: var(--primary);
        }

        /* Drag and drop upload zone styles */
        .upload-zone {
            border: 2px dashed rgba(99, 102, 241, 0.4);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            background: rgba(99, 102, 241, 0.02);
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 40px auto;
            max-width: 800px;
            backdrop-filter: blur(8px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
        }
        .upload-zone:hover, .upload-zone.dragover {
            background: rgba(99, 102, 241, 0.08);
            border-color: var(--primary);
            box-shadow: 0 0 15px var(--primary-glow);
        }
        .upload-icon {
            font-size: 40px;
            color: #a5b4fc;
            margin-bottom: 12px;
        }
        .upload-title {
            font-weight: 600;
            font-size: 16px;
            margin-bottom: 8px;
        }
        .upload-subtitle {
            color: var(--text-muted);
            font-size: 13px;
        }
        .benchmark-card {
            background: rgba(18, 20, 31, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            gap: 12px;
            transition: all 0.25s ease;
            position: relative;
            overflow: hidden;
        }
        .benchmark-card:hover {
            transform: translateY(-2px);
            border-color: rgba(99, 102, 241, 0.5);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
            background: rgba(24, 27, 43, 0.9);
        }
        .benchmark-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: var(--card-border-color, var(--primary));
        }
        .btn-benchmark-scan {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            border: 1px solid rgba(99, 102, 241, 0.4);
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: all 0.2s ease;
            width: 100%;
        }
        .btn-benchmark-scan:hover {
            background: var(--primary);
            color: #ffffff;
            box-shadow: 0 0 12px rgba(99, 102, 241, 0.4);
        }
        .gatekeeper-actions {
            display: flex;
            justify-content: center;
            gap: 16px;
            padding: 20px 40px;
            max-width: 1600px;
            margin: 0 auto;
        }
        .btn-action {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 14px;
            font-weight: 600;
            padding: 12px 28px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }
        .btn-approve {
            background: var(--success);
            color: #ffffff;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
        }
        .btn-approve:hover {
            background: #059669;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.4);
        }
        .btn-reject {
            background: rgba(239, 68, 68, 0.1);
            color: #fb7185;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .btn-reject:hover {
            background: rgba(239, 68, 68, 0.2);
            color: #ffffff;
        }
        .toast-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(10, 11, 16, 0.85);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            display: none;
        }
        .toast-content {
            background: rgba(20, 22, 34, 0.95);
            border: 1px solid var(--border-glow);
            padding: 40px;
            border-radius: 16px;
            text-align: center;
            max-width: 500px;
            box-shadow: 0 0 30px rgba(99, 102, 241, 0.2);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <span>PROTECTION SHIELD</span>
            <span class="logo-tag">PYTHON SUPPLY CHAIN</span>
        </div>
        <div class="project-score-badge">
            <span style="color: var(--text-muted); font-size: 11px;">PROJECT RISK LEVEL</span>
            <div class="project-score-val" id="projectRiskText">-</div>
        </div>
    </header>

    <!-- 10 Benchmark Applications & Multi-File Uploader -->
    <div id="uploadContainer" style="display: block; max-width: 1600px; margin: 30px auto; padding: 0 40px;">
        <!-- Header & Instructions -->
        <div style="text-align: center; margin-bottom: 28px;">
            <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(99,102,241,0.12); border: 1px solid rgba(99,102,241,0.3); padding: 6px 16px; border-radius: 20px; color: #a5b4fc; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">
                <span>🔬</span> 10 Application Evaluation Suite & Full Pipeline Gatekeeper
            </div>
            <h1 style="font-family: 'Space Grotesk', sans-serif; font-size: 28px; font-weight: 700; color: #ffffff; margin: 0 0 8px 0;">
                Select & Scan Any Application (Code + Runtime + Dependencies)
            </h1>
            <p style="color: var(--text-muted); font-size: 14px; max-width: 820px; margin: 0 auto; line-height: 1.6;">
                Each benchmark application is a real-world Python project. Scanning an application evaluates its <strong>Python source code (.py)</strong>, <strong>AST injection vectors</strong>, <strong>setup.py install hooks</strong>, <strong>obfuscation entropy</strong>, <strong>sandboxed runtime execution</strong>, and <strong>dependency manifests</strong>.
            </p>
        </div>

        <!-- 10 Benchmark Applications Grid -->
        <div style="margin-bottom: 32px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 8px;">
                <h3 style="font-family: 'Space Grotesk', sans-serif; font-size: 18px; color: #ffffff; margin: 0; display: flex; align-items: center; gap: 8px;">
                    <span>📂</span> 10 Benchmark Test Cases (Benign Safe to Critical Compromised)
                </h3>
                <span style="font-size: 12px; color: var(--text-muted);">Click "Scan Application" to run full static + runtime + supply chain pipeline</span>
            </div>
            <div id="benchmarkAppsGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 16px;">
                <!-- Dynamically rendered via renderBenchmarkAppsGrid() -->
            </div>
        </div>

        <!-- Divider -->
        <div style="display: flex; align-items: center; gap: 16px; margin: 36px 0 24px 0;">
            <div style="flex: 1; height: 1px; background: rgba(255,255,255,0.08);"></div>
            <span style="color: var(--text-muted); font-size: 12px; text-transform: uppercase; font-weight: 600; letter-spacing: 1px;">OR CHOOSE SCANNING MODE (FOLDER VS FILES)</span>
            <div style="flex: 1; height: 1px; background: rgba(255,255,255,0.08);"></div>
        </div>

        <!-- Dual Mode Options Grid (Folder Scanner & File Scanner) -->
        <div style="max-width: 1100px; margin: 0 auto 24px auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(480px, 1fr)); gap: 18px;">
            <!-- Option A: Scan Entire Project Folder -->
            <div style="background: rgba(18,20,31,0.85); border: 1px solid rgba(99,102,241,0.25); border-radius: 14px; padding: 20px 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.25);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <span style="font-family: 'Space Grotesk', sans-serif; font-size: 15px; font-weight: 700; color: #a5b4fc; display: flex; align-items: center; gap: 8px;">
                        <span>📁</span> Option 1: Scan Full Project Folder
                    </span>
                    <button type="button" class="btn-action" style="padding: 6px 14px; font-size: 12px; background: rgba(99,102,241,0.2); color: #c7d2fe; border: 1px solid rgba(99,102,241,0.4);" onclick="document.getElementById('folderInput').click();">
                        📁 Browse Folder
                    </button>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.4;">
                    Scans all files inside the folder: all <strong>.py</strong> source files, <strong>setup.py</strong> install hooks, and <strong>requirements.txt</strong>.
                </div>
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 12px;">
                    <input type="text" id="dirPathInput" placeholder="Enter folder path (e.g. test_cases/app_01_clean_calculator)..." style="flex: 1; padding: 10px 14px; border-radius: 8px; background: rgba(10,11,16,0.85); border: 1px solid rgba(255,255,255,0.12); color: #ffffff; font-family: monospace; font-size: 12px;">
                    <button type="button" class="btn-action" style="background: var(--primary); color: #ffffff; padding: 10px 18px; font-size: 12px; white-space: nowrap;" onclick="scanLocalDirectory()">🔍 Scan Folder</button>
                </div>
                <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                    <span style="font-size: 11px; color: var(--text-muted);">Quick Folders:</span>
                    <button type="button" class="badge" style="background: rgba(16,185,129,0.15); color: #86efac; border: 1px solid rgba(16,185,129,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="document.getElementById('dirPathInput').value='test_cases/app_01_clean_calculator'; scanLocalDirectory();">app_01 (Clean)</button>
                    <button type="button" class="badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="document.getElementById('dirPathInput').value='test_cases/app_07_backdoor_setup_hook_service'; scanLocalDirectory();">app_07 (Hook)</button>
                    <button type="button" class="badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="document.getElementById('dirPathInput').value='test_cases/app_08_obfuscated_crypto_service'; scanLocalDirectory();">app_08 (Obfuscated)</button>
                </div>
            </div>

            <!-- Option B: Scan Individual File(s) -->
            <div style="background: rgba(18,20,31,0.85); border: 1px solid rgba(14,165,233,0.25); border-radius: 14px; padding: 20px 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.25);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <span style="font-family: 'Space Grotesk', sans-serif; font-size: 15px; font-weight: 700; color: #7dd3fc; display: flex; align-items: center; gap: 8px;">
                        <span>📄</span> Option 2: Scan Specific File(s)
                    </span>
                    <button type="button" class="btn-action" style="padding: 6px 14px; font-size: 12px; background: rgba(14,165,233,0.2); color: #bae6fd; border: 1px solid rgba(14,165,233,0.4);" onclick="document.getElementById('fileInput').click();">
                        📄 Browse File(s)
                    </button>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.4;">
                    Scans individual files: select any <strong>requirements.txt</strong> for supply-chain risk or <strong>.py</strong> code for AST security.
                </div>
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 12px;">
                    <input type="text" id="filePathInput" placeholder="Enter file path (e.g. test_cases/app_01_clean_calculator/calculator.py)..." style="flex: 1; padding: 10px 14px; border-radius: 8px; background: rgba(10,11,16,0.85); border: 1px solid rgba(255,255,255,0.12); color: #ffffff; font-family: monospace; font-size: 12px;">
                    <button type="button" class="btn-action" style="background: #0284c7; color: #ffffff; padding: 10px 18px; font-size: 12px; white-space: nowrap;" onclick="scanLocalFile()">🔍 Scan File</button>
                </div>
                <div style="display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
                    <span style="font-size: 11px; color: var(--text-muted);">Quick Files:</span>
                    <button type="button" class="badge" style="background: rgba(16,185,129,0.15); color: #86efac; border: 1px solid rgba(16,185,129,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="scanLocalFile('test_cases/app_01_clean_calculator/requirements.txt')">app_01 reqs</button>
                    <button type="button" class="badge" style="background: rgba(16,185,129,0.15); color: #86efac; border: 1px solid rgba(16,185,129,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="scanLocalFile('test_cases/app_01_clean_calculator/calculator.py')">app_01 code</button>
                    <button type="button" class="badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="scanLocalFile('test_cases/app_05_typosquatting_currency_tool/requirements.txt')">app_05 typosquat</button>
                    <button type="button" class="badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="scanLocalFile('test_cases/app_07_backdoor_setup_hook_service/setup.py')">app_07 setup.py</button>
                    <button type="button" class="badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); cursor: pointer; padding: 3px 8px; font-size: 11px;" onclick="scanLocalFile('test_cases/app_08_obfuscated_crypto_service/crypto_tool.py')">app_08 exec.py</button>
                </div>
            </div>
        </div>

        <!-- Custom Upload Zone (Folder & Multi-File Drag & Drop) -->
        <div class="upload-zone" id="dropZone" style="max-width: 1100px; margin: 0 auto; cursor: default;">
            <div class="upload-icon">📥</div>
            <div class="upload-title" style="font-family: 'Space Grotesk', sans-serif; font-size: 18px; margin-bottom: 6px;">
                Drag & Drop Project Folder OR Individual Files
            </div>
            <div class="upload-subtitle" style="font-size: 13px; margin-bottom: 16px;">
                Drop an entire folder (e.g. app_01_clean_calculator) or multiple files (.py + requirements.txt)
            </div>
            <div style="display: flex; gap: 14px; justify-content: center; flex-wrap: wrap;">
                <button type="button" class="btn-action" style="padding: 10px 22px; font-size: 13px; background: rgba(99,102,241,0.25); color: #c7d2fe; border: 1px solid rgba(99,102,241,0.45); font-weight: 600;" onclick="document.getElementById('folderInput').click();">
                    📁 Browse Project Folder
                </button>
                <button type="button" class="btn-action" style="padding: 10px 22px; font-size: 13px; background: rgba(14,165,233,0.25); color: #bae6fd; border: 1px solid rgba(14,165,233,0.45); font-weight: 600;" onclick="document.getElementById('fileInput').click();">
                    📄 Browse Individual Files
                </button>
            </div>
            <input type="file" id="folderInput" webkitdirectory directory multiple style="display: none;">
            <input type="file" id="fileInput" multiple style="display: none;">
        </div>
    </div>

    <div id="resultsContainer" style="display: none;">
        <!-- Active Application Banner -->
        <div id="appProfileBanner" style="max-width: 1600px; margin: 24px auto 0 auto; padding: 0 40px; display: none;">
            <div class="card" style="padding: 20px 24px; border-left: 4px solid var(--primary); background: linear-gradient(135deg, rgba(30,33,50,0.85) 0%, rgba(17,19,29,0.95) 100%);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 22px;">📦</span>
                            <h2 id="bannerAppName" style="font-family: 'Space Grotesk', sans-serif; font-size: 20px; font-weight: 700; color: #ffffff; margin: 0;">Application Analysis Profile</h2>
                            <span id="bannerAppVerdictBadge" class="badge badge-success" style="font-size: 11px; padding: 4px 10px;">VERIFIED</span>
                        </div>
                        <div id="bannerAppDesc" style="color: var(--text-muted); font-size: 13px; margin-top: 6px;">Application details and evaluation.</div>
                    </div>
                    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                        <div style="text-align: right;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Source Files Evaluated</div>
                            <div id="bannerAppFiles" style="font-size: 13px; font-family: monospace; color: #38bdf8; font-weight: 600; margin-top: 2px;">-</div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Benchmark Case / Category</div>
                            <div id="bannerAppCategory" style="font-size: 13px; font-weight: 600; color: #a5b4fc; margin-top: 2px;">-</div>
                        </div>
                    </div>
                </div>
                <div style="display: flex; gap: 12px; margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.06); flex-wrap: wrap; font-size: 12px;">
                    <span style="color: var(--text-muted);">Layers Verified:</span>
                    <span class="badge" style="background: rgba(99,102,241,0.15); color: #a5b4fc; border: 1px solid rgba(99,102,241,0.3);">✓ Python AST Injections</span>
                    <span class="badge" style="background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3);">✓ Shannon Entropy (Obfuscation)</span>
                    <span class="badge" style="background: rgba(16,185,129,0.15); color: #86efac; border: 1px solid rgba(16,185,129,0.3);">✓ setup.py Hook Detector</span>
                    <span class="badge" style="background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.3);">✓ Runtime Behavioral Sandbox</span>
                    <span class="badge" style="background: rgba(168,85,247,0.15); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.3);">✓ HGAT GNN Supply Chain</span>
                </div>
            </div>
        </div>
        <!-- Early Warning Performance KPI Cards -->
        <div style="max-width: 1600px; margin: 24px auto 0 auto; padding: 0 40px;">
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;">
                <div class="card" style="padding: 16px 20px; border-left: 4px solid var(--primary);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Detection Latency (TTD)</div>
                    <div style="font-size: 24px; font-family: 'Space Grotesk', sans-serif; font-weight: 700; color: #a5b4fc; margin-top: 4px;" id="kpiLatency">-</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Avg threat verification speed</div>
                </div>
                <div class="card" style="padding: 16px 20px; border-left: 4px solid #38bdf8;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Median TTD</div>
                    <div style="font-size: 24px; font-family: 'Space Grotesk', sans-serif; font-weight: 700; color: #38bdf8; margin-top: 4px;" id="kpiMedian">-</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Median time to detection</div>
                </div>
                <div class="card" style="padding: 16px 20px; border-left: 4px solid #34d399;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Intercepted @ 24h</div>
                    <div style="font-size: 24px; font-family: 'Space Grotesk', sans-serif; font-weight: 700; color: #34d399; margin-top: 4px;" id="kpi24h">-</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Quarantined in day 1</div>
                </div>
                <div class="card" style="padding: 16px 20px; border-left: 4px solid #fbbf24;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Early Detection Rate (EDR)</div>
                    <div style="font-size: 24px; font-family: 'Space Grotesk', sans-serif; font-weight: 700; color: #fbbf24; margin-top: 4px;" id="kpiEdr">-</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Threats caught within 12h</div>
                </div>
            </div>
        </div>

        <div class="grid-container">
        <!-- Dependency Graph Card -->
        <div class="card" style="grid-column: 1 / 3;">
            <div class="card-title" style="display: flex; justify-content: space-between; align-items: center;">
                <span>Heterogeneous Supply Chain Security Graph (HGAT representation)</span>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <button class="btn-control" onclick="releaseAllNodes()">Release Pinned Nodes</button>
                    <span style="font-size: 12px; color: var(--text-muted);">Double-click Node to Release</span>
                </div>
            </div>
            <div class="graph-container">
                <svg id="graphSvg"></svg>
                <div class="legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #818cf8;"></div>
                        <span>Package (Size indicates risk)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #fb7185;"></div>
                        <span>Vulnerable Version</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #f43f5e;"></div>
                        <span>CVE Vulnerability</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #34d399;"></div>
                        <span>Maintainer</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerability list / Heatmap Card -->
        <div class="card">
            <div class="card-title">Dependency Risk Assessment Matrix</div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Risk Score</th>
                            <th>RADV (Priority)</th>
                            <th>Blast Radius</th>
                            <th>Threat Vectors</th>
                            <th>Confidence</th>
                            <th>Drift Trend</th>
                        </tr>
                    </thead>
                    <tbody id="riskTableBody">
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Explainable AI (XAI) Card -->
        <div class="card">
            <div class="card-title">GNN Explainability (XAI Saliency & Attention)</div>
            <div style="display: flex; flex-direction: column; gap: 16px;" id="xaiContainer">
            </div>
        </div>

        <!-- Critical Attack paths -->
        <div class="card" style="grid-column: 1 / 3;">
            <div class="card-title">Critical Attack Propagation Paths</div>
            <div class="attack-path-list" id="attackPathsContainer">
            </div>
        </div>

        <!-- Automated Remediation & Safe Upgrade Recipes Card -->
        <div class="card" style="grid-column: 1 / 3;">
            <div class="card-title" style="display: flex; justify-content: space-between; align-items: center;">
                <span>Automated Remediation & Safe Upgrade Recipes</span>
                <span class="logo-tag" id="remediationBadge" style="background: rgba(16, 185, 129, 0.15); border-color: #10b981; color: #34d399;">0 Actions</span>
            </div>
            <div id="remediationContainer" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 16px; margin-top: 12px;">
            </div>
        </div>
    </div> <!-- Close grid-container -->
    
    <!-- Gatekeeper Controls -->
    <div class="gatekeeper-actions" id="gatekeeperActions">
        <button class="btn-action btn-reject" onclick="abortInstallation()">Reject & Abort</button>
        <button class="btn-action" style="background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3);" onclick="resetAndUploadNew()">Scan New Project (Reset)</button>
        <button class="btn-action" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.4);" onclick="window.location.href='/download_csv'">Download CSV Report</button>
        <button class="btn-action" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4);" onclick="openArtifactsExplorer()">Explore Output Artifacts</button>
        <button class="btn-action btn-approve" onclick="approveInstallation()">Approve & Run Local Installation</button>
    </div>
    </div> <!-- Close resultsContainer -->

    <!-- Output Explorer Modal -->
    <div class="toast-overlay" id="explorerOverlay">
        <div class="toast-content" style="max-width: 900px; width: 90%; height: 80vh; max-height: 800px; display: flex; flex-direction: row; text-align: left; padding: 24px; gap: 24px;">
            <!-- Left Pane: Files List -->
            <div style="flex: 1; border-right: 1px solid rgba(255,255,255,0.05); padding-right: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px;">
                <h3 style="font-family: 'Space Grotesk', sans-serif; font-size: 18px; margin-bottom: 8px;">Output Artifacts</h3>
                <div id="explorerFilesList" style="display: flex; flex-direction: column; gap: 8px;">
                </div>
                <button class="btn-action btn-reject" style="margin-top: auto;" onclick="closeArtifactsExplorer()">Close Explorer</button>
            </div>
            <!-- Right Pane: Content Previewer -->
            <div style="flex: 2; overflow: hidden; display: flex; flex-direction: column; gap: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 id="explorerPreviewHeader" style="font-family: 'Space Grotesk', sans-serif; font-size: 18px; color: #a5b4fc; margin: 0;">Select a file to inspect</h3>
                    <button class="btn-action btn-reject" style="padding: 6px 12px; font-size: 12px; margin: 0;" onclick="closeArtifactsExplorer()">Exit Viewer</button>
                </div>
                <div style="flex: 1; background: rgba(10,11,16,0.6); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; overflow: auto;">
                    <pre><code id="explorerCodeBlock" style="font-family: monospace; font-size: 12px; color: var(--text-main); white-space: pre-wrap; word-break: break-all;"></code></pre>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notification Overlay -->
    <div class="toast-overlay" id="toastOverlay">
        <div class="toast-content" style="max-width: 520px; width: 90%; text-align: center; display: flex; flex-direction: column; gap: 16px; padding: 32px 28px;">
            <div id="toastIcon" style="font-size: 38px; line-height: 1;">🛡️</div>
            <h2 id="toastTitle" style="font-family: 'Space Grotesk', sans-serif; font-size: 20px;">Running Installation</h2>
            <p id="toastMessage" style="color: var(--text-muted); font-size: 14px; line-height: 1.5; margin: 0;">Please check host terminal logs for live progress...</p>
            <div id="toastButtons" style="display: flex; gap: 12px; justify-content: center; align-items: center; margin-top: 8px; flex-wrap: wrap;">
                <button class="btn-action btn-approve" id="toastContinueBtn" style="display: none; padding: 10px 22px; font-size: 13px;" onclick="continueAndUploadNew()">Continue & Upload New File</button>
                <button class="btn-action btn-reject" id="toastCloseBtn" style="display: none; padding: 10px 22px; font-size: 13px;" onclick="closeToast()">Close</button>
            </div>
        </div>
    </div>

    <script>
        // Global D3 simulation reference
        let currentSimulation = null;
        let currentNodeSelection = null;

        // Data injected by python builder
        const graphData = {graph_data_json};
        const predictionData = {prediction_data_json};

        // 10 Benchmark Evaluation Applications
        const benchmarkApps = [
            {
                id: 1,
                name: "App 01: Scientific Calculator CLI",
                files: "calculator.py + requirements.txt",
                category: "Completely Safe (Benign Control)",
                risk: "7.2%",
                verdict: "APPROVED (CLEAN)",
                badge_color: "#10b981",
                desc: "Clean arithmetic, formulas, and compound interest. 0 SAST findings, verified clean AST."
            },
            {
                id: 2,
                name: "App 02: Markdown Document Processor",
                files: "text_converter.py + requirements.txt",
                category: "Completely Safe (Benign Utility)",
                risk: "7.2%",
                verdict: "APPROVED (CLEAN)",
                badge_color: "#10b981",
                desc: "Markdown parser & HTML sanitizer. Clean open-source text processing utility with verified AST."
            },
            {
                id: 3,
                name: "App 03: Desktop File Organizer",
                files: "organizer.py + requirements.txt",
                category: "Minor / Low Risk",
                risk: "19.2%",
                verdict: "APPROVED (LOW RISK)",
                badge_color: "#38bdf8",
                desc: "Automated file categorization utility with unpinned dependency boundaries."
            },
            {
                id: 4,
                name: "App 04: Weather Intelligence CLI",
                files: "weather_cli.py + requirements.txt",
                category: "Moderate Risk (Needs Monitoring)",
                risk: "41.5%",
                verdict: "MONITOR (MEDIUM RISK)",
                badge_color: "#f59e0b",
                desc: "Network API query client. Unpinned requests with transitive reach flagged for monitoring."
            },
            {
                id: 5,
                name: "App 05: Currency Exchange Converter",
                files: "converter.py + requirements.txt",
                category: "Targeted Attack (T1 Typosquatting)",
                risk: "88.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "Imports typosquatted package 'reqeusts' (Levenshtein distance = 1 from 'requests')."
            },
            {
                id: 6,
                name: "App 06: Corporate Employee Directory",
                files: "directory.py + requirements.txt",
                category: "Targeted Attack (T2 Dep Confusion)",
                risk: "88.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "Namespace hijacking attempt spoofing internal corporate authentication package."
            },
            {
                id: 7,
                name: "App 07: System Monitoring Daemon",
                files: "service.py + setup.py + requirements.txt",
                category: "Targeted Attack (T5 Install Hook)",
                risk: "94.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "setup.py overrides cmdclass build/install with curl reverse shell. Caught by hook detector."
            },
            {
                id: 8,
                name: "App 08: Cryptographic Protection Utility",
                files: "crypto_tool.py + requirements.txt",
                category: "Targeted Attack (T5 Obfuscated Exec)",
                risk: "96.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "Encapsulates high-entropy packed base64 payload (H=7.1) evaluated dynamically via exec()."
            },
            {
                id: 9,
                name: "App 09: Web Archival & Link Scraper",
                files: "web_scraper.py + requirements.txt",
                category: "Targeted Attack (T6 Transitive CVE)",
                risk: "88.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "Benign surface scraper importing dependencies with known high CVSS CVEs (CVSS 7.5+)."
            },
            {
                id: 10,
                name: "App 10: Enterprise Workflow Engine",
                files: "workflow.py + requirements.txt",
                category: "Completely Vulnerable (Compound Incident)",
                risk: "98.0%",
                verdict: "QUARANTINED (BLOCKED)",
                badge_color: "#ef4444",
                desc: "Compound supply chain attack combining maintainer account hijack (ctx), exec(), and CVEs."
            }
        ];

        function renderBenchmarkAppsGrid() {
            const grid = document.getElementById("benchmarkAppsGrid");
            if (!grid) return;
            grid.innerHTML = "";
            benchmarkApps.forEach(app => {
                const card = document.createElement("div");
                card.className = "benchmark-card";
                card.style.setProperty("--card-border-color", app.badge_color);
                card.innerHTML = `
                    <div>
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 6px;">
                            <strong style="font-family: 'Space Grotesk', sans-serif; font-size: 14px; color: #ffffff;">${escapeHtml(app.name)}</strong>
                            <span class="badge" style="background: ${app.badge_color}22; color: ${app.badge_color}; border: 1px solid ${app.badge_color}55; font-size: 10px; white-space: nowrap;">${app.risk}</span>
                        </div>
                        <div style="font-size: 11px; font-family: monospace; color: #38bdf8; margin-bottom: 6px;">
                            📄 ${escapeHtml(app.files)}
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); line-height: 1.4; margin-bottom: 10px;">
                            ${escapeHtml(app.desc)}
                        </div>
                    </div>
                    <div>
                        <div style="font-size: 10px; color: var(--text-muted); margin-bottom: 6px; display: flex; justify-content: space-between;">
                            <span>Expected:</span>
                            <strong style="color: ${app.badge_color};">${escapeHtml(app.verdict)}</strong>
                        </div>
                        <button class="btn-benchmark-scan" style="margin-bottom: 6px;" onclick="scanBenchmarkApp(${app.id}, 'all')" title="Scan whole application folder (all code + dependencies)">
                            <span>📁</span> Scan Entire Folder
                        </button>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px;">
                            <button type="button" class="btn-action" style="padding: 6px 4px; font-size: 11px; background: rgba(99,102,241,0.18); border: 1px solid rgba(99,102,241,0.35); color: #c7d2fe; text-align: center; border-radius: 6px;" onclick="scanBenchmarkApp(${app.id}, 'requirements')" title="Scan only requirements.txt manifest">
                                📄 requirements
                            </button>
                            <button type="button" class="btn-action" style="padding: 6px 4px; font-size: 11px; background: rgba(14,165,233,0.18); border: 1px solid rgba(14,165,233,0.35); color: #bae6fd; text-align: center; border-radius: 6px;" onclick="scanBenchmarkApp(${app.id}, 'code')" title="Scan only Python source files (.py)">
                                🐍 Python Code
                            </button>
                        </div>
                    </div>
                `;
                grid.appendChild(card);
            });
        }

        function scanBenchmarkApp(appId, targetType = 'all') {
            const targetApp = benchmarkApps.find(a => a.id === appId) || { name: `App ${appId}` };
            resetDashboardState(false);
            let modeTitle = "Analyzing Application Folder";
            let modeDetail = `Evaluating full application "${escapeHtml(targetApp.name)}" (Python source code, AST, runtime sandbox, and dependencies)...`;
            if (targetType === "requirements") {
                modeTitle = "Analyzing Requirements File";
                modeDetail = `Evaluating dependencies in "${escapeHtml(targetApp.name)}" requirements.txt...`;
            } else if (targetType === "code") {
                modeTitle = "Analyzing Python Source Code";
                modeDetail = `Evaluating Python source code in "${escapeHtml(targetApp.name)}" (AST injection, entropy, and dynamic execution)...`;
            }
            showToast(modeTitle, modeDetail, false, false, "🔍");
            
            fetch("/scan_benchmark_app", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ app_id: appId, target_type: targetType })
            })
            .then(res => {
                if (!res.ok) throw new Error("Application threat scan failed or backend returned error.");
                return res.json();
            })
            .then(data => {
                hideToast();
                renderDashboard(data.predictions, data.graph);
            })
            .catch(err => {
                resetDashboardState(false);
                showToast("Application Scan Error", err.message || "Failed to scan application.", true, true, "⚠️");
            });
        }

        // Complete dashboard state reset
        function resetDashboardState(callBackend = true) {
            // 0. Reset Application Profile Banner
            const appBanner = document.getElementById("appProfileBanner");
            if (appBanner) appBanner.style.display = "none";

            // 1. Reset project risk badge in header
            const riskText = document.getElementById("projectRiskText");
            if (riskText) {
                riskText.innerHTML = "-";
                riskText.style.color = "var(--text-muted)";
            }

            // 2. Reset Early Warning KPI cards
            const kpiLatency = document.getElementById("kpiLatency");
            if (kpiLatency) kpiLatency.innerText = "-";
            const kpiMedian = document.getElementById("kpiMedian");
            if (kpiMedian) kpiMedian.innerText = "-";
            const kpi24h = document.getElementById("kpi24h");
            if (kpi24h) kpi24h.innerText = "-";
            const kpiEdr = document.getElementById("kpiEdr");
            if (kpiEdr) kpiEdr.innerText = "-";

            // 3. Clear Risk Matrix table
            const tableBody = document.getElementById("riskTableBody");
            if (tableBody) tableBody.innerHTML = "";

            // 4. Clear Explainable AI blocks
            const xaiContainer = document.getElementById("xaiContainer");
            if (xaiContainer) xaiContainer.innerHTML = "";

            // 5. Clear Attack Propagation paths
            const apContainer = document.getElementById("attackPathsContainer");
            if (apContainer) apContainer.innerHTML = "";

            // 6. Clear Automated Remediation recipes and badge
            const remedContainer = document.getElementById("remediationContainer");
            if (remedContainer) remedContainer.innerHTML = "";
            const remedBadge = document.getElementById("remediationBadge");
            if (remedBadge) remedBadge.innerText = "0 Actions";

            // 7. Stop active D3 simulation and wipe SVG
            if (currentSimulation) {
                try { currentSimulation.stop(); } catch(e) {}
                currentSimulation = null;
            }
            d3.select("#graphSvg").selectAll("*").remove();
            currentNodeSelection = null;

            // 8. Clear file input, folder input, path input and drag styling
            const fileInput = document.getElementById("fileInput");
            if (fileInput) fileInput.value = "";
            const folderInput = document.getElementById("folderInput");
            if (folderInput) folderInput.value = "";
            const dirPathInput = document.getElementById("dirPathInput");
            if (dirPathInput) dirPathInput.value = "";
            const filePathInput = document.getElementById("filePathInput");
            if (filePathInput) filePathInput.value = "";
            const dropZone = document.getElementById("dropZone");
            if (dropZone) dropZone.classList.remove("dragover");

            // 9. Show upload container and hide results/actions
            const uploadContainer = document.getElementById("uploadContainer");
            if (uploadContainer) uploadContainer.style.display = "block";
            const resultsContainer = document.getElementById("resultsContainer");
            if (resultsContainer) resultsContainer.style.display = "none";
            const gatekeeperActions = document.getElementById("gatekeeperActions");
            if (gatekeeperActions) gatekeeperActions.style.display = "none";

            // 10. Re-render benchmark grid
            renderBenchmarkAppsGrid();

            // 11. Call backend /reset endpoint to clean staging files
            if (callBackend) {
                fetch("/reset", { method: "POST" }).catch(() => {});
            }
        }

        // XSS sanitization helper
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // HTML5 Recursive Folder Traversal for Drag and Drop
        async function readAllEntriesFromReader(reader) {
            const entries = [];
            while (true) {
                const batch = await new Promise((resolve, reject) => {
                    reader.readEntries(resolve, reject);
                });
                if (!batch || batch.length === 0) break;
                entries.push(...batch);
            }
            return entries;
        }

        async function traverseFileSystemEntry(entry, path = "") {
            const files = [];
            if (entry.isFile) {
                const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
                file.fullPath = (path ? path + "/" : "") + file.name;
                files.push(file);
            } else if (entry.isDirectory) {
                const reader = entry.createReader();
                const entries = await readAllEntriesFromReader(reader);
                for (const child of entries) {
                    const subFiles = await traverseFileSystemEntry(child, (path ? path + "/" : "") + entry.name);
                    files.push(...subFiles);
                }
            }
            return files;
        }

        async function extractFilesFromDataTransfer(dataTransfer) {
            const files = [];
            let folderName = "";
            const items = dataTransfer.items;
            if (items && items.length > 0 && items[0].webkitGetAsEntry) {
                for (let i = 0; i < items.length; i++) {
                    const entry = items[i].webkitGetAsEntry();
                    if (entry) {
                        if (entry.isDirectory && !folderName) {
                            folderName = entry.name;
                        }
                        const traversed = await traverseFileSystemEntry(entry);
                        files.push(...traversed);
                    }
                }
            }
            if (files.length === 0 && dataTransfer.files && dataTransfer.files.length > 0) {
                for (let i = 0; i < dataTransfer.files.length; i++) {
                    files.push(dataTransfer.files[i]);
                }
            }
            return { files, folderName };
        }

        // Scan Local Project Directory from Path
        function scanLocalDirectory() {
            const input = document.getElementById("dirPathInput");
            const dirPath = input ? input.value.trim() : "";
            if (!dirPath) {
                alert("Please enter a local project folder path (e.g. test_cases/app_01_clean_calculator).");
                return;
            }

            resetDashboardState(false);
            showToast("Scanning Project Folder", `Traversing and evaluating all files inside "${escapeHtml(dirPath)}"...`, false, false, "🔍");

            fetch("/scan_directory", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ directory_path: dirPath })
            })
            .then(async res => {
                if (!res.ok) {
                    const err = await res.text();
                    throw new Error(err || "Failed to scan folder.");
                }
                return res.json();
            })
            .then(data => {
                hideToast();
                renderDashboard(data.predictions, data.graph);
            })
            .catch(err => {
                resetDashboardState(false);
                showToast("Folder Scan Error", err.message || "Could not analyze the folder path.", true, true, "⚠️");
            });
        }

        // Scan Local File from Path
        function scanLocalFile(presetPath) {
            const input = document.getElementById("filePathInput");
            if (presetPath && input) input.value = presetPath;
            const filePath = input ? input.value.trim() : (presetPath || "");
            if (!filePath) {
                alert("Please enter a local file path (e.g. test_cases/app_01_clean_calculator/calculator.py or requirements.txt).");
                return;
            }

            resetDashboardState(false);
            showToast("Scanning File", `Targeting and analyzing file "${escapeHtml(filePath)}"...`, false, false, "📄");

            fetch("/scan_file", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ file_path: filePath })
            })
            .then(async res => {
                if (!res.ok) {
                    const err = await res.text();
                    throw new Error(err || "Failed to scan file.");
                }
                return res.json();
            })
            .then(data => {
                hideToast();
                renderDashboard(data.predictions, data.graph);
            })
            .catch(err => {
                resetDashboardState(false);
                showToast("File Scan Error", err.message || "Could not analyze the file path.", true, true, "⚠️");
            });
        }

        // Multi-file and Project Folder uploader
        function handleUploadedFiles(fileList, folderName = "") {
            if (!fileList || fileList.length === 0) return;

            // If only 1 requirements.txt file, use standard upload
            if (fileList.length === 1 && fileList[0].name.endsWith(".txt")) {
                uploadRequirementsFile(fileList[0]);
                return;
            }

            resetDashboardState(false);
            const dispName = folderName ? `folder "${escapeHtml(folderName)}" (${fileList.length} files)` : `${fileList.length} files`;
            showToast("Analyzing Application Folder", `Reading and scanning ${dispName} — evaluating Python AST, setup hooks, and dependencies...`, false, false, "🔍");

            const filesArray = Array.from(fileList);
            const readPromises = filesArray.map(file => {
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    const fname = file.webkitRelativePath || file.fullPath || file.name;
                    reader.onload = e => resolve({ name: fname, content: e.target.result });
                    reader.onerror = () => reject(new Error(`Failed to read file ${fname}`));
                    reader.readAsText(file);
                });
            });

            Promise.all(readPromises)
            .then(readFiles => {
                return fetch("/scan_application", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ files: readFiles, folder_name: folderName })
                });
            })
            .then(res => {
                if (!res.ok) throw new Error("Application threat scan failed or backend returned error.");
                return res.json();
            })
            .then(data => {
                hideToast();
                renderDashboard(data.predictions, data.graph);
            })
            .catch(err => {
                resetDashboardState(false);
                showToast("Analysis Error", err.message || "Failed to scan uploaded application files.", true, true, "⚠️");
            });
        }

        // File drag & drop / browse event handlers
        const dropZone = document.getElementById("dropZone");
        const fileInput = document.getElementById("fileInput");
        const folderInput = document.getElementById("folderInput");
        const dirPathInput = document.getElementById("dirPathInput");
        const filePathInput = document.getElementById("filePathInput");

        if (dirPathInput) {
            dirPathInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    scanLocalDirectory();
                }
            });
        }

        if (filePathInput) {
            filePathInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    scanLocalFile();
                }
            });
        }
        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });
        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragover");
        });
        dropZone.addEventListener("drop", async (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            const { files, folderName } = await extractFilesFromDataTransfer(e.dataTransfer);
            if (files.length > 0) {
                handleUploadedFiles(files, folderName);
            }
        });
        fileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                handleUploadedFiles(e.target.files, "");
            }
        });
        folderInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                const files = Array.from(e.target.files);
                const folderName = files[0] && files[0].webkitRelativePath ? files[0].webkitRelativePath.split('/')[0] : "";
                handleUploadedFiles(files, folderName);
            }
        });

        function uploadRequirementsFile(file) {
            if (!file) return;

            // Immediately reset all previous values so no stale data is shown
            resetDashboardState(false);
            showToast("Analyzing Requirements", 'Scanning "' + escapeHtml(file.name) + '" — staging packages and querying threat intelligence...', false, false, "🔍");
            
            const reader = new FileReader();
            reader.onload = function(event) {
                const fileContent = event.target.result;
                fetch("/scan_requirements", {
                    method: "POST",
                    headers: { "Content-Type": "text/plain" },
                    body: fileContent
                })
                .then(res => {
                    if (!res.ok) throw new Error("Threat scan failed or invalid requirements file.");
                    return res.json();
                })
                .then(data => {
                    hideToast();
                    renderDashboard(data.predictions, data.graph);
                })
                .catch(err => {
                    resetDashboardState(false);
                    showToast("Analysis Error", err.message || "Failed to scan requirements.", true, true, "⚠️");
                });
            };
            reader.onerror = function() {
                resetDashboardState(false);
                showToast("File Read Error", "Could not read the uploaded requirements file.", true, true, "⚠️");
            };
            reader.readAsText(file);
        }

        // Approve and Run pip install
        function approveInstallation() {
            showToast("Running Local Installation", "Executing pip install on the host machine. Please look at the terminal for progress...", false, false, "⏳");
            
            fetch("/install", { method: "POST" })
            .then(async res => {
                if (!res.ok) {
                    const errText = await res.text();
                    throw new Error(errText || "Host installation failed");
                }
                return res.text();
            })
            .then(msg => {
                showToast(
                    "Installation Complete",
                    "All approved packages have been installed successfully on the host! Would you like to continue and scan another project?",
                    true,
                    true,
                    "✅"
                );
            })
            .catch(err => {
                showToast("Installation Error", err.message, true, true, "⚠️");
            });
        }

        // Output Explorer Modal Handlers
        function openArtifactsExplorer() {
            fetch("/list_outputs")
            .then(res => res.json())
            .then(files => {
                const listContainer = document.getElementById("explorerFilesList");
                listContainer.innerHTML = "";
                files.forEach(f => {
                    const btn = document.createElement("div");
                    btn.innerText = "📄 " + f;
                    btn.style.cssText = "padding: 10px 14px; border-radius: 6px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); cursor: pointer; transition: all 0.2s ease; font-size: 13px; font-weight: 500; margin-bottom: 8px;";
                    btn.onmouseover = () => btn.style.background = "rgba(255,255,255,0.08)";
                    btn.onmouseout = () => btn.style.background = "rgba(255,255,255,0.02)";
                    btn.onclick = () => previewArtifactFile(f);
                    listContainer.appendChild(btn);
                });
                document.getElementById("explorerOverlay").style.display = "flex";
            });
        }

        function previewArtifactFile(filename) {
            document.getElementById("explorerPreviewHeader").innerText = "Previewing: " + filename;
            if (filename.endsWith(".png")) {
                const imgUrl = "/view_output?file=" + encodeURIComponent(filename);
                document.getElementById("explorerCodeBlock").innerHTML = `<div style="display: flex; justify-content: center; align-items: center; width: 100%; height: 100%; padding: 10px; background: rgba(10,11,16,0.3); border-radius: 4px;"><img src="${imgUrl}" style="max-width: 100%; max-height: 500px; border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,0.6);" /></div>`;
                return;
            }
            
            document.getElementById("explorerCodeBlock").innerHTML = "Loading content...";
            fetch("/view_output?file=" + encodeURIComponent(filename))
            .then(res => res.text())
            .then(text => {
                try {
                    const parsed = JSON.parse(text);
                    document.getElementById("explorerCodeBlock").innerText = JSON.stringify(parsed, null, 2);
                } catch(e) {
                    document.getElementById("explorerCodeBlock").innerText = text;
                }
            })
            .catch(err => {
                document.getElementById("explorerCodeBlock").innerText = "Error loading file: " + err.message;
            });
        }

        function closeArtifactsExplorer() {
            document.getElementById("explorerOverlay").style.display = "none";
        }

        // Reject / Abort scan
        function abortInstallation() {
            fetch("/abort", { method: "POST" })
            .then(() => {
                resetDashboardState(false);
                showToast(
                    "Project Rejected & Aborted",
                    "Dependencies installation was aborted and staging files were cleared. Would you like to continue and scan another project?",
                    true,
                    true,
                    "🛑"
                );
            })
            .catch(() => {
                resetDashboardState(false);
                showToast(
                    "Project Rejected",
                    "Installation cancelled. You can now upload and scan another project.",
                    true,
                    true,
                    "🛑"
                );
            });
        }

        function showToast(title, message, showClose = false, showContinue = false, icon = "🛡️") {
            const toastTitle = document.getElementById("toastTitle");
            const toastMessage = document.getElementById("toastMessage");
            const toastIcon = document.getElementById("toastIcon");
            const toastCloseBtn = document.getElementById("toastCloseBtn");
            const toastContinueBtn = document.getElementById("toastContinueBtn");

            if (toastTitle) toastTitle.innerText = title;
            if (toastMessage) toastMessage.innerText = message;
            if (toastIcon) toastIcon.innerText = icon;
            if (toastCloseBtn) toastCloseBtn.style.display = showClose ? "inline-block" : "none";
            if (toastContinueBtn) toastContinueBtn.style.display = showContinue ? "inline-block" : "none";
            document.getElementById("toastOverlay").style.display = "flex";
        }

        function hideToast() {
            document.getElementById("toastOverlay").style.display = "none";
        }

        function continueAndUploadNew() {
            hideToast();
            resetDashboardState(true);
        }

        function closeToast() {
            hideToast();
            const title = document.getElementById("toastTitle") ? document.getElementById("toastTitle").innerText : "";
            if (title.includes("Rejected") || title.includes("Success") || title.includes("Complete") || title.includes("Cancelled") || title.includes("Error")) {
                resetDashboardState(true);
            }
        }

        function resetAndUploadNew() {
            resetDashboardState(true);
        }

        // Main dashboard renderer
        function renderDashboard(predData, gData) {
            if (!predData || !predData.package_risks || Object.keys(predData.package_risks).length === 0) {
                resetDashboardState(false);
                return;
            }
            
            document.getElementById("uploadContainer").style.display = "none";
            document.getElementById("resultsContainer").style.display = "block";
            document.getElementById("gatekeeperActions").style.display = "flex";
            
            // Project level risk score
            const pr = predData.project_risk_score !== undefined ? Number(predData.project_risk_score) : 0;

            // 0. Render Application Profile Banner
            const appBanner = document.getElementById("appProfileBanner");
            if (appBanner) {
                if (predData.app_info) {
                    appBanner.style.display = "block";
                    const bName = document.getElementById("bannerAppName");
                    if (bName) bName.innerText = predData.app_info.name || "Custom Application";
                    const bDesc = document.getElementById("bannerAppDesc");
                    if (bDesc) bDesc.innerText = predData.app_info.description || "Python application source code and dependency graph analysis.";
                    const bFiles = document.getElementById("bannerAppFiles");
                    if (bFiles) bFiles.innerText = predData.app_info.code_files || "Source Files Analyzed";
                    const bCat = document.getElementById("bannerAppCategory");
                    if (bCat) bCat.innerText = predData.app_info.category || "Custom Application";
                    
                    const bVerdict = document.getElementById("bannerAppVerdictBadge");
                    if (bVerdict) {
                        const verdict = predData.app_info.expected_verdict || (pr > 0.6 ? "QUARANTINED" : (pr > 0.3 ? "MONITOR" : "APPROVED"));
                        bVerdict.innerText = verdict;
                        bVerdict.className = `badge ${pr > 0.6 ? 'badge-danger' : (pr > 0.3 ? 'badge-warning' : 'badge-success')}`;
                    }
                } else {
                    appBanner.style.display = "none";
                }
            }

            // 1. Render project level risk in header
            const riskText = document.getElementById("projectRiskText");
            if (pr > 0.6) {
                riskText.innerHTML = (pr * 100).toFixed(0) + "% - HIGH RISK";
                riskText.style.color = "var(--danger)";
            } else if (pr > 0.3) {
                riskText.innerHTML = (pr * 100).toFixed(0) + "% - MEDIUM RISK";
                riskText.style.color = "var(--warning)";
            } else {
                riskText.innerHTML = (pr * 100).toFixed(0) + "% - LOW RISK";
                riskText.style.color = "var(--success)";
            }

            // 2. Render Early Warning KPIs
            const ew = predData.early_warning_metrics || {};
            const lat = ew.detection_latency_hours !== undefined ? ew.detection_latency_hours.toFixed(1) : "0.0";
            const med = ew.median_ttd_hours !== undefined ? ew.median_ttd_hours.toFixed(1) : "0.0";
            const t24 = ew.ttd_at_24h_percent !== undefined ? ew.ttd_at_24h_percent.toFixed(1) : "100.0";
            const edr = ew.early_detection_rate_percent !== undefined ? ew.early_detection_rate_percent.toFixed(1) : "100.0";
            
            document.getElementById("kpiLatency").innerText = lat + "h";
            document.getElementById("kpiMedian").innerText = med + "h";
            document.getElementById("kpi24h").innerText = t24 + "%";
            document.getElementById("kpiEdr").innerText = edr + "%";

            // 3. Render table
            const tableBody = document.getElementById("riskTableBody");
            tableBody.innerHTML = "";
            Object.entries(predData.package_risks).forEach(([pkg, score]) => {
                const conf = predData.confidence_scores[pkg] || 0.9;
                const explanations = predData.explanations[pkg] || {};
                const driftVal = explanations.temporal_drift || 0.1;
                
                const badgeClass = score > 0.6 ? "badge-danger" : (score > 0.3 ? "badge-warning" : "badge-success");
                const badgeLabel = score > 0.6 ? "CRITICAL" : (score > 0.3 ? "SUSPICIOUS" : "SECURE");
                
                const radv = (predData.radv_scores && predData.radv_scores[pkg] !== undefined) ? predData.radv_scores[pkg].toFixed(2) : "0.00";
                const br = (predData.blast_radius_scores && predData.blast_radius_scores[pkg] !== undefined) ? predData.blast_radius_scores[pkg] : 0;
                const threats = (predData.package_threats && predData.package_threats[pkg]) ? predData.package_threats[pkg] : [];
                
                let threatBadges = '<span style="color: var(--text-muted); font-size: 11px;">Clean</span>';
                if (threats.length > 0) {
                    threatBadges = threats.map(t => `<span class="badge badge-danger" style="margin-right: 4px; font-size: 10px;" title="${escapeHtml(t.detail)}">${escapeHtml(t.id)}: ${escapeHtml(t.vector)}</span>`).join('');
                }
                
                const row = `<tr>
                    <td><strong>${escapeHtml(pkg)}</strong></td>
                    <td>
                        <span class="badge ${badgeClass}">${(score * 100).toFixed(0)}% (${badgeLabel})</span>
                    </td>
                    <td style="font-family: 'Space Grotesk', sans-serif; color: #a5b4fc; font-weight: 600;">${radv}</td>
                    <td style="font-family: 'Space Grotesk', sans-serif;">${br}</td>
                    <td>${threatBadges}</td>
                    <td>${(conf * 100).toFixed(0)}%</td>
                    <td>
                        <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">LSTM Drift: ${driftVal.toFixed(2)}</div>
                        <div class="progress-bar-container">
                            <div class="progress-bar-fill" style="width: ${driftVal * 100}%; background: ${driftVal > 0.5 ? 'var(--danger)' : 'var(--primary)'}"></div>
                        </div>
                    </td>
                </tr>`;
                tableBody.innerHTML += row;
            });

            // 4. Render XAI Details
            const xaiContainer = document.getElementById("xaiContainer");
            xaiContainer.innerHTML = "";
            Object.entries(predData.explanations).forEach(([pkg, exp]) => {
                if (exp.top_features.length > 0) {
                    const featureLines = exp.top_features.map(([f, weight]) => `
                        <div style="display: flex; justify-content: space-between; font-size: 11px;">
                            <span>${escapeHtml(f)}</span>
                            <span style="font-family: 'Space Grotesk', sans-serif;">${(weight * 100).toFixed(0)}% importance</span>
                        </div>
                    `).join('');
                    
                    const neighborLines = exp.top_influencing_nodes.map(([n, w]) => `
                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(n)} (attention: ${w.toFixed(2)})</div>
                    `).join('') || '<div style="font-size: 11px; color: var(--text-muted);">No graph neighbors</div>';
                    
                    const block = `<div class="xai-block">
                        <div style="font-weight: 600; color: #a5b4fc; margin-bottom: 6px;">Package: ${escapeHtml(pkg)}</div>
                        <div style="font-size: 12px; margin-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">Top Saliency Features:</div>
                        ${featureLines}
                        <div style="font-size: 12px; margin-top: 8px; margin-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">Graph Attention Influences:</div>
                        ${neighborLines}
                    </div>`;
                    xaiContainer.innerHTML += block;
                }
            });

            // 5. Render Attack paths
            const apContainer = document.getElementById("attackPathsContainer");
            apContainer.innerHTML = "";
            if (predData.attack_paths.length === 0) {
                apContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">No critical transitive attack propagation paths detected.</div>';
            } else {
                predData.attack_paths.forEach(ap => {
                    const block = `<div class="attack-path-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span class="badge badge-danger">PROPAGATED RISK: ${(ap.risk_score * 100).toFixed(0)}%</span>
                            <span style="font-size: 11px; color: var(--text-muted);">CVE: ${escapeHtml(ap.cve_id)}</span>
                        </div>
                        <div class="attack-path-route">${escapeHtml(ap.path)}</div>
                    </div>`;
                    apContainer.innerHTML += block;
                });
            }

            // 5.5 Render Automated Remediation Recipes
            const remedContainer = document.getElementById("remediationContainer");
            const remedBadge = document.getElementById("remediationBadge");
            if (remedContainer) {
                remedContainer.innerHTML = "";
                const plan = predData.remediation_plan || {};
                const actions = plan.actions || [];
                if (remedBadge) remedBadge.innerText = `${actions.length} Actions Available`;

                if (actions.length === 0) {
                    remedContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 13px; grid-column: 1 / -1;">All packages verified clean. No remediation upgrade required.</div>';
                } else {
                    actions.forEach((act, idx) => {
                        const badgeClass = act.severity === "CRITICAL" ? "badge-danger" : "badge-warning";
                        const cvesPreview = escapeHtml(act.cves_resolved.slice(0, 3).join(', ') + (act.cves_resolved.length > 3 ? '...' : ''));
                        const safeCmd = escapeHtml(act.upgrade_command);
                        const block = `<div class="remediation-card">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <strong style="font-size: 15px; color: #a5b4fc;">${escapeHtml(act.package)}</strong>
                                <span class="badge ${badgeClass}">${escapeHtml(act.severity)} (CVSS: ${act.max_cvss})</span>
                            </div>
                            <div style="font-size: 12px; color: var(--text-muted);">
                                <span>Current: <code style="color: #fda4af;">${escapeHtml(act.current_version)}</code></span> &rarr; 
                                <span>Recommended: <code style="color: #86efac; font-weight: 700;">&gt;=${escapeHtml(act.recommended_version)}</code></span>
                            </div>
                            <div style="font-size: 11px; color: var(--text-muted);">
                                Fixes ${act.cve_count} CVEs: <span style="color: #fca5a5;">${cvesPreview}</span>
                            </div>
                            <div class="remediation-cmd-box">
                                <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-right: 8px;">${safeCmd}</span>
                                <button class="btn-copy-fix" id="copyBtn_${idx}" onclick="copyFixCommand(this.getAttribute('data-cmd'), 'copyBtn_${idx}')" data-cmd="${safeCmd}">Copy</button>
                            </div>
                        </div>`;
                        remedContainer.innerHTML += block;
                    });
                }
            }

            // 6. Draw D3 homogeneous graph
            drawD3Graph(gData, predData);
        }

        function copyFixCommand(cmd, btnId) {
            navigator.clipboard.writeText(cmd).then(() => {
                const btn = document.getElementById(btnId);
                if (btn) {
                    const oldText = btn.innerText;
                    btn.innerText = "Copied! ✓";
                    btn.style.background = "var(--success)";
                    setTimeout(() => {
                        btn.innerText = oldText;
                        btn.style.background = "";
                    }, 1500);
                }
            });
        }

        // Homogeneous force-directed graph renderer using D3.js
        function drawD3Graph(graphData, predictionData) {
            if (currentSimulation) {
                try { currentSimulation.stop(); } catch(e) {}
                currentSimulation = null;
            }
            d3.select("#graphSvg").selectAll("*").remove();
            currentNodeSelection = null;

            if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
                return;
            }
            
            const svg = d3.select("#graphSvg");
            const container = document.querySelector(".graph-container");
            const width = container ? container.clientWidth : 800;
            const height = 500;

            currentSimulation = d3.forceSimulation(graphData.nodes)
                .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(80))
                .force("charge", d3.forceManyBody().strength(-60))
                .force("collide", d3.forceCollide().radius(d => getNodeSize(d) + 15))
                .force("center", d3.forceCenter(width / 2, height / 2));

            // Edge markers (Arrows)
            svg.append("defs").selectAll("marker")
                .data(["suit", "licensing", "resolved"])
                .enter().append("marker")
                .attr("id", d => d)
                .attr("viewBox", "0 -5 10 10")
                .attr("refX", 20)
                .attr("refY", 0)
                .attr("markerWidth", 6)
                .attr("markerHeight", 6)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("fill", "rgba(255, 255, 255, 0.15)");

            // Add links
            const link = svg.append("g")
                .selectAll("line")
                .data(graphData.links)
                .enter().append("line")
                .attr("stroke", d => {
                    if (d.relationship === "vulnerable_to") return "rgba(239, 68, 68, 0.4)";
                    if (d.relationship === "depends_on") return "rgba(99, 102, 241, 0.4)";
                    return "rgba(255, 255, 255, 0.08)";
                })
                .attr("stroke-width", d => d.relationship === "vulnerable_to" ? 2 : 1)
                .attr("marker-end", "url(#suit)");

            // Color mapping for node types
            function getNodeColor(d) {
                if (d.type === "package") {
                    const r = predictionData.package_risks[d.id] || 0.1;
                    return r > 0.6 ? "#f87171" : (r > 0.3 ? "#fbbf24" : "#818cf8");
                }
                if (d.type === "version") return "#fda4af";
                if (d.type === "cve") return "#f43f5e";
                if (d.type === "maintainer") return "#34d399";
                return "#9ca3af";
            }

            // Size mapping for node types
            function getNodeSize(d) {
                if (d.type === "package") {
                    const r = predictionData.package_risks[d.id] || 0.1;
                    return 10 + (r * 12);
                }
                if (d.type === "cve") return 14;
                return 8;
            }

            // Add nodes
            const node = svg.append("g")
                .selectAll("circle")
                .data(graphData.nodes)
                .enter().append("circle")
                .attr("r", getNodeSize)
                .attr("fill", getNodeColor)
                .attr("stroke", "#0a0b10")
                .attr("stroke-width", 2)
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended))
                .on("dblclick", function(event, d) {
                    d.fx = null;
                    d.fy = null;
                    d3.select(this).attr("stroke", "#0a0b10").attr("stroke-width", 2);
                    if (currentSimulation) currentSimulation.alpha(0.3).restart();
                });

            currentNodeSelection = node;

            // Node labels
            const labels = svg.append("g")
                .selectAll("text")
                .data(graphData.nodes)
                .enter().append("text")
                .text(d => d.id.split("@")[0])
                .attr("font-size", d => d.type === "package" ? "12px" : "9px")
                .attr("dx", d => getNodeSize(d) + 4)
                .attr("dy", ".35em")
                .attr("fill", "#f3f4f6")
                .attr("pointer-events", "none");

            // Simulation update
            currentSimulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                node
                    .attr("cx", d => {
                        d.x = Math.max(25, Math.min(width - 25, d.x));
                        return d.x;
                    })
                    .attr("cy", d => {
                        d.y = Math.max(25, Math.min(height - 25, d.y));
                        return d.y;
                    });

                labels
                    .attr("x", d => d.x)
                    .attr("y", d => d.y);
            });

            function dragstarted(event, d) {
                if (!event.active && currentSimulation) currentSimulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active && currentSimulation) currentSimulation.alphaTarget(0);
                d3.select(this).attr("stroke", "#ffffff").attr("stroke-width", 3);
            }

            // Global release pinned nodes function
            window.releaseAllNodes = function() {
                if (!currentNodeSelection || !currentSimulation) return;
                currentNodeSelection.each(d => {
                    d.fx = null;
                    d.fy = null;
                });
                currentNodeSelection.attr("stroke", "#0a0b10").attr("stroke-width", 2);
                currentSimulation.alpha(0.3).restart();
            };
        }

        // Render 10 Benchmark Applications grid
        renderBenchmarkAppsGrid();

        // Initialize dashboard if predictionData has items (initial page load)
        renderDashboard(predictionData, graphData);
    </script>
</body>
</html>
"""

def generate_security_dashboard(prediction_results, resolved_packages, output_path="outputs/dashboard.html"):
    """
    Compiles NetworkX graph structure and predictor outputs into an interactive D3.html dashboard.
    """
    print(f"\nGenerating Interactive Security Dashboard at: {output_path}...")
    G = prediction_results["graph"]
    
    # 1. Convert NetworkX nodes to D3-compatible nodes
    nodes_list = []
    for node, attr in G.nodes(data=True):
        nodes_list.append({
            "id": node,
            "type": attr.get("type", "package")
        })
        
    # 2. Convert NetworkX edges to D3-compatible links
    links_list = []
    for u, v, attr in G.edges(data=True):
        links_list.append({
            "source": u,
            "target": v,
            "relationship": attr.get("relationship", "depends_on")
        })
        
    graph_data_json = json.dumps({"nodes": nodes_list, "links": links_list}).replace("<", "\\u003c")
    
    # 3. Clean prediction outputs (remove PyTorch tensor structures)
    prediction_clean = {
        "project_risk_score": float(prediction_results["project_risk_score"]),
        "package_risks": {k: float(v) for k, v in prediction_results["package_risks"].items()},
        "confidence_scores": {k: float(v) for k, v in prediction_results["confidence_scores"].items()},
        "radv_scores": {k: float(v) for k, v in prediction_results.get("radv_scores", {}).items()},
        "blast_radius_scores": {k: int(v) for k, v in prediction_results.get("blast_radius_scores", {}).items()},
        "early_warning_metrics": prediction_results.get("early_warning_metrics", {}),
        "package_threats": prediction_results.get("package_threats", {}),
        "attack_paths": prediction_results["attack_paths"],
        "remediation_plan": prediction_results.get("remediation_plan", {}),
        "app_info": prediction_results.get("app_info", None),
        "explanations": {}
    }
    
    # Format explanations cleanly
    for pkg, exp in prediction_results["explanations"].items():
        prediction_clean["explanations"][pkg] = {
            "graph_risk": float(exp["graph_risk"]),
            "temporal_drift": float(exp["temporal_drift"]),
            "top_features": [(f, float(w)) for f, w in exp["top_features"]],
            "top_influencing_nodes": [(n, float(w)) for n, w in exp["top_influencing_nodes"]]
        }
        
    prediction_data_json = json.dumps(prediction_clean).replace("<", "\\u003c")
    
    # 1. Clean up double curly braces in HTML_TEMPLATE first to avoid bracket formatting conflicts
    compiled_template = HTML_TEMPLATE.replace("{{", "{").replace("}}", "}")
    
    # 2. Inject prediction and graph JSON strings into the cleaned template
    html_content = compiled_template.replace("{graph_data_json}", graph_data_json).replace("{prediction_data_json}", prediction_data_json)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print("Security Dashboard created successfully.")
