import os
import json
import networkx as nx

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software Supply Chain Threat Intelligence Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://d3js.org/d3.v7.min.js"></script>
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

    <!-- Drag & Drop Uploader -->
    <div id="uploadContainer" style="display: block;">
        <div class="upload-zone" id="dropZone">
            <div class="upload-icon">📥</div>
            <div class="upload-title" style="font-family: 'Space Grotesk', sans-serif; font-size: 18px; margin-bottom: 6px;">Drag & Drop requirements.txt here</div>
            <div class="upload-subtitle" style="font-size: 13px;">or click to browse local files</div>
            <input type="file" id="fileInput" accept=".txt" style="display: none;">
        </div>
    </div>

    <div id="resultsContainer" style="display: none;">
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
    </div> <!-- Close grid-container -->
    
    <!-- Gatekeeper Controls -->
    <div class="gatekeeper-actions" id="gatekeeperActions">
        <button class="btn-action btn-reject" onclick="abortInstallation()">Reject & Abort</button>
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
        <div class="toast-content">
            <h2 id="toastTitle" style="font-family: 'Space Grotesk', sans-serif;">Running Installation</h2>
            <p id="toastMessage" style="color: var(--text-muted); font-size: 14px;">Please check host terminal logs for live progress...</p>
            <button class="btn-action btn-reject" id="toastCloseBtn" style="display: none; align-self: center;" onclick="closeToast()">Close</button>
        </div>
    </div>

    <script>
        // Data injected by python builder
        const graphData = {graph_data_json};
        const predictionData = {prediction_data_json};

        // File drag & drop / browse event handlers
        const dropZone = document.getElementById("dropZone");
        const fileInput = document.getElementById("fileInput");

        dropZone.addEventListener("click", () => fileInput.click());
        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });
        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragover");
        });
        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                uploadRequirementsFile(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                uploadRequirementsFile(e.target.files[0]);
            }
        });

        function uploadRequirementsFile(file) {
            showToast("Analyzing Requirements", "Staging, downloading, and scanning package dependencies pre-install...");
            
            const reader = new FileReader();
            reader.onload = function(event) {
                const fileContent = event.target.result;
                fetch("/scan_requirements", {
                    method: "POST",
                    headers: { "Content-Type": "text/plain" },
                    body: fileContent
                })
                .then(res => {
                    if (!res.ok) throw new Error("Threat scan failed");
                    return res.json();
                })
                .then(data => {
                    hideToast();
                    renderDashboard(data.predictions, data.graph);
                })
                .catch(err => {
                    showToast("Analysis Error", err.message, true);
                });
            };
            reader.readAsText(file);
        }

        // Approve and Run pip install
        function approveInstallation() {
            showToast("Running Local Installation", "Executing pip install on the host machine. Please look at the terminal for progress...");
            
            fetch("/install", { method: "POST" })
            .then(async res => {
                if (!res.ok) {
                    const errText = await res.text();
                    throw new Error(errText || "Host installation failed");
                }
                return res.text();
            })
            .then(msg => {
                showToast("Installation Success", "All dependency check packages have been installed successfully!", true);
            })
            .catch(err => {
                showToast("Installation Error", err.message, true);
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
                showToast("Scan Cancelled", "Dependencies installation aborted. You can scan another requirements.txt file.", true);
            });
        }

        function showToast(title, message, showClose = false) {
            document.getElementById("toastTitle").innerText = title;
            document.getElementById("toastMessage").innerText = message;
            document.getElementById("toastCloseBtn").style.display = showClose ? "inline-block" : "none";
            document.getElementById("toastOverlay").style.display = "flex";
        }

        function hideToast() {
            document.getElementById("toastOverlay").style.display = "none";
        }

        function closeToast() {
            hideToast();
            // Reset to upload screen if aborted or finished
            const title = document.getElementById("toastTitle").innerText;
            if (title === "Scan Cancelled" || title === "Installation Success") {
                document.getElementById("uploadContainer").style.display = "block";
                document.getElementById("resultsContainer").style.display = "none";
                document.getElementById("gatekeeperActions").style.display = "none";
            }
        }

        // Main dashboard renderer
        function renderDashboard(predData, gData) {
            if (!predData || !predData.package_risks || Object.keys(predData.package_risks).length === 0) {
                document.getElementById("uploadContainer").style.display = "block";
                document.getElementById("resultsContainer").style.display = "none";
                document.getElementById("gatekeeperActions").style.display = "none";
                return;
            }
            
            document.getElementById("uploadContainer").style.display = "none";
            document.getElementById("resultsContainer").style.display = "block";
            document.getElementById("gatekeeperActions").style.display = "flex";
            
            // 1. Render project level risk
            const pr = predData.project_risk_score;
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
                    threatBadges = threats.map(t => `<span class="badge badge-danger" style="margin-right: 4px; font-size: 10px;" title="${t.detail}">${t.id}: ${t.vector}</span>`).join('');
                }
                
                const row = `<tr>
                    <td><strong>${pkg}</strong></td>
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
                            <span>${f}</span>
                            <span style="font-family: 'Space Grotesk', sans-serif;">${(weight * 100).toFixed(0)}% importance</span>
                        </div>
                    `).join('');
                    
                    const neighborLines = exp.top_influencing_nodes.map(([n, w]) => `
                        <div style="font-size: 11px; color: var(--text-muted);">${n} (attention: ${w.toFixed(2)})</div>
                    `).join('') || '<div style="font-size: 11px; color: var(--text-muted);">No graph neighbors</div>';
                    
                    const block = `<div class="xai-block">
                        <div style="font-weight: 600; color: #a5b4fc; margin-bottom: 6px;">Package: ${pkg}</div>
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
                            <span style="font-size: 11px; color: var(--text-muted);">CVE: ${ap.cve_id}</span>
                        </div>
                        <div class="attack-path-route">${ap.path}</div>
                    </div>`;
                    apContainer.innerHTML += block;
                });
            }

            // 6. Draw D3 homogeneous graph
            drawD3Graph(gData, predData);
        }

        // Homogeneous force-directed graph renderer using D3.js
        function drawD3Graph(graphData, predictionData) {
            d3.select("#graphSvg").selectAll("*").remove();
            
            const svg = d3.select("#graphSvg");
            const width = document.querySelector(".graph-container").clientWidth;
            const height = 500;

            const simulation = d3.forceSimulation(graphData.nodes)
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
                    simulation.alpha(0.3).restart();
                });

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
            simulation.on("tick", () => {
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
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d3.select(this).attr("stroke", "#ffffff").attr("stroke-width", 3);
            }

            // Global release pinned nodes function
            window.releaseAllNodes = function() {
                node.each(d => {
                    d.fx = null;
                    d.fy = null;
                });
                node.attr("stroke", "#0a0b10").attr("stroke-width", 2);
                simulation.alpha(0.3).restart();
            };
        }

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
        
    graph_data_json = json.dumps({"nodes": nodes_list, "links": links_list})
    
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
        
    prediction_data_json = json.dumps(prediction_clean)
    
    # 1. Clean up double curly braces in HTML_TEMPLATE first to avoid bracket formatting conflicts
    compiled_template = HTML_TEMPLATE.replace("{{", "{").replace("}}", "}")
    
    # 2. Inject prediction and graph JSON strings into the cleaned template
    html_content = compiled_template.replace("{graph_data_json}", graph_data_json).replace("{prediction_data_json}", prediction_data_json)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print("Security Dashboard created successfully.")
