# 3D Nessus Scan Visualization

A Python project that converts Nessus-like vulnerability scan results into an interactive 3D graph.

## ✨ Features

- Visualizes:
  - Subnet → Hosts → Services → Vulnerabilities
- Node size is based on **risk score**
- Risk score = CVSS + weighted severity
- Interactive 3D view using Plotly
- Designed for SOC, Blue Team, and CISO risk prioritization

## 📸 Example

(Add screenshot here)

## 🚀 How to Run

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python generate_large_nessus_scan.py
python visualize_3d_nessus.py nesus_large.json
