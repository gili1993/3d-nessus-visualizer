# 3D Nessus Scan Visualization
<img width="432" height="279" alt="image" src="https://github.com/user-attachments/assets/3f6cfd70-7a51-4a4d-91f5-bbd1e4a00d97" />

# 3D Nessus Scan Visualization

An interactive 3D visualization tool that converts vulnerability scan results (Nessus or any scanner that exports JSON)
into a navigable 3D graph of:

**Subnet → Hosts → Services → Vulnerabilities**

Instead of reading flat tables, this tool helps you **see risk concentration and attack surface**.

---

## Concept Architecture

> This diagram illustrates how scan data is transformed into a 3D risk graph.

![Architecture](architecture.png)

---

## Features

- Visualizes:
  - Subnet → Hosts → Services → Vulnerabilities
- Works with:
  - Nessus scan exports
  - Or any vulnerability scanner that outputs JSON (after normalization)
- Node size is based on **risk score**
- Risk score = **CVSS + weighted severity**
- Interactive 3D view using Plotly
- Designed for SOC, Blue Team, and CISO risk prioritization

---

## Important Note About Test Data

This repository includes a file:
generate_large_nessus_scan.py

This script is **ONLY for demo, testing and performance simulation**.

> The real tool is designed to work with **real scan results** from:
- Nessus
- Or any other vulnerability scanner that exports JSON

The generator exists only to:
- Test performance on 100+ hosts
- Demonstrate the visualization without sensitive data
- Keep the repository free of real customer data

---

## How to Run

python -m venv venv
pip install -r requirements.txt
python visualize_3d_nessus.py <your_scan.json>

##  Requirements
Python 3.10+
networkx
plotly
numpy
scipy

## Architecture (Code Flow)
Scan JSON (Nessus / Other Scanner)
        ↓
   normalize.py
        ↓
   build_graph.py
        ↓
   plot_3d.py
        ↓
 Interactive 3D Graph

## Why This Exists

Security teams usually get vulnerability data as:
  - Huge tables
  - Thousands of rows
No intuitive sense of:
  - Where risk is concentrated
  - Which hosts are the real problem
  - How the attack surface looks as a system
  - This project turns scan data into a spatial risk map.
