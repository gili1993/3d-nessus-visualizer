# 3D Nessus Scan Visualization
<img width="432" height="279" alt="image" src="https://github.com/user-attachments/assets/3f6cfd70-7a51-4a4d-91f5-bbd1e4a00d97" />


An interactive 3D visualization tool that converts vulnerability scan results (Nessus or any scanner that exports JSON)
into a navigable 3D graph of:

**Subnet → Hosts → Services → Vulnerabilities**

Instead of reading flat tables, this tool helps you **see risk concentration and attack surface**.

---

## 🧠 Concept Architecture

![Architecture](architecture.png)

---

## ✨ Features

- Visualizes:
  - Subnet → Hosts → Services → Vulnerabilities
- Works with:
  - Nessus scan exports
  - Or any vulnerability scanner that outputs JSON (after normalization)
- Node size is based on **risk score**
- Risk score = CVSS + weighted severity
- Interactive 3D view using Plotly
- Designed for SOC, Blue Team, and CISO risk prioritization

---

## ⚠️ Important Note About Test Data

This repository includes a file:

```text
generate_large_nessus_scan.py
