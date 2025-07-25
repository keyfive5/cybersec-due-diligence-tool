# AI-Powered Cybersecurity Due Diligence Tool

This tool scans a target domain or IP for open ports and vulnerabilities, then uses OpenAI GPT to generate a concise due diligence report with risk scoring and remediation advice.

## Features
- Nmap port and service scanning
- Nuclei vulnerability scanning
- AI-generated summary and risk assessment
- Simple Streamlit web UI

## Prerequisites
- Python 3.8+
- [Nmap](https://nmap.org/download.html) installed and in your PATH
- [Nuclei](https://github.com/projectdiscovery/nuclei#installation) installed and in your PATH
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
streamlit run cybersec_due_diligence_app.py
```

Enter a domain or IP, click "Scan", and view the results and AI-generated report. You can also download the report as a text file.

---

**Note:**
- Only scan systems you have permission to test.
- The tool requires internet access for OpenAI API calls. 