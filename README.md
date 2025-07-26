# 🔒 CyberScanner Pro

**Professional Cybersecurity Assessment & Report Generator**

A powerful AI-powered cybersecurity tool that generates professional reports for clients, job applications, and consulting work. Perfect for cybersecurity professionals, freelancers, and consultants looking to monetize their skills.

## ✨ Features

### 🔍 **Security Scanning**
- **Nmap Integration**: Port scanning and service detection
- **Nuclei Vulnerability Scanner**: Automated vulnerability detection
- **AI-Powered Analysis**: Intelligent threat assessment and risk scoring

### 📋 **Professional Report Generation**
- **Multiple Report Types**: Comprehensive, Executive, Technical, Compliance
- **Client Customization**: Add client names and customize reports
- **Executive-Ready**: Professional formatting suitable for C-level presentations
- **Download Options**: TXT and JSON formats for easy sharing

### 💼 **Monetization Features**
- **Pricing Calculator**: Suggested rates for different service levels
- **Portfolio Building**: Generate sample reports for job applications
- **Freelance Ready**: Perfect for Upwork, Fiverr, and consulting gigs
- **Certification Support**: Build case studies for CISSP, CEH, etc.

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Optional: Install Nuclei (for vulnerability scanning)
```bash
# Windows (using scoop)
scoop install nuclei

# Or download from: https://nuclei.projectdiscovery.io/nuclei/get-started/
```

### Run the Application
```bash
streamlit run cybersec_due_diligence_app.py
```

## 💰 Monetization Guide

### **Freelance Opportunities**
- **Upwork/Fiverr**: Offer security assessments at $50-500 per report
- **Consulting**: Use reports for client presentations and proposals
- **Bug Bounty**: Generate detailed reports for vulnerability submissions

### **Job Applications**
- **Portfolio**: Include sample reports in your cybersecurity portfolio
- **Case Studies**: Build real-world examples for interviews
- **Certifications**: Create case studies for CISSP, CEH, OSCP

### **Suggested Pricing**
- **Basic Scan**: $50-100
- **Comprehensive Report**: $200-500
- **Executive Summary**: $150-300
- **Compliance Report**: $300-800

## 🎯 Use Cases

### **For Freelancers**
- Generate professional reports for clients
- Build a portfolio of security assessments
- Offer different service tiers (basic scan vs. comprehensive report)

### **For Job Seekers**
- Create sample reports for applications
- Demonstrate technical writing skills
- Show real-world security assessment experience

### **For Consultants**
- Present findings to executives
- Generate compliance reports
- Create detailed technical documentation

## 📊 Report Types

### **Comprehensive Report**
- Full technical analysis
- Detailed remediation steps
- Compliance impact assessment
- Cost estimates

### **Executive Summary**
- High-level risk assessment
- Business impact analysis
- Strategic recommendations
- Executive-friendly language

### **Technical Report**
- Deep technical details
- Vulnerability explanations
- Technical remediation steps
- Code examples

### **Compliance Report**
- Regulatory compliance analysis
- Audit trail documentation
- Policy recommendations
- Risk mitigation strategies

## 🔧 Configuration

### **API Key Setup**
1. **Sidebar Input**: Enter your OpenAI API key in the app
2. **Environment Variable**: Set `OPENAI_API_KEY=your_key_here`
3. **`.env` File**: Create a `.env` file with your API key

### **Nuclei Installation**
For vulnerability scanning, install Nuclei:
- **Windows**: `scoop install nuclei`
- **macOS**: `brew install nuclei`
- **Linux**: Download from project website

## 📁 File Structure
```
cybersec_due_diligence_app.py  # Main application
requirements.txt               # Python dependencies
README.md                      # This file
.env                          # API key configuration (create this)
```

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

This project is open source and available under the MIT License.

---

**💡 Pro Tip**: Use this tool to build a portfolio of security assessments that you can showcase to potential clients or employers. Each report demonstrates your technical skills and ability to communicate complex security findings to different audiences. 