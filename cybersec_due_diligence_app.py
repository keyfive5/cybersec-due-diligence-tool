import streamlit as st
import nmap
import subprocess
import openai
import os
import json
import datetime
from dotenv import load_dotenv

# Set page config - must be first Streamlit command
st.set_page_config(page_title="CyberScanner Pro", page_icon="🔒", layout="wide")

# Try multiple ways to get the API key
api_key = None

# Method 1: Check environment variable
api_key = os.getenv('OPENAI_API_KEY')

# Method 2: Try to load .env file safely
if not api_key:
    try:
        load_dotenv()
        api_key = os.getenv('OPENAI_API_KEY')
    except Exception:
        # If .env loading fails, try manual file reading
        try:
            with open('.env', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('OPENAI_API_KEY='):
                        api_key = line.split('=', 1)[1].strip()
                        break
        except (FileNotFoundError, UnicodeDecodeError):
            pass

# Method 3: Allow manual input in Streamlit
if not api_key:
    st.sidebar.header("OpenAI API Configuration")
    api_key = st.sidebar.text_input(
        "Enter your OpenAI API Key", 
        type="password",
        help="You can also set the OPENAI_API_KEY environment variable or create a .env file"
    )
    
    if not api_key:
        st.error("OpenAI API key is required. Please enter your API key in the sidebar or set the OPENAI_API_KEY environment variable.")
        st.info("""
        **How to set up your API key:**
        
        1. **Sidebar input (temporary):** Enter your key in the sidebar above
        2. **Environment variable:** Set `OPENAI_API_KEY=your_key_here` in your system
        3. **Create a .env file:** Add `OPENAI_API_KEY=your_key_here` to a .env file in this directory
        
        Get your API key from: https://platform.openai.com/api-keys
        """)
        st.stop()

openai.api_key = api_key

def run_nmap_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sV -O')
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service = nm[host][proto][port].get('name', '')
                    version = nm[host][proto][port].get('version', '')
                    results.append(f"Port {port}/{proto}: {service} {version}")
        return '\n'.join(results) if results else 'No open ports found.'
    except Exception as e:
        return f"Nmap scan error: {e}"

def run_nuclei_scan(target):
    try:
        # Check if nuclei is installed
        result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Nuclei not installed. Install from: https://nuclei.projectdiscovery.io/nuclei/get-started/"
        
        # Run nuclei scan with better error handling
        result = subprocess.run([
            'nuclei', '-u', target, '-silent', '-json', '-timeout', '30'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            return f"Nuclei scan failed: {result.stderr.strip()}"
        
        output = result.stdout.strip()
        if not output:
            return 'No vulnerabilities found.'
        
        # Parse JSON output for better formatting
        try:
            vulns = []
            for line in output.split('\n'):
                if line.strip():
                    vuln_data = json.loads(line)
                    vulns.append(f"• {vuln_data.get('info', {}).get('name', 'Unknown')}: {vuln_data.get('info', {}).get('description', 'No description')}")
            return '\n'.join(vulns) if vulns else 'No vulnerabilities found.'
        except json.JSONDecodeError:
            return output
    except subprocess.TimeoutExpired:
        return "Nuclei scan timed out after 60 seconds."
    except FileNotFoundError:
        return "Nuclei not found. Install from: https://nuclei.projectdiscovery.io/nuclei/get-started/"
    except Exception as e:
        return f"Nuclei scan error: {e}"

def generate_professional_report(domain, nmap_results, nuclei_results, client_name="", report_type="comprehensive"):
    prompt = f"""
You are a senior cybersecurity consultant creating a professional report for {client_name if client_name else 'a client'}.

**Target:** {domain}
**Report Type:** {report_type}

**Scan Results:**
Nmap Results:
{nmap_results}

Nuclei Results:
{nuclei_results}

Create a professional cybersecurity assessment report with the following structure:

1. **Executive Summary** (2-3 sentences)
2. **Risk Assessment** (High/Medium/Low with justification)
3. **Key Findings** (bullet points of main issues)
4. **Technical Details** (detailed analysis of vulnerabilities)
5. **Remediation Recommendations** (actionable steps with priority levels)
6. **Compliance Impact** (if any regulations are affected)
7. **Estimated Remediation Cost** (Low/Medium/High effort)

Make it professional, actionable, and suitable for executive presentation. Include specific technical details and business impact.
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        return f"OpenAI API error: {e}"

def generate_ai_summary(domain, nmap_results, nuclei_results):
    prompt = f"""
You are a cybersecurity analyst. I scanned {domain} and found the following:
Nmap Results:
{nmap_results}
Nuclei Results:
{nuclei_results}
Provide a brief due diligence report summarizing these findings, the risks they pose, and remediation recommendations. Assign a risk level (High/Medium/Low) and explain your reasoning.
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        return f"OpenAI API error: {e}"

def main():
    # Sidebar for configuration
    st.sidebar.title("🔒 CyberScanner Pro")
    st.sidebar.markdown("---")
    
    # Report configuration
    st.sidebar.subheader("📋 Report Settings")
    client_name = st.sidebar.text_input("Client Name (Optional)", placeholder="Enter client name for report")
    report_type = st.sidebar.selectbox(
        "Report Type",
        ["comprehensive", "executive", "technical", "compliance"],
        help="Choose the type of report to generate"
    )
    
    # Pricing calculator
    st.sidebar.markdown("---")
    st.sidebar.subheader("💰 Pricing Calculator")
    st.sidebar.markdown("""
    **Suggested Pricing:**
    - Basic Scan: $50-100
    - Comprehensive Report: $200-500
    - Executive Summary: $150-300
    - Compliance Report: $300-800
    """)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.title("🔒 CyberScanner Pro")
        st.markdown("**Professional Cybersecurity Assessment & Report Generator**")
        st.markdown("*Generate professional reports for clients, job applications, and consulting work*")
    
    with col2:
        st.markdown("### 💼 **Monetization Tips**")
        st.markdown("""
        - **Freelance:** Offer security assessments on Upwork/Fiverr
        - **Consulting:** Use reports for client presentations
        - **Job Applications:** Include sample reports in portfolio
        - **Certifications:** Build case studies for CISSP, CEH, etc.
        """)
    
    st.markdown("---")
    
    # Preset domain buttons with better styling
    st.subheader("🎯 Quick Scan Targets")
    preset_domains = [
        ("scanme.nmap.org", "Official Nmap test server"),
        ("example.com", "Standard test domain"),
        ("testphp.vulnweb.com", "Vulnerable test site"),
        ("httpbin.org", "HTTP testing service"),
        ("demo.testfire.net", "Demo banking site"),
        ("localhost", "Your local machine")
    ]
    
    cols = st.columns(len(preset_domains))
    for i, (domain_val, domain_desc) in enumerate(preset_domains):
        if cols[i].button(f"🎯 {domain_val}", help=domain_desc, key=f"btn_{i}"):
            st.session_state['domain'] = domain_val
    
    # Domain input
    if 'domain' not in st.session_state:
        st.session_state['domain'] = "example.com"
    
    domain = st.text_input("🎯 Target Domain or IP", st.session_state['domain'], key="domain_input")
    
    # Scan options
    col1, col2 = st.columns(2)
    with col1:
        run_scan = st.button("🔍 Run Security Scan", type="primary")
    with col2:
        generate_report = st.button("📋 Generate Professional Report", type="secondary")
    
    if run_scan or generate_report:
        if not domain:
            st.error("Please enter a target domain or IP")
            return
            
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Run scans
        status_text.text("Running Nmap scan...")
        progress_bar.progress(25)
        nmap_results = run_nmap_scan(domain)
        
        status_text.text("Running Nuclei vulnerability scan...")
        progress_bar.progress(50)
        nuclei_results = run_nuclei_scan(domain)
        
        # Display results
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🔍 Nmap Results")
            st.code(nmap_results)
        
        with col2:
            st.subheader("🛡️ Vulnerability Scan Results")
            st.code(nuclei_results)
        
        # Generate report based on button clicked
        if generate_report:
            status_text.text("Generating professional report...")
            progress_bar.progress(75)
            
            professional_report = generate_professional_report(
                domain, nmap_results, nuclei_results, client_name, report_type
            )
            
            progress_bar.progress(100)
            status_text.text("Complete!")
            
            st.markdown("---")
            st.subheader("📋 Professional Cybersecurity Report")
            
            # Report metadata
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Target", domain)
            with col2:
                st.metric("Report Type", report_type.title())
            with col3:
                st.metric("Date", datetime.datetime.now().strftime("%Y-%m-%d"))
            
            st.markdown(professional_report)
            
            # Download options
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📄 Download Report (TXT)",
                    data=f"CYBERSECURITY ASSESSMENT REPORT\n{'='*50}\n\nTarget: {domain}\nClient: {client_name}\nDate: {datetime.datetime.now().strftime('%Y-%m-%d')}\nReport Type: {report_type}\n\n{professional_report}",
                    file_name=f"{domain}_{report_type}_security_report.txt",
                    mime="text/plain"
                )
            with col2:
                st.download_button(
                    label="📊 Download Raw Data (JSON)",
                    data=json.dumps({
                        "target": domain,
                        "client": client_name,
                        "date": datetime.datetime.now().isoformat(),
                        "report_type": report_type,
                        "nmap_results": nmap_results,
                        "nuclei_results": nuclei_results,
                        "professional_report": professional_report
                    }, indent=2),
                    file_name=f"{domain}_security_data.json",
                    mime="application/json"
                )
        else:
            # Quick summary
            status_text.text("Generating AI summary...")
            progress_bar.progress(75)
            
            ai_summary = generate_ai_summary(domain, nmap_results, nuclei_results)
            
            progress_bar.progress(100)
            status_text.text("Complete!")
            
            st.markdown("---")
            st.subheader("🤖 AI-Generated Summary")
            st.markdown(ai_summary)
            
            # Quick download
            st.download_button(
                label="📄 Download Summary",
                data=f"Target: {domain}\nDate: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n{ai_summary}",
                file_name=f"{domain}_summary.txt",
                mime="text/plain"
            )

if __name__ == "__main__":
    main() 