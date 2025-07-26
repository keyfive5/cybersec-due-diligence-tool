import streamlit as st
import nmap
import subprocess
import openai
import os
from dotenv import load_dotenv

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
        # Assumes nuclei is installed and in PATH
        result = subprocess.run([
            'nuclei', '-u', target, '-silent', '-json'
        ], capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return f"Nuclei error: {result.stderr.strip()}"
        return result.stdout.strip() or 'No vulnerabilities found.'
    except Exception as e:
        return f"Nuclei scan error: {e}"

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
    st.title("AI-Powered Cybersecurity Due Diligence Tool")
    st.write("Enter a domain or IP to scan for open ports, vulnerabilities, and get an AI-generated risk summary.")

    # Preset domain buttons
    preset_domains = [
        ("scanme.nmap.org", "Official Nmap test server. Designed for scanning!"),
        ("example.com", "Standard test domain, but may have few/no open ports."),
        ("testphp.vulnweb.com", "Intentionally vulnerable web app for security testing."),
        ("httpbin.org", "Public HTTP request/response service."),
        ("demo.testfire.net", "Demo banking site for security testing."),
        ("localhost", "Your own machine.")
    ]
    if 'domain' not in st.session_state:
        st.session_state['domain'] = "example.com"

    cols = st.columns(len(preset_domains))
    for i, (domain_val, domain_desc) in enumerate(preset_domains):
        if cols[i].button(domain_val, help=domain_desc):
            st.session_state['domain'] = domain_val

    domain = st.text_input("Target Domain or IP", st.session_state['domain'], key="domain_input")
    if st.button("Scan"):
        with st.spinner('Running Nmap scan...'):
            nmap_results = run_nmap_scan(domain)
        st.subheader("Nmap Results")
        st.code(nmap_results)

        with st.spinner('Running Nuclei scan...'):
            nuclei_results = run_nuclei_scan(domain)
        st.subheader("Nuclei Results")
        st.code(nuclei_results)

        with st.spinner('Generating AI summary...'):
            ai_summary = generate_ai_summary(domain, nmap_results, nuclei_results)
        st.subheader("AI-Generated Due Diligence Report")
        st.write(ai_summary)

        st.download_button(
            label="Download Report",
            data=f"Nmap Results:\n{nmap_results}\n\nNuclei Results:\n{nuclei_results}\n\nAI Summary:\n{ai_summary}",
            file_name=f"{domain}_cybersec_report.txt"
        )

if __name__ == "__main__":
    main() 