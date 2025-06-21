import streamlit as st
from src.core import AdvancedWebRecon
import json
import time
import os
import plotly.express as px
import plotly.graph_objects as go
from urllib.parse import urlparse

# Set page config with red team theme
st.set_page_config(
    page_title="Red Team Recon",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="💀"
)

# Inject Tailwind CSS and custom styles
st.markdown(
    """
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body {
            background: #1a1a1a;
            color: #e5e7eb;
            font-family: 'Orbitron', sans-serif;
        }
        .main-header {
            color: #ff2d55;
            text-shadow: 0 0 10px #ff2d55;
            font-size: 2.5rem;
        }
        .sidebar .sidebar-content {
            background: #2d2d2d;
            border-right: 2px solid #ff2d55;
        }
        .stButton>button {
            background: linear-gradient(45deg, #ff2d55, #7928ca);
            color: white;
            border: none;
            border-radius: 0.5rem;
            padding: 0.5rem 1rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .stButton>button:hover {
            transform: scale(1.05);
            box-shadow: 0 0 15px #ff2d55;
        }
        .tooltip {
            position: relative;
            display: inline-block;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 200px;
            background-color: #7928ca;
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        .digital-rain {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: url('https://media.giphy.com/media/l0Iyl55kTehV9QH2g/giphy.gif') repeat;
            opacity: 0.1;
            z-index: -1;
        }
        .loader {
            border: 4px solid #ff2d55;
            border-top: 4px solid #7928ca;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
    <div class="digital-rain"></div>
    """,
    unsafe_allow_html=True
)

# Custom SVG icons
skull_icon = """
<svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a2 2 0 11-4 0 2 2 0 014 0z"/>
</svg>
"""
lock_icon = """
<svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0-1.657-1.343-3-3-3s-3 1.343-3 3v3h6v-3zm3 0c0-1.657-1.343-3-3-3s-3 1.343-3 3v3h6v-3zm-3-7a7 7 0 00-7 7v5a2 2 0 002 2h10a2 2 0 002-2v-5a7 7 0 00-7-7z"/>
</svg>
"""
terminal_icon = """
<svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
</svg>
"""

# Main header
st.markdown(f'<h1 class="main-header">{skull_icon} Red Team Recon</h1>', unsafe_allow_html=True)

# Initialize recon tool
if 'recon' not in st.session_state:
    st.session_state.recon = AdvancedWebRecon(max_threads=10, timeout=15, stealth=True)

# Sidebar configuration
with st.sidebar:
    st.markdown(f'<h2 class="text-lg text-red-500 flex items-center">{lock_icon} Configuration</h2>', unsafe_allow_html=True)
    stealth_mode = st.checkbox("Enable Stealth Mode", value=True, help="Minimizes detection by rotating proxies and headers")
    brute_force = st.checkbox("Enable Brute-Force", value=True, help="Performs aggressive subdomain and directory scans")
    max_threads = st.slider("Max Threads", 1, 50, 10, help="Number of concurrent threads for scanning")
    rate_limit = st.slider("Rate Limit (req/s)", 0.1, 5.0, 0.5, help="Requests per second to avoid rate limiting")

    # Custom payloads
    st.markdown(f'<h3 class="text-md text-purple-500 flex items-center">{terminal_icon} Custom Payloads</h3>', unsafe_allow_html=True)
    payload_type = st.selectbox("Payload Type", ["xss", "sqli", "lfi", "dir"], help="Type of vulnerability to test")
    payload_input = st.text_area("Enter Payloads (one per line)", placeholder="e.g., <script>alert(1)</script>", height=100)
    payload_file = st.file_uploader("Upload Payload File", type=["txt"])

    if payload_input or payload_file:
        payloads = []
        if payload_input:
            payloads.extend(payload_input.splitlines())
        if payload_file:
            payloads.extend(payload_file.read().decode('utf-8').splitlines())
        if payloads and st.button("Load Payloads", key="payload_btn"):
            st.session_state.recon.load_custom_payloads(payload_type, payloads)
            st.success(f"Loaded {len(payloads)} payloads for {payload_type}")

    # Wordlist management
    st.markdown(f'<h3 class="text-md text-purple-500 flex items-center">{terminal_icon} Wordlist Management</h3>', unsafe_allow_html=True)
    wordlist_option = st.selectbox("Wordlist Option", ["Default", "Upload", "Generate"], help="Choose how to provide wordlists")
    wordlist_input = st.text_area("Enter Wordlist (one per line)", placeholder="e.g., admin\nlogin", height=100, disabled=wordlist_option != "Upload")
    wordlist_file = st.file_uploader("Upload Wordlist File", type=["txt"], disabled=wordlist_option != "Upload")

    if wordlist_option == "Generate" and st.button("Generate Wordlist", key="generate_wordlist"):
        if url := st.session_state.get('url', ''):
            domain = urlparse(url).netloc
            wordlist = st.session_state.recon.generate_wordlist(domain)
            st.success(f"Generated {len(wordlist)} wordlist entries")
        else:
            st.error("Please enter a target URL")

    if wordlist_option == "Upload" and (wordlist_input or wordlist_file):
        wordlist = []
        if wordlist_input:
            wordlist.extend(wordlist_input.splitlines())
        if wordlist_file:
            wordlist.extend(wordlist_file.read().decode('utf-8').splitlines())
        if wordlist and st.button("Load Wordlist", key="load_wordlist"):
            st.session_state.recon.load_custom_wordlist(wordlist)
            st.success(f"Loaded {len(wordlist)} wordlist entries")

    # Proxy management
    st.markdown(f'<h3 class="text-md text-purple-500 flex items-center">{terminal_icon} Proxy Management</h3>', unsafe_allow_html=True)
    proxy_option = st.selectbox("Proxy Option", ["None", "Free Proxy Pool", "Custom Proxies"], help="Choose proxy settings")
    proxy_input = st.text_area("Enter Proxies (one per line)", placeholder="e.g., 1.2.3.4:8080", height=100, disabled=proxy_option != "Custom Proxies")
    proxy_file = st.file_uploader("Upload Proxy File", type=["txt"], disabled=proxy_option != "Custom Proxies")

    if proxy_option == "Free Proxy Pool" and st.button("Fetch Free Proxies", key="fetch_proxies"):
        st.session_state.recon.fetch_free_proxies()
        st.success("Fetched free proxies")

    if proxy_option == "Custom Proxies" and (proxy_input or proxy_file):
        proxies = []
        if proxy_input:
            proxies.extend(proxy_input.splitlines())
        if proxy_file:
            proxies.extend(proxy_file.read().decode('utf-8').splitlines())
        if proxies and st.button("Load Proxies", key="load_proxies"):
            st.session_state.recon.load_proxies(proxies)
            st.success(f"Loaded {len(proxies)} proxies")

    # Scan history
    st.markdown(f'<h3 class="text-md text-purple-500 flex items-center">{terminal_icon} Scan History</h3>', unsafe_allow_html=True)
    if st.button("View Scan History", key="scan_history"):
        history = st.session_state.recon.get_scan_history()
        if isinstance(history, list):
            st.markdown("### Scan History")
            for scan in history:
                st.markdown(f"- **ID**: {scan['id']} | **URL**: {scan['url']} | **Time**: {scan['timestamp']} | **Status**: {scan['status']}")

# Input section
st.markdown('<div class="tooltip">Enter Target URL<span class="tooltiptext">Provide the website URL to scan (e.g., https://example.com)</span></div>', unsafe_allow_html=True)
url = st.text_input("", placeholder="https://example.com", key="url_input")
st.session_state['url'] = url

# Scan button with animation
if st.button(f"{skull_icon} Start Scan", key="start_scan"):
    if url:
        with st.spinner():
            st.markdown('<div class="loader"></div>', unsafe_allow_html=True)
            start_time = time.time()
            results = st.session_state.recon.get_website_full_scan(
                url, stealth=stealth_mode, brute_force=brute_force
            )
            elapsed_time = time.time() - start_time

        if results.get('status') != 'failed':
            st.markdown(f'<p class="text-green-400">Scan completed in {elapsed_time:.2f} seconds</p>', unsafe_allow_html=True)
            tabs = st.tabs([
                "Summary", "Technologies", "Headers", "DNS", "Subdomains",
                "WHOIS", "Ports", "Vulnerabilities", "WAF", "Robots", "Sitemap", "Exploits", "CSRF", "Report"
            ])

            with tabs[0]:
                st.markdown("### Scan Summary")
                st.markdown(f"**URL**: {results['url']}")
                st.markdown(f"**Timestamp**: {results['timestamp']}")
                st.markdown(f"**Status**: {results['status']}")
                if results['errors']:
                    st.error("Errors: " + "; ".join(results['errors']))

            with tabs[1]:
                st.markdown("### Technologies")
                if isinstance(results.get('technologies'), list):
                    st.write(results['technologies'])
                    # Pie chart for technologies
                    tech_counts = {tech: 1 for tech in results['technologies']}
                    fig = px.pie(
                        names=list(tech_counts.keys()),
                        values=list(tech_counts.values()),
                        title="Technology Distribution",
                        color_discrete_sequence=["#ff2d55", "#7928ca", "#4299e1", "#48bb78"]
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e5e7eb"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.error(results['technologies'].get('error', 'Unknown error'))

            with tabs[2]:
                st.markdown("### Headers")
                if results.get('headers'):
                    st.json(results['headers'])
                else:
                    st.error(results['headers'].get('error', 'Unknown error'))

            with tabs[3]:
                st.markdown("### DNS Records")
                if results.get('dns_records'):
                    st.json(results['dns_records'])
                else:
                    st.error(results['dns_records'].get('error', 'Unknown error'))

            with tabs[4]:
                st.markdown("### Subdomains")
                if isinstance(results.get('subdomains'), list):
                    st.write(results['subdomains'])
                else:
                    st.error(results['subdomains'].get('error', 'Unknown error'))

            with tabs[5]:
                st.markdown("### WHOIS Info")
                if results.get('whois_info'):
                    st.json(results['whois_info'])
                else:
                    st.error(results['whois_info'].get('error', 'Unknown error'))

            with tabs[6]:
                st.markdown("### Open Ports")
                if results.get('open_ports'):
                    st.json(results['open_ports'])
                else:
                    st.error(results['open_ports'].get('error', 'Unknown error'))

            with tabs[7]:
                st.markdown("### Vulnerabilities")
                if isinstance(results.get('vulnerabilities'), list):
                    for vuln in results['vulnerabilities']:
                        st.markdown(f"- {vuln['type']} ({vuln['severity']}): {vuln['details']}")
                    # Bar chart for vulnerability severity
                    severities = [v['severity'] for v in results['vulnerabilities'] if isinstance(v, dict)]
                    severity_counts = {
                        'Critical': severities.count('Critical'),
                        'High': severities.count('High'),
                        'Medium': severities.count('Medium'),
                        'Low': severities.count('Low')
                    }
                    fig = px.bar(
                        x=list(severity_counts.keys()),
                        y=list(severity_counts.values()),
                        title="Vulnerability Severity Distribution",
                        color=list(severity_counts.keys()),
                        color_discrete_map={
                            'Critical': '#ff2d55',
                            'High': '#f56565',
                            'Medium': '#ecc94b',
                            'Low': '#48bb78'
                        }
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e5e7eb",
                        xaxis_title="Severity",
                        yaxis_title="Count"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.error(results['vulnerabilities'].get('error', 'Unknown error'))

            with tabs[8]:
                st.markdown("### WAF Info")
                if results.get('waf_info'):
                    st.json(results['waf_info'])
                else:
                    st.error(results['waf_info'].get('error', 'Unknown error'))

            with tabs[9]:
                st.markdown("### Robots.txt")
                if results.get('robots_txt'):
                    st.json(results['robots_txt'])
                else:
                    st.error(results['robots_txt'].get('error', 'Unknown error'))

            with tabs[10]:
                st.markdown("### Sitemap")
                if results.get('sitemap'):
                    st.json(results['sitemap'])
                else:
                    st.error(results['sitemap'].get('error', 'Unknown error'))

            with tabs[11]:
                st.markdown("### Exploit Suggestions")
                if isinstance(results.get('exploit_suggestions'), list):
                    for sugg in results['exploit_suggestions']:
                        st.markdown(f"- {sugg['target']} ({sugg['priority']}): {sugg['exploit']}")
                else:
                    st.error(results['exploit_suggestions'].get('error', 'Unknown error'))

            with tabs[12]:
                st.markdown("### CSRF Tokens")
                if results.get('url_info') and isinstance(results['url_info'].get('csrf_tokens'), list):
                    for token in results['url_info']['csrf_tokens']:
                        st.markdown(f"- **Token**: {token['token'][:50]}")
                        st.markdown(f"  **Analysis**: {token['analysis']['details']}")
                    # Donut chart for CSRF token status
                    csrf_status = [
                        t['analysis']['is_vulnerable'] for t in results['url_info']['csrf_tokens']
                    ]
                    status_counts = {
                        'Vulnerable': sum(1 for s in csrf_status if s),
                        'Secure': sum(1 for s in csrf_status if not s)
                    }
                    fig = go.Figure(
                        data=[
                            go.Pie(
                                labels=list(status_counts.keys()),
                                values=list(status_counts.values()),
                                hole=0.4,
                                marker_colors=['#ff2d55', '#48bb78']
                            )
                        ]
                    )
                    fig.update_layout(
                        title="CSRF Token Status",
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e5e7eb"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.markdown("No CSRF tokens found")

            with tabs[13]:
                st.markdown("### Report")
                if results.get('report') and os.path.exists(results['report']['report_path']):
                    with open(results['report']['report_path'], 'rb') as f:
                        st.download_button(
                            label="Download PDF Report",
                            data=f.read(),
                            file_name="web_recon_report.pdf",
                            mime="application/pdf",
                            key="download_report"
                        )
                else:
                    st.error(results['report'].get('error', 'Report generation failed'))

            with open('scan_results.json', 'w') as f:
                json.dump(results, f, indent=4)
            st.download_button(
                label="Download JSON Results",
                data=json.dumps(results, indent=4),
                file_name="scan_results.json",
                mime="application/json",
                key="download_json"
            )
        else:
            st.error(f"Scan failed: {results.get('error', 'Unknown error')}")
    else:
        st.error("Please enter a target URL")