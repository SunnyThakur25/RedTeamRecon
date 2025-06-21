RedTeamRecon
A powerful, open-source web reconnaissance tool designed for red team operations and penetration testing. RedTeamRecon combines stealthy scanning, vulnerability detection, and advanced visualizations with a modern GUI and CLI interface. Built with Python, it supports custom wordlists, proxies, payloads, CSRF token analysis, and adaptive rate limiting, making it suitable for both beginners and advanced security professionals.
Repository: github.com/SunnyThakur25/RedTeamReconAuthor: Sunny ThakurLicense: MIT

Table of Contents

Features
Project Structure
Getting Started
Prerequisites
Installation


Usage
GUI Usage
CLI Usage


Customization
For Beginners
For Advanced Users


Contributing
Troubleshooting
License
Acknowledgments


Features

Stealth Mode: Proxy rotation, randomized headers, and adaptive rate limiting to evade detection.
Comprehensive Scanning: URL analysis, DNS records, subdomains, WHOIS, open ports, vulnerabilities, WAF detection, robots.txt, and sitemap parsing.
Vulnerability Detection: XSS, SQL injection, LFI, exposed directories/files, and CSRF token predictability.
Custom Inputs: Support for custom wordlists, proxies, and payloads (XSS, SQLi, LFI, directories).
Modern GUI: Streamlit-based interface with Plotly visualizations, Tailwind CSS, and a red team cyberpunk theme.
CLI Interface: Lightweight terminal-based scanning with JSON output and PDF reports.
Reporting: Generate detailed PDF reports with LaTeX, including vulnerabilities and CSRF analysis.
Extensible: Modular design allows easy addition of new features or payloads.
Lightweight ML: Uses scikit-learn for technology detection without heavy resource demands.


Project Structure
RedTeamRecon/
├── src/
│   └── core.py           # Core scanning logic (AdvancedWebRecon class)
├── gui.py                # Streamlit-based GUI with visualizations
├── cli.py                # Command-line interface for terminal users
├── requirements.txt      # Python dependencies
├── scans.db              # SQLite database for scan history
├── report.tex            # LaTeX template for PDF reports
├── report.pdf            # Generated PDF report
└── scan_results.json     # JSON output of scan results


core.py: Implements the AdvancedWebRecon class, handling all scanning tasks, proxy rotation, CSRF token analysis, and report generation.
gui.py: Provides a web-based interface with a dark, cyberpunk theme, featuring interactive charts for vulnerabilities, technologies, and CSRF tokens.
cli.py: Offers a terminal interface for quick scans, supporting all core.py features.
requirements.txt: Lists dependencies for easy installation.


Getting Started
Prerequisites

Python: Version 3.8 or higher.
Operating System: Linux, macOS, or Windows (Linux recommended for full compatibility).
Tools:
Git for cloning the repository.
LaTeX distribution (e.g., TeX Live) for PDF report generation.


Internet Connection: Required for fetching free proxies and external data.

Installation

Clone the Repository:
git clone https://github.com/SunnyThakur25/RedTeamRecon.git
cd RedTeamRecon


Set Up a Virtual Environment (recommended):
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Python Dependencies:
pip install -r requirements.txt


Install Playwright Browsers (for stealth mode):
playwright install


Install External Tools:

WAFW00F (WAF detection):git clone https://github.com/EnableSecurity/wafw00f.git
cd wafw00f && python setup.py install
cd ..


XSStrike (XSS scanning):git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip install -r requirements.txt
cd ..


sqlmap (SQL injection):pip install sqlmap




Install LaTeX (for PDF reports):

On Ubuntu/Debian:sudo apt-get install texlive-full


On macOS (with Homebrew):brew install texlive


On Windows: Install MiKTeX or TeX Live.




Usage
RedTeamRecon supports two interfaces: a GUI for visual interaction and a CLI for terminal-based operations. Both leverage the same core functionality.
GUI Usage

Start the GUI:
streamlit run gui.py


Opens in your default browser (default: http://localhost:8501).


Configure the Scan:

Target URL: Enter the website to scan (e.g., https://example.com).
Stealth Mode: Enable for proxy rotation and evasion.
Brute-Force: Enable for aggressive subdomain/directory scanning.
Threads & Rate Limit: Adjust for performance and rate limiting.
Wordlist: Choose default, upload a file (e.g., wordlist.txt), or generate a domain-specific wordlist.
Example wordlist.txt:admin
login
api




Proxies: Use free proxies, upload a custom list (e.g., proxies.txt), or disable proxies.
Example proxies.txt:1.2.3.4:8080
5.6.7.8:3128




Payloads: Upload custom payloads for XSS, SQLi, LFI, or directories (e.g., payloads.txt).
Example payloads.txt (for XSS):<script>alert(1)</script>
"><img src=x onerror=alert(1)>






Run the Scan:

Click "Start Scan" to perform a full scan or specific tasks.
View results in tabs (Summary, Technologies, Vulnerabilities, etc.).
Visualize data with charts (e.g., vulnerability severity, CSRF token status).
Download results as JSON (scan_results.json) or PDF (report.pdf).


Example:

Scan https://example.com with stealth mode, custom wordlist, and free proxies.
Review vulnerabilities and CSRF token analysis in the GUI.



CLI Usage

Run a Scan:
python cli.py <url> [options]


Common Commands:

Full scan with PDF report:python cli.py https://example.com --stealth --report


Subdomain scan with custom wordlist:python cli.py https://example.com --wordlist wordlist.txt --task subdomains


Vulnerability scan with free proxies and custom payloads:python cli.py https://example.com --free-proxies --payloads payloads.txt --payload-type xss --task vulns


Generate domain-specific wordlist:python cli.py https://example.com --generate-wordlist --task subdomains




Options:

--stealth: Enable stealth mode.
--no-brute: Disable brute-force.
--threads <n>: Set max threads (1-50).
--rate-limit <n>: Set requests per second (0.1-5.0).
--wordlist <file>: Custom wordlist file.
--generate-wordlist: Generate wordlist.
--proxies <file>: Custom proxy list file.
--free-proxies: Use free proxy pool.
--payloads <file>: Custom payloads file.
--payload-type <type>: Payload type (xss, sqli, lfi, dir).
--task <task>: Specific task (full, url, dns, subdomains, whois, ports, vulns, waf, robots, sitemap).
--output <file>: Output JSON file.
--report: Generate PDF report (full scan only).


Output:

Results printed to terminal in JSON format.
Saved to --output file (default: scan_results.json).
PDF report generated if --report is used (saved as report.pdf).


Example:
python cli.py https://example.com --stealth --threads 20 --rate-limit 1.0 --task full --report


Outputs results to scan_results.json and generates report.pdf.




Customization
RedTeamRecon is designed to be extensible. Below are modification tips for beginners and advanced users.
For Beginners

Add New Payloads:

Edit payloads.txt and upload via GUI or CLI (--payloads).
Example: Add new XSS payload:<script>prompt(1)</script>


In core.py, payloads are loaded in _load_default_payloads or via load_custom_payloads.


Modify Wordlists:

Create a new wordlist.txt with custom entries (e.g., dashboard, panel).
Use GUI to upload or CLI with --wordlist.
Default wordlist is in core.py (_get_default_wordlist).


Change GUI Theme:

In gui.py, modify Tailwind CSS colors in the <style> block.
Example: Change red (#ff2d55) to blue (#4299e1):.main-header { color: #4299e1; text-shadow: 0 0 10px #4299e1; }




Add new SVG icons in gui.py for buttons or headers.


Adjust Scan Settings:

In GUI, tweak threads and rate limit sliders.
In CLI, use --threads and --rate-limit.
In core.py, default values are set in AdvancedWebRecon.__init__.



For Advanced Users

Extend Scanning Features:

Add new methods to core.py (e.g., for SSRF testing):def test_ssrf(self, url):
    payloads = ['http://169.254.169.254/latest/meta-data/', 'http://localhost']
    results = []
    for payload in payloads:
        test_url = f"{url}?url={payload}"
        response = self.session.get(test_url, timeout=self.timeout, verify=False)
        if "instance-id" in response.text:
            results.append({"type": "SSRF", "details": f"Vulnerable to {payload}"})
    return results


Integrate into get_website_vulnerabilities and GUI/CLI.


Enhance Visualizations:

In gui.py, add new Plotly charts (e.g., subdomain network graph):import plotly.graph_objects as go
def plot_subdomain_network(subdomains):
    edges = [(s, urlparse(args.url).netloc) for s in subdomains]
    fig = go.Figure(data=[go.Scatter(x=[0], y=[0], mode='markers+text', text=[urlparse(args.url).netloc])])
    st.plotly_chart(fig)


Call in the "Subdomains" tab.


Add WAF Evasion:

In core.py, modify _obfuscate_payload to include HTTP parameter pollution:def _obfuscate_payload(self, payload):
    transformations = [
        lambda x: f"{x}&test={x}",
        lambda x: x.replace('<', '%3C').replace('>', '%3E'),
        lambda x: x.replace('script', 'scr%69pt')
    ]
    return random.choice(transformations)(payload)




Database Enhancements:

In core.py, add new tables to scans.db for payload or proxy history:def _init_db(self):
    with sqlite3.connect(self.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                payload TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()




Automate Scans:

Create a script to schedule scans using cli.py:import schedule
import subprocess
def run_scan():
    subprocess.run(["python", "cli.py", "https://example.com", "--report"])
schedule.every().day.at("02:00").do(run_scan)
while True:
    schedule.run_pending()
    time.sleep(60)




Add New Dependencies:

Update requirements.txt for new libraries (e.g., tqdm for progress bars):tqdm>=4.66.5


Install: pip install -r requirements.txt.




Contributing
Contributions are welcome! Follow these steps to contribute to RedTeamRecon:

Fork the Repository:
git clone https://github.com/SunnyThakur25/RedTeamRecon.git
cd RedTeamRecon
git checkout -b feature/your-feature


Make Changes:

Modify core.py, gui.py, cli.py, or add new files.
Update requirements.txt if new dependencies are added.
Test changes thoroughly.


Commit and Push:
git add .
git commit -m "Add your-feature description"
git push origin feature/your-feature


Create a Pull Request:

Go to github.com/SunnyThakur25/RedTeamRecon.
Submit a pull request with a clear description of changes.


Code Guidelines:

Follow PEP 8 for Python code.
Add comments for complex logic.
Ensure compatibility with Python 3.8+.
Test on Linux for full functionality.


Issues:

Report bugs or suggest features via GitHub Issues.




Troubleshooting

GUI Not Loading:

Ensure Streamlit is installed: pip install streamlit.
Check port 8501 is free: lsof -i :8501 (Linux) or equivalent.
Run: streamlit run gui.py --server.port 8502.


Playwright Errors:

Reinstall browsers: playwright install.
Ensure dependencies: sudo apt-get install libnss3 libatk-bridge2.0-0 (Ubuntu).


LaTeX Report Fails:

Verify TeX Live installation: pdflatex --version.
Install missing packages: tlmgr install noto.


Proxy Issues:

Free proxies may be unreliable. Use premium proxies in proxies.txt.
Check proxy format: ip:port.


Scan Errors:

Increase --rate-limit or reduce --threads.
Enable --stealth for WAF evasion.
Check logs in terminal or GUI for details.


Dependencies Conflict:

Use a virtual environment: python -m venv venv.
Reinstall: pip install -r requirements.txt.



For further assistance, open an issue on GitHub.

License
This project is licensed under the MIT License. See LICENSE for details.

Acknowledgments


Libraries: Built with Streamlit, Plotly, BeautifulSoup, and more.
Community: Inspired by the cybersecurity and red team community.


Happy Hacking!Follow @SunnyThakur25 for updates and new projects.
