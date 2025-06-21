import argparse
import json
import sys
import os
from src.core import AdvancedWebRecon
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def print_banner():
    """Display RedTeamRecon CLI banner"""
    banner = """
    ╔══════════════════════════════════════╗
    ║       RedTeamRecon CLI v1.0          ║
    ║   Advanced Web Reconnaissance Tool   ║
    ╚══════════════════════════════════════╝
    """
    print(f"\033[91m{banner}\033[0m")

def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description="RedTeamRecon CLI: Advanced Web Reconnaissance Tool")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (proxy rotation, randomized headers)")
    parser.add_argument("--no-brute", action="store_true", help="Disable brute-force for subdomains/directories")
    parser.add_argument("--threads", type=int, default=10, help="Max threads for scanning (1-50)")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Requests per second (0.1-5.0)")
    parser.add_argument("--wordlist", type=str, help="Path to custom wordlist file")
    parser.add_argument("--generate-wordlist", action="store_true", help="Generate wordlist based on domain")
    parser.add_argument("--proxies", type=str, help="Path to custom proxy list file")
    parser.add_argument("--free-proxies", action="store_true", help="Use free proxy pool")
    parser.add_argument("--payloads", type=str, help="Path to custom payloads file")
    parser.add_argument("--payload-type", choices=["xss", "sqli", "lfi", "dir"], default="xss", help="Payload type")
    parser.add_argument("--task", choices=["full", "url", "dns", "subdomains", "whois", "ports", "vulns", "waf", "robots", "sitemap"], default="full", help="Specific task to run")
    parser.add_argument("--output", type=str, default="scan_results.json", help="Output file for results (JSON)")
    parser.add_argument("--report", action="store_true", help="Generate PDF report")
    return parser.parse_args()

def load_file_lines(file_path):
    """Load lines from a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error loading file {file_path}: {str(e)}")
        return []

def main():
    """Main CLI function"""
    print_banner()
    args = parse_args()

    try:
        # Initialize recon tool
        recon = AdvancedWebRecon(
            max_threads=max(1, min(args.threads, 50)),
            timeout=15,
            stealth=args.stealth,
            rate_limit=max(0.1, min(args.rate_limit, 5.0))
        )

        # Load custom wordlist
        if args.wordlist:
            wordlist = load_file_lines(args.wordlist)
            if wordlist:
                recon.load_custom_wordlist(wordlist)
                logger.info(f"Loaded {len(wordlist)} wordlist entries")
            else:
                logger.warning("No valid wordlist entries loaded, using default")

        # Generate wordlist
        if args.generate_wordlist:
            domain = urlparse(args.url).netloc
            wordlist = recon.generate_wordlist(domain)
            logger.info(f"Generated {len(wordlist)} wordlist entries")

        # Load proxies
        if args.free_proxies:
            recon.fetch_free_proxies()
        elif args.proxies:
            proxies = load_file_lines(args.proxies)
            if proxies:
                recon.load_proxies(proxies)
                logger.info(f"Loaded {len(proxies)} proxies")
            else:
                logger.warning("No valid proxies loaded")

        # Load custom payloads
        if args.payloads:
            payloads = load_file_lines(args.payloads)
            if payloads:
                recon.load_custom_payloads(args.payload_type, payloads)
                logger.info(f"Loaded {len(payloads)} payloads for {args.payload_type}")
            else:
                logger.warning("No valid payloads loaded")

        # Execute task
        results = {}
        if args.task == "full":
            results = recon.get_website_full_scan(args.url, stealth=args.stealth, brute_force=not args.no_brute)
        elif args.task == "url":
            results = recon.get_url_info(args.url, stealth=args.stealth)
        elif args.task == "dns":
            results = recon.get_dns_records(urlparse(args.url).netloc)
        elif args.task == "subdomains":
            results = recon.get_subdomains(urlparse(args.url).netloc, brute_force=not args.no_brute)
        elif args.task == "whois":
            results = recon.get_whois_info(urlparse(args.url).netloc)
        elif args.task == "ports":
            results = recon.scan_open_ports(urlparse(args.url).netloc)
        elif args.task == "vulns":
            results = recon.get_website_vulnerabilities(args.url)
        elif args.task == "waf":
            results = recon.get_website_waf_info(args.url)
        elif args.task == "robots":
            results = recon.get_robots_txt(args.url)
        elif args.task == "sitemap":
            results = recon.get_sitemap(args.url)

        # Display results
        if isinstance(results, dict) and 'error' in results:
            logger.error(f"Task failed: {results['error']}")
            sys.exit(1)

        print(f"\033[92m[+] Results for {args.task} task:\033[0m")
        print(json.dumps(results, indent=2))

        # Save results to file
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {args.output}")

        # Generate PDF report if requested
        if args.report and args.task == "full":
            report_result = recon.generate_report(results)
            if 'report_path' in report_result:
                logger.info(f"PDF report generated: {report_result['report_path']}")
            else:
                logger.error(f"Report generation failed: {report_result.get('error', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()