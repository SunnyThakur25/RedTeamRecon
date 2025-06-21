import requests
from bs4 import BeautifulSoup, Comment
import tldextract
from urllib.parse import urlparse, urljoin
from urllib3.exceptions import InsecureRequestWarning
import re
import socket
import dns.resolver
import ssl
import json
import time
import random
from fake_useragent import UserAgent
import whois
import xml.etree.ElementTree as ET
from datetime import datetime
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import http.client
from playwright.sync_api import sync_playwright
import nltk
from nltk.tokenize import word_tokenize
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from collections import deque
import subprocess
import os
import sqlite3
from wafw00f import WAFW00F
from xsstrike import XSStrike
import latexmk

# Download NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class AdvancedWebRecon:
    def __init__(self, max_threads=10, timeout=15, user_agent=None, stealth=True, proxies=None, rate_limit=0.5, db_path="scans.db"):
        self.max_threads = max(1, min(max_threads, 50))
        self.timeout = max(5, min(timeout, 60))
        self.stealth = stealth
        self.proxies = proxies or {}
        self.ua = UserAgent() if user_agent is None else user_agent
        self.session = self._create_session()
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        self._error_list = []
        self._lock = threading.Lock()
        self.rate_limit = max(0.1, rate_limit)
        self._last_request = time.time()
        self._backoff = 0  # For adaptive rate limiting
        self._payloads = self._load_default_payloads()
        self._custom_payloads = {}
        self._technology_signatures = self._load_technology_signatures()
        self.db_path = db_path
        self._init_db()
        self._wordlist = self._get_default_wordlist()
        self._proxy_pool = []

    def _init_db(self):
        """Initialize SQLite database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT,
                        timestamp TEXT,
                        results TEXT,
                        status TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")

    def _create_session(self):
        """Create a configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'en-GB,en;q=0.5', 'fr-FR,fr;q=0.5']),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        if self.proxies:
            session.proxies.update(self.proxies)
        return session

    def load_custom_wordlist(self, wordlist):
        """Load custom wordlist for brute-forcing"""
        try:
            if not isinstance(wordlist, list):
                raise ValueError("Wordlist must be a list")
            self._wordlist = [str(w).strip() for w in wordlist if str(w).strip()]
            logger.info(f"Loaded {len(self._wordlist)} custom wordlist entries")
        except Exception as e:
            logger.error(f"Error loading custom wordlist: {str(e)}")

    def generate_wordlist(self, domain):
        """Generate wordlist based on domain"""
        try:
            base = domain.split('.')[0]
            words = [base, 'admin', 'login', 'api', 'secure', 'dev', 'test', 'staging']
            generated = words + [f"{w}{i}" for w in words for i in range(1, 10)]
            generated += [f"{base}-{w}" for w in ['panel', 'server', 'backup']]
            self._wordlist = list(set(self._wordlist + generated))
            logger.info(f"Generated {len(generated)} wordlist entries for {domain}")
            return self._wordlist
        except Exception as e:
            logger.error(f"Error generating wordlist: {str(e)}")
            return self._wordlist

    def load_proxies(self, proxies):
        """Load user-defined proxy list"""
        try:
            if not isinstance(proxies, list):
                raise ValueError("Proxies must be a list")
            self._proxy_pool = [str(p).strip() for p in proxies if str(p).strip()]
            logger.info(f"Loaded {len(self._proxy_pool)} custom proxies")
        except Exception as e:
            logger.error(f"Error loading proxies: {str(e)}")

    def fetch_free_proxies(self):
        """Fetch free proxies from ProxyScrape"""
        try:
            self._rate_limit_request()
            response = requests.get('https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all', timeout=self.timeout)
            proxies = response.text.splitlines()
            self._proxy_pool.extend([p for p in proxies if p.strip()])
            logger.info(f"Fetched {len(proxies)} free proxies")
        except Exception as e:
            logger.error(f"Error fetching free proxies: {str(e)}")

    def rotate_proxies(self):
        """Rotate proxies for requests"""
        try:
            if not self._proxy_pool:
                self.fetch_free_proxies()
            if self._proxy_pool:
                proxy = random.choice(self._proxy_pool)
                self.proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
                self.session.proxies.update(self.proxies)
                logger.info(f"Rotated to proxy: {proxy}")
        except Exception as e:
            logger.error(f"Error rotating proxies: {str(e)}")

    def _load_default_payloads(self):
        """Load default payloads"""
        return {
            'xss': [
                '<script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                'javascript:alert(1)'
            ],
            'sqli': [
                "' OR 1=1 --",
                "1' UNION SELECT 1,@@version --",
                "' OR 'a'='a"
            ],
            'lfi': [
                '/etc/passwd',
                '../../../../../../etc/passwd',
                '/proc/self/environ'
            ],
            'dir': [
                'admin/', 'login/', 'api/', 'config/', 'backup/'
            ]
        }

    def _load_technology_signatures(self):
        """Load technology signatures"""
        return {
            'WordPress': {'patterns': ['wp-content', 'wp-includes', 'wp-json'], 'weight': 0.8},
            'Drupal': {'patterns': ['sites/default', 'Drupal.settings'], 'weight': 0.7},
            'Joomla': {'patterns': ['/media/jui/', 'Joomla!'], 'weight': 0.7},
            'React': {'patterns': ['react-', 'data-react'], 'weight': 0.6},
            'Vue.js': {'patterns': ['vue', 'v-bind'], 'weight': 0.6},
            'Angular': {'patterns': ['ng-app', 'ng-bind'], 'weight': 0.6},
            'Cloudflare': {'patterns': ['cf-ray', '__cfduid'], 'weight': 0.9},
            'AWS': {'patterns': ['aws', 'amazonaws.com'], 'weight': 0.9}
        }

    def load_custom_payloads(self, payload_type, payloads):
        """Load custom payloads"""
        try:
            if not isinstance(payloads, list):
                raise ValueError("Payloads must be a list")
            self._custom_payloads[payload_type] = [str(p).strip() for p in payloads if str(p).strip()]
            logger.info(f"Loaded {len(self._custom_payloads[payload_type])} custom payloads for {payload_type}")
        except Exception as e:
            logger.error(f"Error loading custom payloads: {str(e)}")

    def _rate_limit_request(self):
        """Enforce adaptive rate limiting"""
        try:
            if hasattr(self, '_backoff') and self._backoff > 0:
                time.sleep(self._backoff)
            elapsed = time.time() - self._last_request
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_request = time.time()
            self._backoff = max(0, self._backoff * 0.9)  # Reduce backoff over time
        except Exception as e:
            logger.error(f"Error in rate limiting: {str(e)}")

    def _validate_url(self, url):
        """Validate and normalize URL"""
        if not url:
            raise ValueError("URL cannot be empty")
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        return url

    def _validate_domain(self, domain):
        """Validate and normalize domain"""
        if not domain:
            raise ValueError("Domain cannot be empty")
        domain = domain.strip().lower()
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise ValueError("Invalid domain format")
        return domain

    def _obfuscate_payload(self, payload):
        """Obfuscate payload"""
        transformations = [
            lambda x: x.replace('<', '%3C').replace('>', '%3E'),
            lambda x: x.replace('script', 'scr%69pt'),
            lambda x: ''.join(c + random.choice(['', ' ']) for c in x),
            lambda x: x.replace('=', '%3D').replace('"', '%22')
        ]
        return random.choice(transformations)(payload)

    def _test_csrf_token(self, token):
        """Test CSRF token predictability"""
        try:
            if not token:
                return {'is_vulnerable': True, 'details': 'No CSRF token found'}
            if len(token) < 16:
                return {'is_vulnerable': True, 'details': 'CSRF token too short'}
            if re.match(r'^\d+$', token) or re.match(r'^[a-f0-9]+$', token):
                return {'is_vulnerable': True, 'details': 'CSRF token predictable (numeric or hex)'}
            entropy = len(set(token)) / len(token)
            if entropy < 0.5:
                return {'is_vulnerable': True, 'details': 'CSRF token low entropy'}
            return {'is_vulnerable': False, 'details': 'CSRF token appears secure'}
        except Exception as e:
            logger.warning(f"Error in _test_csrf_token: {str(e)}")
            return {'is_vulnerable': False, 'details': f'Error analyzing token: {str(e)}'}

    def get_url_info(self, url, stealth=True):
        """Enhanced URL information gathering"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            if self.stealth:
                self.rotate_proxies()
            headers = {
                'User-Agent': self.ua.random,
                'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
            } if stealth or self.stealth else {}

            if self.stealth:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.set_extra_http_headers(headers)
                    response = page.goto(url, timeout=self.timeout * 1000)
                    content = page.content()
                    status_code = response.status if response else 200
                    headers_dict = dict(response.all_headers()) if response else {}
                    browser.close()
            else:
                response = self.session.get(url, verify=False, timeout=self.timeout, headers=headers, allow_redirects=True)
                if response.status_code == 429:
                    self._backoff = min(self._backoff + 1, 10)  # Increase backoff
                    logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                    return {'url': url, 'error': 'Rate limit detected'}
                content = response.text
                status_code = response.status_code
                headers_dict = dict(response.headers)

            info = {
                'url': url,
                'final_url': response.url if not self.stealth else url,
                'status_code': status_code,
                'headers': headers_dict,
                'content_type': headers_dict.get('Content-Type', ''),
                'server': headers_dict.get('Server', ''),
                'x_powered_by': headers_dict.get('X-Powered-By', ''),
                'content_length': headers_dict.get('Content-Length', 0),
                'response_time': response.timing.get('duration', 0) / 1000 if self.stealth else response.elapsed.total_seconds(),
                'redirect_chain': [r.url for r in response.history] if not self.stealth else [],
                'technologies': self._detect_technologies(content, headers_dict),
                'security_headers': self._check_security_headers(headers_dict),
                'tls_info': self._get_tls_info(url) if url.startswith('https://') else None,
                'api_endpoints': self._discover_api_endpoints(content, url),
                'cors_info': self._check_cors(url)
            }

            if 'html' in headers_dict.get('Content-Type', '').lower():
                info.update(self._analyze_html_content(content))

            return info

        except Exception as e:
            logger.error(f"Error in get_url_info: {str(e)}")
            return {'url': url, 'error': str(e)}

    def _detect_technologies(self, content, headers):
        """Enhanced technology detection"""
        try:
            tokens = word_tokenize(content.lower())
            tech_scores = {}
            for tech, sig in self._technology_signatures.items():
                score = sum(content.lower().count(p.lower()) for p in sig['patterns']) * sig['weight']
                for header in headers.values():
                    if tech.lower() in header.lower():
                        score += 2 * sig['weight']
                tech_scores[tech] = score

            vectorizer = TfidfVectorizer(vocabulary=[p for sig in self._technology_signatures.values() for p in sig['patterns']])
            tfidf_matrix = vectorizer.fit_transform([content])
            for idx, feature in enumerate(vectorizer.get_feature_names_out()):
                for tech, sig in self._technology_signatures.items():
                    if feature in sig['patterns']:
                        tech_scores[tech] += tfidf_matrix[0, idx] * sig['weight']

            return [tech for tech, score in tech_scores.items() if score > 0.5]
        except Exception as e:
            logger.warning(f"Error in _detect_technologies: {str(e)}")
            return []

    def _check_security_headers(self, headers):
        """Analyze security headers"""
        security = {}
        important_headers = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy'
        ]
        for header in important_headers:
            value = headers.get(header, 'MISSING')
            security[header] = {
                'value': value,
                'status': 'secure' if value != 'MISSING' else 'missing',
                'recommendation': f"Implement {header}" if value == 'MISSING' else None
            }
        return security

    def _get_tls_info(self, url):
        """Get TLS certificate information"""
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    return {
                        'issuer': issuer,
                        'subject': subject,
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_name': cert.get('subjectAltName', []),
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'cipher': ssock.cipher(),
                        'is_expired': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') < datetime.utcnow()
                    }
        except Exception as e:
            logger.error(f"Error in _get_tls_info: {str(e)}")
            return {'error': str(e)}

    def _analyze_html_content(self, html):
        """Analyze HTML with CSRF token testing"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = {
                'title': soup.title.string.strip() if soup.title else None,
                'meta': {},
                'forms': [],
                'comments': [],
                'scripts': [],
                'links': [],
                'emails': set(),
                'phone_numbers': set(),
                'hidden_elements': [],
                'csrf_tokens': []
            }

            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                if name:
                    results['meta'][name.lower()] = meta.get('content', '')

            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for input_tag in form.find_all('input'):
                    if input_tag.get('name', '').lower() in ['csrf_token', '_csrf', 'xsrf_token']:
                        token = input_tag.get('value', '')
                        if token:
                            results['csrf_tokens'].append({
                                'token': token,
                                'analysis': self._test_csrf_token(token)
                            })
                    form_info['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                results['forms'].append(form_info)

            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                results['comments'].append(comment.strip())

            for script in soup.find_all('script'):
                if script.get('src'):
                    results['scripts'].append(script.get('src'))

            for link in soup.find_all('a'):
                if link.get('href'):
                    results['links'].append(link.get('href'))

            for hidden in soup.find_all(['input', 'div', 'span'], {'type': 'hidden'}):
                results['hidden_elements'].append({
                    'tag': hidden.name,
                    'attributes': hidden.attrs
                })

            text = soup.get_text()
            results['emails'].update(re.findall(r'[\w\.-]+@[\w\.-]+', text))
            results['phone_numbers'].update(re.findall(r'(\+?\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}', text))
            results['emails'] = list(results['emails'])
            results['phone_numbers'] = list(results['phone_numbers'])

            return results
        except Exception as e:
            logger.error(f"Error in _analyze_html_content: {str(e)}")
            return {'error': str(e)}

    def _discover_api_endpoints(self, content, base_url):
        """Discover API endpoints"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            endpoints = set()
            patterns = [
                r'/(api|rest|v\d+|graphql)/[\w\-/]+',
                r'/\w+\.json',
                r'/\w+\.api'
            ]
            for script in soup.find_all('script'):
                if script.get('src'):
                    for pattern in patterns:
                        matches = re.findall(pattern, script['src'])
                        endpoints.update(urljoin(base_url, match) for match in matches)
            for link in soup.find_all('a'):
                if link.get('href'):
                    for pattern in patterns:
                        matches = re.findall(pattern, link['href'])
                        endpoints.update(urljoin(base_url, match) for match in matches)
            return list(endpoints)
        except Exception as e:
            logger.warning(f"Error in _discover_api_endpoints: {str(e)}")
            return []

    def _check_cors(self, url):
        """Check for CORS misconfigurations"""
        try:
            self._rate_limit_request()
            headers = {'Origin': 'http://evil.com'}
            response = self.session.options(url, headers=headers, timeout=self.timeout, verify=False)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return {'error': 'Rate limit detected'}
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', ''),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', ''),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', '')
            }
            is_vulnerable = cors_headers['Access-Control-Allow-Origin'] in ['*', 'http://evil.com']
            return {
                'headers': cors_headers,
                'is_vulnerable': is_vulnerable,
                'details': 'Wildcard or untrusted origin allowed' if is_vulnerable else 'No obvious CORS issues'
            }
        except Exception as e:
            logger.warning(f"Error in _check_cors: {str(e)}")
            return {'error': str(e)}

    def get_dns_records(self, domain):
        """Get DNS records"""
        try:
            domain = self._validate_domain(domain)
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SPF', 'DMARC']
            results = {}
            for record_type in record_types:
                try:
                    answers = self.dns_resolver.resolve(domain, record_type)
                    results[record_type] = [str(r) for r in answers]
                    if record_type == 'TXT':
                        results['TXT_analysis'] = self._analyze_txt_records([str(r) for r in answers])
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                    results[record_type] = []
                except Exception as e:
                    results[record_type] = {'error': str(e)}
            return results
        except Exception as e:
            logger.error(f"Error in get_dns_records: {str(e)}")
            return {'error': str(e)}

    def _analyze_txt_records(self, txt_records):
        """Analyze TXT records"""
        analysis = {'spf': None, 'dmarc': None, 'dkim': None}
        for record in txt_records:
            if 'v=spf1' in record.lower():
                analysis['spf'] = record
            if 'v=DMARC1' in record:
                analysis['dmarc'] = record
            if 'dkim' in record.lower():
                analysis['dkim'] = record
        return analysis

    def get_subdomains(self, domain, brute_force=True):
        """Discover subdomains with custom wordlist"""
        try:
            domain = self._validate_domain(domain)
            subdomains = set()

            try:
                answers = self.dns_resolver.resolve(domain, 'NS')
                for rdata in answers:
                    ns_domain = str(rdata.target).rstrip('.')
                    if ns_domain.endswith(domain):
                        subdomains.add(ns_domain)
            except Exception as e:
                logger.warning(f"NS lookup failed: {str(e)}")

            subdomains.update(self._get_ct_subdomains(domain))

            if brute_force:
                prioritized = self._prioritize_subdomains(self._wordlist, domain)
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    futures = []
                    for word in prioritized[:1000]:
                        subdomain = f"{word}.{domain}"
                        futures.append(executor.submit(self._check_subdomain, subdomain))
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            subdomains.add(result)
                            self._rate_limit_request()

            return sorted(list(subdomains))
        except Exception as e:
            logger.error(f"Error in get_subdomains: {str(e)}")
            return {'error': str(e)}

    def _prioritize_subdomains(self, wordlist, domain):
        """Prioritize subdomains"""
        try:
            scores = []
            for word in wordlist:
                score = len(word) * 0.1
                if any(keyword in word for keyword in ['admin', 'api', 'secure', 'login']):
                    score += 0.5
                scores.append((word, score))
            return [word for word, _ in sorted(scores, key=lambda x: x[1], reverse=True)]
        except Exception as e:
            logger.warning(f"Error in _prioritize_subdomains: {str(e)}")
            return wordlist

    def _get_ct_subdomains(self, domain):
        """Get subdomains from Certificate Transparency"""
        try:
            self._rate_limit_request()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return set()
            data = response.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                names = name_value.split('\n')
                for name in names:
                    if name.endswith(domain):
                        subdomains.add(name.strip())
            return subdomains
        except Exception as e:
            logger.warning(f"CT lookup failed: {str(e)}")
            return set()

    def _get_default_wordlist(self):
        """Get default wordlist"""
        return [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns', 'ns1',
            'ns2', 'smtp', 'secure', 'vpn', 'api', 'app', 'login', 'staging',
            'dev', 'test', 'beta', 'cdn', 'static', 'backup', 'console', 'admin-panel'
        ]

    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            if self.stealth:
                self._rate_limit_request()
                response = self.session.get(f"https://{subdomain}", timeout=self.timeout, verify=False)
                if response.status_code == 429:
                    self._backoff = min(self._backoff + 1, 10)
                    logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                    return None
                if response.status_code in [200, 301, 302]:
                    return subdomain
            return subdomain
        except socket.gaierror:
            return None
        except Exception as e:
            logger.warning(f"Error checking subdomain {subdomain}: {str(e)}")
            return None

    def get_whois_info(self, domain):
        """Enhanced WHOIS information"""
        try:
            domain = self._validate_domain(domain)
            whois_data = whois.whois(domain)
            parsed = {
                'domain_name': getattr(whois_data, 'domain_name', None),
                'registrar': getattr(whois_data, 'registrar', None),
                'whois_server': getattr(whois_data, 'whois_server', None),
                'creation_date': getattr(whois_data, 'creation_date', None),
                'expiration_date': getattr(whois_data, 'expiration_date', None),
                'updated_date': getattr(whois_data, 'updated_date', None),
                'name_servers': list(getattr(whois_data, 'name_servers', [])) or [],
                'status': getattr(whois_data, 'status', None),
                'emails': getattr(whois_data, 'emails', []) or [],
                'dnssec': getattr(whois_data, 'dnssec', None),
                'is_redacted': any('redacted' in str(field).lower() for field in whois_data.values()),
                'raw': str(whois_data)
            }
            return parsed
        except Exception as e:
            logger.error(f"Error in get_whois_info: {str(e)}")
            return {'error': str(e)}

    def get_robots_txt(self, url):
        """Get robots.txt"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            robots_url = urljoin(url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return {'error': 'Rate limit detected'}
            if response.status_code == 200:
                analysis = {
                    'disallowed': [],
                    'allowed': [],
                    'sitemaps': [],
                    'crawl_delay': None,
                    'user_agents': set(),
                    'sensitive_paths': []
                }
                current_ua = None
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = [p.strip() for p in line.split(':', 1)]
                    if len(parts) != 2:
                        continue
                    directive, value = parts
                    directive = directive.lower()
                    if directive == 'user-agent':
                        current_ua = value
                        analysis['user_agents'].add(value)
                    elif directive == 'disallow' and current_ua:
                        analysis['disallowed'].append({'user_agent': current_ua, 'path': value})
                        if any(keyword in value for keyword in ['admin', 'login', 'api']):
                            analysis['sensitive_paths'].append(value)
                    elif directive == 'allow' and current_ua:
                        analysis['allowed'].append({'user_agent': current_ua, 'path': value})
                    elif directive == 'sitemap':
                        analysis['sitemaps'].append(value)
                    elif directive == 'crawl-delay':
                        analysis['crawl_delay'] = value
                analysis['user_agents'] = list(analysis['user_agents'])
                return {'content': response.text, 'analysis': analysis}
            return None
        except Exception as e:
            logger.error(f"Error in get_robots_txt: {str(e)}")
            return {'error': str(e)}

    def get_sitemap(self, url):
        """Get and parse sitemap.xml"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            sitemap_url = urljoin(url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=self.timeout)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return {'error': 'Rate limit detected'}
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    urls = []
                    for url_elem in root.findall('{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                        loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                        if loc is not None:
                            urls.append(loc.text)
                    validated_urls = self._validate_sitemap_urls(urls)
                    return {'content': response.text, 'urls': urls, 'validated_urls': validated_urls}
                except ET.ParseError:
                    urls = [line.strip() for line in response.text.splitlines() if line.strip()]
                    validated_urls = self._validate_sitemap_urls(urls)
                    return {'content': response.text, 'urls': urls, 'validated_urls': validated_urls}
            return None
        except Exception as e:
            logger.error(f"Error in get_sitemap: {str(e)}")
            return {'error': str(e)}

    def _validate_sitemap_urls(self, urls):
        """Validate sitemap URLs"""
        validated = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._check_url_status, url) for url in urls[:50]]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    validated.append(result)
                self._rate_limit_request()
        return validated

    def _check_url_status(self, url):
        """Check URL accessibility"""
        try:
            response = self.session.head(url, timeout=self.timeout, verify=False)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return None
            return {'url': url, 'status_code': response.status_code}
        except Exception:
            return None

    def scan_open_ports(self, domain, ports=None):
        """Scan for open ports"""
        try:
            domain = self._validate_domain(domain)
            if ports is None:
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080]
            open_ports = []
            ip = socket.gethostbyname(domain)

            def check_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            service = self._guess_service(port)
                            return {'port': port, 'service': service}
                except:
                    return None

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(check_port, port) for port in ports]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                    self._rate_limit_request()

            return {'ip': ip, 'open_ports': sorted(open_ports, key=lambda x: x['port'])}
        except Exception as e:
            logger.error(f"Error in scan_open_ports: {str(e)}")
            return {'error': str(e)}

    def _guess_service(self, port):
        """Guess service on port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')

    def get_website_technologies(self, url):
        """Detect website technologies"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            if self.stealth:
                self.rotate_proxies()
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return {'error': 'Rate limit detected'}
            soup = BeautifulSoup(response.text, 'html.parser')
            technologies = self._detect_technologies(response.text, response.headers)

            if soup.find('meta', {'name': 'generator', 'content': re.compile(r'WordPress')}):
                technologies.append('WordPress')
            if soup.find('meta', {'name': 'generator', 'content': re.compile(r'Joomla')}):
                technologies.append('Joomla')
            if soup.find('meta', {'name': 'Generator', 'content': re.compile(r'Drupal')}):
                technologies.append('Drupal')

            return list(set(technologies))
        except Exception as e:
            logger.error(f"Error in get_website_technologies: {str(e)}")
            return {'error': str(e)}

    def run_sqlmap(self, url, level=1):
        """Run sqlmap"""
        try:
            cmd = [
                'sqlmap',
                '-u', url,
                '--level', str(level),
                '--batch',
                '--output-dir', 'sqlmap_output'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            vulnerabilities = []
            if 'sqlmap identified' in output.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'details': output[:500],
                    'sqlmap_output': 'sqlmap_output'
                })
            return vulnerabilities if vulnerabilities else ['No SQL injection found']
        except Exception as e:
            logger.error(f"Error in run_sqlmap: {str(e)}")
            return {'error': str(e)}

    def run_wafw00f(self, url):
        """Run wafw00f"""
        try:
            waf = WAFW00F(url)
            result = waf.identwaf()
            if result:
                return {
                    'detected': True,
                    'provider': result,
                    'details': f"WAF identified: {result}"
                }
            return {
                'detected': False,
                'provider': None,
                'details': 'No WAF detected'
            }
        except Exception as e:
            logger.error(f"Error in run_wafw00f: {str(e)}")
            return {'error': str(e)}

    def run_xsstrike(self, url):
        """Run XSStrike"""
        try:
            xs = XSStrike()
            xs.target = url
            xs.crawl()
            results = xs.scan()
            vulnerabilities = []
            for vuln in results:
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'Medium',
                    'details': f"Payload: {vuln['payload']}, Vector: {vuln['vector']}"
                })
            return vulnerabilities if vulnerabilities else ['No XSS found']
        except Exception as e:
            logger.error(f"Error in run_xsstrike: {str(e)}")
            return {'error': str(e)}

    def get_website_vulnerabilities(self, url):
        """Check vulnerabilities with integrated tools"""
        try:
            url = self._validate_url(url)
            vulnerabilities = []
            scores = []

            for path in ['.git/', '.env', 'wp-config.php', 'configuration.php']:
                self._rate_limit_request()
                if self.stealth:
                    self.rotate_proxies()
                test_url = urljoin(url, path)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                if response.status_code == 429:
                    self._backoff = min(self._backoff + 1, 10)
                    logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                    continue
                if response.status_code == 200:
                    if path == '.git/' and 'directory' in response.text.lower():
                        vulnerabilities.append({'type': 'Exposed .git directory', 'severity': 'High', 'details': 'Git repository exposed'})
                        scores.append(0.9)
                    elif path == '.env' and '=' in response.text:
                        vulnerabilities.append({'type': 'Exposed .env file', 'severity': 'Critical', 'details': 'Environment variables exposed'})
                        scores.append(1.0)
                    elif path in ['wp-config.php', 'configuration.php']:
                        vulnerabilities.append({'type': f'Exposed {path}', 'severity': 'Critical', 'details': 'Sensitive configuration file exposed'})
                        scores.append(1.0)

            for vuln_type, payloads in {**self._payloads, **self._custom_payloads}.items():
                for payload in payloads:
                    self._rate_limit_request()
                    if self.stealth:
                        self.rotate_proxies()
                    obfuscated = self._obfuscate_payload(payload)
                    test_url = f"{url}?q={obfuscated}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if response.status_code == 429:
                        self._backoff = min(self._backoff + 1, 10)
                        logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                        continue
                    if response.status_code in [403, 406, 419]:
                        continue
                    if vuln_type == 'xss' and any(p in response.text.lower() for p in ['alert(1)', 'onerror']):
                        vulnerabilities.append({'type': 'Custom XSS', 'severity': 'Medium', 'details': f'Payload: {payload}'})
                        scores.append(0.6)
                    elif vuln_type == 'sqli' and 'sql syntax' in response.text.lower():
                        vulnerabilities.append({'type': 'Custom SQL Injection', 'severity': 'High', 'details': f'Payload: {payload}'})
                        scores.append(0.8)

            dir_results = self._brute_force_directories(url)
            vulnerabilities.extend(dir_results)
            scores.extend([0.5] * len(dir_results))

            sqlmap_results = self.run_sqlmap(url)
            if isinstance(sqlmap_results, list):
                vulnerabilities.extend(sqlmap_results)
                scores.extend([0.8] * len(sqlmap_results))

            xsstrike_results = self.run_xsstrike(url)
            if isinstance(xsstrike_results, list):
                vulnerabilities.extend(xsstrike_results)
                scores.extend([0.6] * len(xsstrike_results))

            if vulnerabilities:
                sorted_vulns = [v for _, v in sorted(zip(scores, vulnerabilities), key=lambda x: x[0], reverse=True)]
                return sorted_vulns
            return ['No obvious vulnerabilities found']
        except Exception as e:
            logger.error(f"Error in get_website_vulnerabilities: {str(e)}")
            return {'error': str(e)}

    def _brute_force_directories(self, url):
        """Brute-force directories with custom wordlist"""
        try:
            vulnerabilities = []
            payloads = self._payloads['dir'] + self._custom_payloads.get('dir', [])
            for path in payloads[:50]:
                self._rate_limit_request()
                if self.stealth:
                    self.rotate_proxies()
                test_url = urljoin(url, path)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                if response.status_code == 429:
                    self._backoff = min(self._backoff + 1, 10)
                    logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                    continue
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Exposed Directory',
                        'severity': 'Medium',
                        'details': f"Accessible directory: {test_url}"
                    })
            return vulnerabilities
        except Exception as e:
            logger.warning(f"Error in _brute_force_directories: {str(e)}")
            return []

    def get_website_headers_dump(self, url):
        """Get HTTP headers"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            if self.stealth:
                self.rotate_proxies()
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 429:
                self._backoff = min(self._backoff + 1, 10)
                logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                return {'error': 'Rate limit detected'}
            headers = dict(response.headers)
            analysis = {
                'missing_security_headers': [],
                'insecure_headers': [],
                'recommendations': [],
                'fingerprinting': []
            }
            security_headers = [
                'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options',
                'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy'
            ]
            for header in security_headers:
                if header not in headers:
                    analysis['missing_security_headers'].append(header)
                    analysis['recommendations'].append(f"Implement {header}")
            if 'Server' in headers:
                analysis['insecure_headers'].append(f"Server: {headers['Server']}")
                analysis['fingerprinting'].append(f"Server header reveals: {headers['Server']}")
            if 'X-Powered-By' in headers:
                analysis['insecure_headers'].append(f"X-Powered-By: {headers['X-Powered-By']}")
                analysis['fingerprinting'].append(f"X-Powered-By reveals: {headers['X-Powered-By']}")
            return {'headers': headers, 'analysis': analysis}
        except Exception as e:
            logger.error(f"Error in get_website_headers_dump: {str(e)}")
            return {'error': str(e)}

    def get_website_waf_info(self, url):
        """Detect WAF"""
        try:
            url = self._validate_url(url)
            self._rate_limit_request()
            if self.stealth:
                self.rotate_proxies()
            waf_result = self.run_wafw00f(url)
            if isinstance(waf_result, dict) and waf_result.get('error'):
                return waf_result
            waf_info = {
                'detected': waf_result['detected'],
                'provider': waf_result['provider'],
                'bypass_attempts': []
            }

            for payload in self._payloads['xss'] + self._custom_payloads.get('xss', []):
                self._rate_limit_request()
                if self.stealth:
                    self.rotate_proxies()
                obfuscated = self._obfuscate_payload(payload)
                test_url = f"{url}?test={obfuscated}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if response.status_code == 429:
                        self._backoff = min(self._backoff + 1, 10)
                        logger.warning(f"Rate limit detected, backoff: {self._backoff}s")
                        continue
                    if response.status_code in [403, 406, 419] or 'blocked' in response.text.lower():
                        waf_info['bypass_attempts'].append({
                            'payload': obfuscated,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:200]
                        })
                    else:
                        waf_info['bypass_attempts'].append({
                            'payload': obfuscated,
                            'status_code': response.status_code,
                            'bypass_success': True
                        })
                except:
                    continue

            return waf_info
        except Exception as e:
            logger.error(f"Error in get_website_waf_info: {str(e)}")
            return {'error': str(e )}

    def get_exploit_suggestions(self, url, technologies, vulnerabilities):
        """Suggest exploits"""
        try:
            suggestions = []
            for tech in technologies:
                if tech == 'WordPress':
                    suggestions.append({
                        'target': 'WordPress',
                        'exploit': 'Check for outdated plugins/themes (e.g., WPScan)',
                        'cve': 'Multiple CVEs (e.g., CVE-2023-1234)',
                        'priority': 'High'
                    })
                elif tech == 'Drupal':
                    suggestions.append({
                        'target': 'Drupal',
                        'exploit': 'Test for Drupalgeddon vulnerabilities (e.g., CVE-2018-7600)',
                        'cve': 'CVE-2018-7600',
                        'priority': 'High'
                    })
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    if vuln.get('type') == 'Exposed .git directory':
                        suggestions.append({
                            'target': '.git exposure',
                            'exploit': 'Use GitTools to extract repository data',
                            'cve': None,
                            'priority': 'Critical'
                        })
                    elif vuln.get('type') in ['Potential XSS', 'Custom XSS']:
                        suggestions.append({
                            'target': 'XSS',
                            'exploit': 'Test with polyglot payloads or Burp Suite',
                            'cve': None,
                            'priority': 'Medium'
                        })
                    elif vuln.get('type') in ['SQL Injection', 'Custom SQL Injection']:
                        suggestions.append({
                            'target': 'SQL Injection',
                            'exploit': 'Exploit with sqlmap or manual payloads',
                            'cve': None,
                            'priority': 'High'
                        })
            return suggestions if suggestions else ['No specific exploits identified']
        except Exception as e:
            logger.error(f"Error in get_exploit_suggestions: {str(e)}")
            return {'error': str(e)}

    def generate_report(self, scan_results):
        """Generate PDF report"""
        try:
            latex_content = r"""
            \documentclass{article}
            \usepackage{geometry}
            \geometry{a4paper, margin=1in}
            \usepackage{hyperref}
            \usepackage{longtable}
            \usepackage{noto}
            \title{Web Reconnaissance Report}
            \author{AdvancedWebRecon}
            \date{\today}

            \begin{document}
            \maketitle
            \section{Scan Summary}
            \textbf{URL:} \url{""" + scan_results['url'] + r"""}\par
            \textbf{Timestamp:} """ + scan_results['timestamp'] + r"""\par
            \textbf{Status:} """ + scan_results['status'] + r"""\par

            \section{Technologies}
            \begin{itemize}
            """
            for tech in scan_results.get('technologies', []):
                latex_content += f"\\item {tech}\n"
            latex_content += r"""
            \end{itemize}

            \section{Vulnerabilities}
            \begin{longtable}{|l|l|p{6cm}|}
            \hline
            \textbf{Type} & \textbf{Severity} & \textbf{Details} \\
            \hline
            """
            for vuln in scan_results.get('vulnerabilities', []):
                if isinstance(vuln, dict):
                    latex_content += f"{vuln['type']} & {vuln['severity']} & {vuln['details'].replace('&', '\\&')} \\\\ \\hline\n"
            latex_content += r"""
            \end{longtable}

            \section{Exploit Suggestions}
            \begin{longtable}{|l|l|p{6cm}|}
            \hline
            \textbf{Target} & \textbf{Priority} & \textbf{Exploit} \\
            \hline
            """
            for sugg in scan_results.get('exploit_suggestions', []):
                if isinstance(sugg, dict):
                    latex_content += f"{sugg['target']} & {sugg['priority']} & {sugg['exploit'].replace('&', '\\&')} \\\\ \\hline\n"
            latex_content += r"""
            \end{longtable}

            \section{CSRF Tokens}
            \begin{longtable}{|p{6cm}|l|}
            \hline
            \textbf{Token} & \textbf{Analysis} \\
            \hline
            """
            for token in scan_results.get('url_info', {}).get('csrf_tokens', []):
                latex_content += f"{token['token'][:50]} & {token['analysis']['details'].replace('&', '\\&')} \\\\ \\hline\n"
            latex_content += r"""
            \end{longtable}

            \end{document}
            """

            with open('report.tex', 'w') as f:
                f.write(latex_content)

            subprocess.run(['latexmk', '-pdf', 'report.tex'], check=True)
            return {'report_path': 'report.pdf'}
        except Exception as e:
            logger.error(f"Error in generate_report: {str(e)}")
            return {'error': str(e)}

    def get_website_full_scan(self, url, stealth=True, brute_force=True):
        """Perform comprehensive scan"""
        try:
            url = self._validate_url(url)
            domain = urlparse(url).netloc
            scan_results = {
                'url': url,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed',
                'errors': []
            }

            def parallel_tasks():
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    futures = {
                        'url_info': executor.submit(self.get_url_info, url, stealth=stealth),
                        'technologies': executor.submit(self.get_website_technologies, url),
                        'headers': executor.submit(self.get_website_headers_dump, url),
                        'dns_records': executor.submit(self.get_dns_records, domain),
                        'subdomains': executor.submit(self.get_subdomains, domain, brute_force=brute_force),
                        'whois_info': executor.submit(self.get_whois_info, domain),
                        'open_ports': executor.submit(self.scan_open_ports, domain),
                        'vulnerabilities': executor.submit(self.get_website_vulnerabilities, url),
                        'waf_info': executor.submit(self.get_website_waf_info, url),
                        'robots_txt': executor.submit(self.get_robots_txt, url),
                        'sitemap': executor.submit(self.get_sitemap, url)
                    }
                    results = {}
                    for key, future in futures.items():
                        results[key] = future.result()
                        if isinstance(results[key], dict) and 'error' in results[key]:
                            with self._lock:
                                self._error_list.append(results[key]['error'])
                        self._rate_limit_request()

                    if 'technologies' in results and 'vulnerabilities' in results:
                        results['exploit_suggestions'] = self.get_exploit_suggestions(
                            url,
                            results['technologies'],
                            results['vulnerabilities']
                        )

                    results['report'] = self.generate_report(results)
                    return results

            scan_results.update(parallel_tasks())
            scan_results['errors'] = list(set(self._error_list))
            if scan_results['errors']:
                scan_results['status'] = 'completed_with_errors'

            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO scans (url, timestamp, results, status) VALUES (?, ?, ?, ?)",
                        (url, scan_results['timestamp'], json.dumps(scan_results), scan_results['status'])
                    )
                    conn.commit()
            except Exception as e:
                logger.error(f"Error saving scan to database: {str(e)}")

            return scan_results

        except Exception as e:
            logger.error(f"Error in get_website_full_scan: {str(e)}")
            return {
                'url': url,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'failed',
                'error': str(e)
            }

    def get_scan_history(self):
        """Retrieve scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, url, timestamp, status FROM scans ORDER BY timestamp DESC")
                return [
                    {'id': row[0], 'url': row[1], 'timestamp': row[2], 'status': row[3]}
                    for row in cursor.fetchall()
                ]
        except Exception as e:
            logger.error(f"Error in get_scan_history: {str(e)}")
            return {'error': str(e)}

    def _safe_execute(self, func, *args, **kwargs):
        """Safely execute a function"""
        try:
            self._rate_limit_request()
            if self.stealth:
                self.rotate_proxies()
            result = func(*args, **kwargs)
            if isinstance(result, dict) and 'error' in result:
                with self._lock:
                    self._error_list.append(result['error'])
                return None
            return result
        except Exception as e:
            with self._lock:
                self._error_list.append(str(e))
            return None

    def _add_error(self, error_msg):
        """Add error message"""
        with self._lock:
            self._error_list.append(error_msg)