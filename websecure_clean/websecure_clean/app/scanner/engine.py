"""
WebSecure Vulnerability Scanner Engine
=======================================
Performs all security checks against a target URL and returns structured findings.

Checks performed:
  1. HTTPS / SSL certificate validation
  2. HTTP Security Headers (CSP, X-Frame-Options, HSTS, X-XSS-Protection, etc.)
  3. Open Ports (80, 443, 8080, 8443)
  4. Directory Exposure (admin, backup, .git, etc.)
  5. SQL Injection indicators in URL parameters
  6. XSS reflection indicators
  7. Login form without HTTPS / autocomplete
  8. Server information leakage
  9. Cookie security flags
 10. Mixed content detection
"""

import socket
import ssl
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

TIMEOUT = 10  # seconds per request

# Headers that should be present on secure sites
SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'risk': 'High',
        'score': 8.0,
        'description': 'Content-Security-Policy (CSP) header is missing. CSP prevents cross-site '
                       'scripting (XSS) and data injection attacks by controlling which resources '
                       'the browser is allowed to load.',
        'recommendation': 'Add a Content-Security-Policy header to your web server configuration. '
                          "Example: Content-Security-Policy: default-src 'self'"
    },
    'X-Frame-Options': {
        'risk': 'Medium',
        'score': 6.0,
        'description': 'X-Frame-Options header is missing. Without this header, your site may be '
                       'vulnerable to Clickjacking attacks, where attackers embed your site in an '
                       'invisible iframe to trick users.',
        'recommendation': 'Add the header: X-Frame-Options: SAMEORIGIN or DENY to prevent '
                          'your pages from being embedded in frames on other domains.'
    },
    'Strict-Transport-Security': {
        'risk': 'High',
        'score': 7.5,
        'description': 'HTTP Strict-Transport-Security (HSTS) header is missing. HSTS instructs '
                       'browsers to only access your site over HTTPS, preventing protocol '
                       'downgrade attacks.',
        'recommendation': 'Add the header: Strict-Transport-Security: max-age=31536000; '
                          'includeSubDomains; preload'
    },
    'X-Content-Type-Options': {
        'risk': 'Low',
        'score': 4.0,
        'description': 'X-Content-Type-Options header is missing. Without it, browsers may '
                       'MIME-sniff responses away from the declared content type, enabling '
                       'XSS and drive-by download attacks.',
        'recommendation': "Add the header: X-Content-Type-Options: nosniff"
    },
    'X-XSS-Protection': {
        'risk': 'Low',
        'score': 3.5,
        'description': 'X-XSS-Protection header is missing. This header enables the cross-site '
                       'scripting (XSS) filter built into older browsers.',
        'recommendation': "Add the header: X-XSS-Protection: 1; mode=block"
    },
    'Referrer-Policy': {
        'risk': 'Low',
        'score': 3.0,
        'description': 'Referrer-Policy header is missing. Without it, full URLs including '
                       'sensitive query parameters may be exposed to third-party sites.',
        'recommendation': "Add the header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    'Permissions-Policy': {
        'risk': 'Low',
        'score': 2.5,
        'description': 'Permissions-Policy (formerly Feature-Policy) header is missing. This '
                       'header limits which browser features and APIs can be used on the page.',
        'recommendation': "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
}

# Sensitive directories to probe
SENSITIVE_PATHS = [
    ('/admin',          'High', 9.0,  'Admin panel may be exposed'),
    ('/administrator',  'High', 9.0,  'Admin panel may be exposed'),
    ('/backup',         'High', 8.5,  'Backup directory may be exposed'),
    ('/backup.zip',     'High', 8.5,  'Backup archive may be downloadable'),
    ('/config',         'High', 8.0,  'Configuration directory may be exposed'),
    ('/config.php',     'High', 8.0,  'Configuration file may be readable'),
    ('/.git',           'High', 9.5,  'Git repository exposed — source code and credentials at risk'),
    ('/.git/config',    'High', 9.5,  'Git config file exposed'),
    ('/.env',           'High', 9.5,  '.env file exposed — may contain passwords and API keys'),
    ('/wp-admin',       'Medium', 7.0, 'WordPress admin login exposed'),
    ('/phpmyadmin',     'High', 8.5,  'phpMyAdmin database interface exposed'),
    ('/server-status',  'Medium', 6.0, 'Apache server-status page may be accessible'),
    ('/robots.txt',     'Low', 2.0,   'robots.txt found — review for sensitive path disclosure'),
    ('/sitemap.xml',    'Low', 1.5,   'Sitemap found — review for unintended path disclosure'),
]

# Common web ports to check
WEB_PORTS = [
    (80,   'HTTP',   'Low',    3.0, 'Port 80 (HTTP) is open — unencrypted traffic possible'),
    (443,  'HTTPS',  'Info',   0.0, 'Port 443 (HTTPS) is open — good'),
    (8080, 'HTTP-alt','Medium', 5.0, 'Port 8080 is open — alternative HTTP port, often unsecured'),
    (8443, 'HTTPS-alt','Low',  3.0, 'Port 8443 is open — alternative HTTPS port'),
    (8888, 'Dev',   'Medium',  5.5, 'Port 8888 is open — often used by dev servers, should not be public'),
    (3000, 'Node',  'Medium',  5.0, 'Port 3000 is open — often a Node.js dev server'),
]

# Simple SQLi test payloads to append to URL
SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1 OR 1=1", "'; DROP TABLE users;--"]
SQLI_ERROR_SIGNATURES = [
    'sql syntax', 'mysql_fetch', 'ora-', 'pg_query', 'sqlite',
    'syntax error', 'unclosed quotation', 'microsoft ole db',
    'odbc drivers', 'you have an error in your sql',
]

# XSS reflection test
XSS_PAYLOAD = '<script>alert(1)</script>'


# ═════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═════════════════════════════════════════════════════════════════════════════

class VulnerabilityScanner:
    """
    Orchestrates all security checks for a given URL.
    Returns a list of finding dicts ready to be stored as Vulnerability records.
    """

    def __init__(self, url: str):
        self.url = self._normalize_url(url)
        self.parsed = urlparse(self.url)
        self.hostname = self.parsed.hostname
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecure-Scanner/1.0 (Security Audit Bot)'
        })

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    def _add_finding(self, vuln_type, risk_level, description, recommendation,
                     evidence=None, score=5.0):
        self.findings.append({
            'vulnerability_type': vuln_type,
            'risk_level':         risk_level,
            'description':        description,
            'recommendation':     recommendation,
            'evidence':           evidence or '',
            'severity_score':     score,
        })

    def _get(self, url, timeout=TIMEOUT, allow_redirects=True):
        try:
            resp = self.session.get(url, timeout=timeout,
                                    allow_redirects=allow_redirects,
                                    verify=False)   # we handle SSL check separately
            return resp
        except requests.exceptions.SSLError as e:
            logger.warning(f'SSL error for {url}: {e}')
            return None
        except requests.exceptions.ConnectionError as e:
            logger.warning(f'Connection error for {url}: {e}')
            return None
        except requests.exceptions.Timeout:
            logger.warning(f'Timeout for {url}')
            return None
        except Exception as e:
            logger.warning(f'Request failed for {url}: {e}')
            return None

    # ── Check 1: HTTPS / SSL ──────────────────────────────────────────────────

    def check_https(self):
        """Verify HTTPS is used and SSL certificate is valid."""
        if self.parsed.scheme != 'https':
            # Check if HTTPS is available on this host
            https_url = self.url.replace('http://', 'https://', 1)
            resp = self._get(https_url)
            if resp and resp.ok:
                self._add_finding(
                    'Missing HTTPS / HTTP only',
                    'High',
                    'The website is served over HTTP (unencrypted). All data exchanged between '
                    'the server and users is transmitted in plaintext, making it vulnerable to '
                    'eavesdropping and man-in-the-middle attacks.',
                    'Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS. '
                    'Free certificates are available via Let\'s Encrypt (https://letsencrypt.org).',
                    evidence=f'Site accessible via HTTP: {self.url}',
                    score=9.0
                )
            else:
                self._add_finding(
                    'No HTTPS Support',
                    'High',
                    'The website does not support HTTPS at all. All communications are unencrypted.',
                    'Install an SSL/TLS certificate immediately. Use Let\'s Encrypt for free certificates.',
                    score=9.5
                )
        else:
            # Validate the SSL certificate
            self._check_ssl_cert()

    def _check_ssl_cert(self):
        """Check SSL certificate validity and expiry."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Check expiry
                    import datetime
                    expire_str = cert.get('notAfter', '')
                    if expire_str:
                        expire_date = ssl.cert_time_to_seconds(expire_str)
                        days_left = (expire_date - time.time()) / 86400
                        if days_left < 0:
                            self._add_finding(
                                'SSL Certificate Expired',
                                'High',
                                f'The SSL certificate has EXPIRED. Browsers will show a security '
                                f'warning to all visitors.',
                                'Renew your SSL certificate immediately.',
                                evidence=f'Certificate expired: {expire_str}',
                                score=10.0
                            )
                        elif days_left < 30:
                            self._add_finding(
                                'SSL Certificate Expiring Soon',
                                'Medium',
                                f'The SSL certificate will expire in {int(days_left)} days.',
                                'Renew your SSL certificate before it expires.',
                                evidence=f'Expires: {expire_str} ({int(days_left)} days left)',
                                score=6.0
                            )
        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                'Invalid SSL Certificate',
                'High',
                'The SSL certificate is invalid or self-signed. Browsers will warn users that '
                'the connection is not secure.',
                'Install a valid SSL certificate from a trusted Certificate Authority.',
                evidence=str(e),
                score=8.5
            )
        except Exception as e:
            logger.debug(f'SSL check exception: {e}')

    # ── Check 2: Security Headers ─────────────────────────────────────────────

    def check_security_headers(self):
        """Check for presence of recommended HTTP security headers."""
        resp = self._get(self.url)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, meta in SECURITY_HEADERS.items():
            if header_name.lower() not in headers:
                self._add_finding(
                    f'Missing Header: {header_name}',
                    meta['risk'],
                    meta['description'],
                    meta['recommendation'],
                    evidence=f'Header "{header_name}" not found in response.',
                    score=meta['score']
                )

        # Check for server info leakage
        server = headers.get('server', '')
        x_powered = headers.get('x-powered-by', '')
        if server and any(v in server.lower() for v in ['apache', 'nginx', 'iis', 'php']):
            self._add_finding(
                'Server Information Leakage (Server header)',
                'Low',
                f'The "Server" response header reveals the web server software and version: '
                f'"{server}". Attackers can use this to target known vulnerabilities.',
                'Configure your web server to suppress or obfuscate the Server header.',
                evidence=f'Server: {server}',
                score=3.5
            )
        if x_powered:
            self._add_finding(
                'Server Information Leakage (X-Powered-By)',
                'Low',
                f'The "X-Powered-By" header reveals the technology stack: "{x_powered}". '
                f'This helps attackers fingerprint your server.',
                'Remove the X-Powered-By header from your server configuration.',
                evidence=f'X-Powered-By: {x_powered}',
                score=3.0
            )

    # ── Check 3: Open Ports ───────────────────────────────────────────────────

    def check_open_ports(self):
        """Probe common web ports on the target host."""
        for port, service, risk, score, desc in WEB_PORTS:
            if risk == 'Info':
                continue  # skip informational items (HTTPS port 443 being open is good)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.hostname, port))
                sock.close()
                if result == 0:  # port is open
                    self._add_finding(
                        f'Open Port: {port} ({service})',
                        risk,
                        desc,
                        f'If port {port} is not required for production traffic, close it via '
                        f'your firewall. Restrict access to known IP ranges if the service must run.',
                        evidence=f'{self.hostname}:{port} is open',
                        score=score
                    )
            except Exception:
                pass

    # ── Check 4: Directory / Path Exposure ───────────────────────────────────

    def check_directory_exposure(self):
        """Probe for sensitive exposed paths and directories."""
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        for path, risk, score, hint in SENSITIVE_PATHS:
            url = base + path
            resp = self._get(url, allow_redirects=False)
            if resp is None:
                continue
            # Treat 200 or directory listing as exposed; 403 is debatable (we flag it too for dirs)
            if resp.status_code in (200, 403):
                status_note = '(HTTP 200 – accessible)' if resp.status_code == 200 \
                              else '(HTTP 403 – path exists but access denied)'
                self._add_finding(
                    f'Path Exposure: {path}',
                    risk,
                    f'{hint}. The path "{path}" returned status {resp.status_code}, suggesting '
                    f'it exists on the server. {status_note}',
                    f'Restrict access to "{path}" via your web server configuration or remove '
                    f'it from the public web root entirely.',
                    evidence=f'GET {url} → HTTP {resp.status_code}',
                    score=score
                )

    # ── Check 5: SQL Injection Indicators ────────────────────────────────────

    def check_sql_injection(self):
        """Test URL parameters for SQL injection error responses."""
        resp = self._get(self.url)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        # Find forms with GET method to test
        forms = soup.find_all('form', method=lambda m: m and m.lower() == 'get')

        # Also test the URL itself if it has query parameters
        if '?' in self.url:
            base_url = self.url.split('?')[0]
            params_str = self.url.split('?')[1]
            params = {}
            for part in params_str.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    params[k] = v

            for payload in SQLI_PAYLOADS[:2]:  # limit to 2 payloads to be polite
                test_params = {k: payload for k in params}
                try:
                    test_resp = self.session.get(base_url, params=test_params,
                                                 timeout=TIMEOUT, verify=False)
                    body = test_resp.text.lower()
                    for sig in SQLI_ERROR_SIGNATURES:
                        if sig in body:
                            self._add_finding(
                                'SQL Injection Vulnerability Indicator',
                                'High',
                                'A URL parameter appears to trigger a SQL error response, which is '
                                'a strong indicator of SQL injection vulnerability. Attackers could '
                                'use this to read, modify, or delete database contents.',
                                'Use parameterized queries or prepared statements in all database '
                                'interactions. Never concatenate user input into SQL strings. '
                                'Consider using an ORM.',
                                evidence=f'SQL error signature "{sig}" found in response to payload: {payload}',
                                score=9.5
                            )
                            return  # one finding is enough
                except Exception:
                    pass

    # ── Check 6: XSS Reflection ───────────────────────────────────────────────

    def check_xss(self):
        """Test for reflected XSS by injecting a payload into URL parameters."""
        if '?' not in self.url:
            return

        base_url = self.url.split('?')[0]
        params_str = self.url.split('?')[1]
        params = {}
        for part in params_str.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
                params[k] = v

        test_params = {k: XSS_PAYLOAD for k in params}
        try:
            resp = self.session.get(base_url, params=test_params,
                                    timeout=TIMEOUT, verify=False)
            if XSS_PAYLOAD in resp.text:
                self._add_finding(
                    'Reflected XSS (Cross-Site Scripting) Indicator',
                    'High',
                    'A URL parameter appears to reflect user input directly into the HTML response '
                    'without sanitization. This is a strong indicator of reflected XSS, which '
                    'allows attackers to inject malicious scripts into pages viewed by other users.',
                    'Sanitize and HTML-encode all user-supplied input before rendering it in pages. '
                    'Implement a Content-Security-Policy header. Use a templating engine with '
                    'auto-escaping enabled.',
                    evidence=f'Payload reflected verbatim in response for param(s): {list(params.keys())}',
                    score=9.0
                )
        except Exception:
            pass

    # ── Check 7: Login Form Security ─────────────────────────────────────────

    def check_login_forms(self):
        """Detect login forms and check for security issues."""
        resp = self._get(self.url)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            inputs = form.find_all('input')
            has_password = any(
                i.get('type', '').lower() == 'password' for i in inputs
            )
            if not has_password:
                continue

            # Check 1: form submits over HTTP
            action = form.get('action', '')
            action_url = urljoin(self.url, action)
            if action_url.startswith('http://'):
                self._add_finding(
                    'Login Form Submits Over HTTP',
                    'High',
                    'A login form on this page submits credentials over an unencrypted HTTP '
                    'connection. Passwords are transmitted in plaintext and can be intercepted.',
                    'Ensure the login form action URL uses HTTPS. Redirect all HTTP traffic to HTTPS.',
                    evidence=f'Form action: {action_url}',
                    score=9.0
                )

            # Check 2: password field has autocomplete enabled
            for inp in inputs:
                if inp.get('type', '').lower() == 'password':
                    autocomplete = inp.get('autocomplete', '').lower()
                    if autocomplete not in ('off', 'new-password', 'current-password'):
                        self._add_finding(
                            'Password Field Autocomplete Enabled',
                            'Low',
                            'A password input field does not have autocomplete="off" set. '
                            'On shared computers, the browser may cache the password.',
                            'Add autocomplete="off" or autocomplete="new-password" to password fields.',
                            evidence='Password <input> missing autocomplete="off"',
                            score=3.0
                        )
                        break  # one finding per form

    # ── Check 8: Cookie Security ──────────────────────────────────────────────

    def check_cookies(self):
        """Inspect session cookies for security flags."""
        resp = self._get(self.url)
        if not resp:
            return

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append('missing Secure flag (cookie sent over HTTP)')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('missing HttpOnly flag (accessible via JavaScript)')
            samesite = cookie._rest.get('SameSite', '').lower()
            if samesite not in ('strict', 'lax'):
                issues.append('missing or weak SameSite attribute')

            if issues:
                self._add_finding(
                    f'Insecure Cookie: {cookie.name}',
                    'Medium',
                    f'The cookie "{cookie.name}" has security issues: {"; ".join(issues)}. '
                    f'Insecure cookies can be stolen or misused.',
                    'Set the Secure, HttpOnly, and SameSite=Strict or SameSite=Lax flags on '
                    'all cookies, especially session cookies.',
                    evidence=f'Cookie "{cookie.name}": {", ".join(issues)}',
                    score=5.5
                )

    # ── Check 9: Mixed Content ────────────────────────────────────────────────

    def check_mixed_content(self):
        """Check for HTTP resources loaded on an HTTPS page."""
        if self.parsed.scheme != 'https':
            return  # only relevant for HTTPS sites

        resp = self._get(self.url)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        mixed = []

        for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href'),
                           ('iframe', 'src'), ('video', 'src'), ('audio', 'src')]:
            for el in soup.find_all(tag):
                val = el.get(attr, '')
                if val.startswith('http://'):
                    mixed.append(f'<{tag} {attr}="{val[:80]}...">' if len(val) > 80
                                 else f'<{tag} {attr}="{val}">')
                    if len(mixed) >= 5:
                        break

        if mixed:
            self._add_finding(
                'Mixed Content (HTTP resources on HTTPS page)',
                'Medium',
                'The HTTPS page loads some resources over HTTP (mixed content). This weakens '
                'HTTPS protection and may cause browser warnings. Attackers could intercept '
                'the HTTP resources to inject malicious code.',
                'Change all resource URLs to HTTPS or use protocol-relative URLs (//example.com/...).',
                evidence='HTTP resources found:\n' + '\n'.join(mixed[:5]),
                score=5.0
            )

    # ── Main orchestrator ─────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Run all security checks.
        Returns dict with findings list and a computed risk score.
        """
        start = time.time()
        logger.info(f'Starting scan of {self.url}')

        # Suppress SSL warnings for intentional unverified requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Run each check module
        checks = [
            ('HTTPS/SSL',           self.check_https),
            ('Security Headers',    self.check_security_headers),
            ('Open Ports',          self.check_open_ports),
            ('Directory Exposure',  self.check_directory_exposure),
            ('SQL Injection',       self.check_sql_injection),
            ('XSS',                 self.check_xss),
            ('Login Forms',         self.check_login_forms),
            ('Cookies',             self.check_cookies),
            ('Mixed Content',       self.check_mixed_content),
        ]

        for name, fn in checks:
            try:
                logger.debug(f'Running check: {name}')
                fn()
            except Exception as e:
                logger.error(f'Check "{name}" failed: {e}')

        duration = time.time() - start
        risk_score = self._compute_risk_score()
        summary = self._build_summary()

        logger.info(f'Scan complete: {len(self.findings)} findings, '
                    f'risk score {risk_score:.1f}, duration {duration:.1f}s')

        return {
            'findings':    self.findings,
            'risk_score':  risk_score,
            'summary':     summary,
            'duration':    duration,
            'total_vulns': len(self.findings),
        }

    def _compute_risk_score(self) -> float:
        """
        Compute a 0–100 composite risk score.
        Weighted sum of severity scores, capped at 100.
        """
        if not self.findings:
            return 0.0
        weights = {'High': 3.0, 'Medium': 2.0, 'Low': 1.0}
        total = sum(
            f['severity_score'] * weights.get(f['risk_level'], 1.0)
            for f in self.findings
        )
        # Normalise: maximum theoretical score per finding is 10 * 3 = 30
        normalised = min(100.0, (total / (len(self.findings) * 30)) * 100)
        # Blend with raw total to reflect volume
        volume_factor = min(1.0, len(self.findings) / 20)
        return round(normalised * 0.7 + volume_factor * 100 * 0.3, 1)

    def _build_summary(self) -> str:
        counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for f in self.findings:
            counts[f['risk_level']] = counts.get(f['risk_level'], 0) + 1
        parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
        if not parts:
            return 'No vulnerabilities detected.'
        return f"Found {len(self.findings)} issue(s): {', '.join(parts)}."
