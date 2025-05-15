#!/usr/bin/env python3
import sys, socket, requests, re, os, json
from urllib.parse import urlparse, urljoin
from subprocess import run
from shutil import which
from typing import Dict

requests.packages.urllib3.disable_warnings()

TECH_FINGERPRINTS: Dict[str, Dict[str, object]] = {
    'Apache': {'type': 'server', 'regex': r'Apache', 'tools': ['dirsearch', 'gobuster', 'nikto']},
    'nginx': {'type': 'server', 'regex': r'nginx', 'tools': ['ffuf', 'dirb', 'nmap']},
    'IIS': {'type': 'server', 'regex': r'Microsoft-IIS', 'tools': ['IIS shortname fuzz', 'nmap --script iis*']},
    'LiteSpeed': {'type': 'server', 'regex': r'LiteSpeed', 'tools': ['gobuster']},
    'PHP': {'type': 'powered', 'regex': r'PHP', 'tools': ['dalfox', 'phpggc', 'arjun']},
    'Express': {'type': 'powered', 'regex': r'Express', 'tools': ['NoSQLMap', 'jsfinder', 'xnLinkFinder', 'LinkFinder.py']},
    'ASP.NET': {'type': 'powered', 'regex': r'ASP.NET', 'tools': ['ysoserial.NET', 'viewstate analyzer']},
    'Java': {'type': 'cookie', 'regex': r'JSESSIONID', 'tools': ['J2EEScan', 'Struts2', 'SpringScan', '/jmx-console', '/invoker/readonly', '/actuator', '/console', '/admin-console']},
    'WordPress': {'type': 'meta', 'regex': r'WordPress', 'tools': ['wpscan', 'xmlrpc exploit', 'dirsearch']},
    'Drupal': {'type': 'meta', 'regex': r'Drupal', 'tools': ['droopescan', 'CVE-2018-7600']},
    'Cloudflare': {'type': 'header', 'regex': r'cloudflare', 'tools': ['dnsdumpster', 'shodan']},
}

BACKEND_FINGERPRINTS = {
    'PHP': {'header': [r'PHP'], 'html': [r'\.php', r'index\.php']},
    'ASP.NET': {'header': [r'ASP\.NET'], 'html': [r'\.aspx', r'WebResource\.axd']},
    'Java': {'header': [r'JSESSIONID'], 'html': [r'\.jsp', r'Spring Framework']},
    'Python': {'header': [r'Python'], 'html': [r'\.py', r'Django']},
    'Ruby': {'header': [r'_rails', r'Ruby'], 'html': [r'\.rb', r'Rails']},
    'Node.js': {'header': [r'Express'], 'html': [r'node_modules', r'Express']},
}

CONTEXTUAL_PATHS = {
    'Generic': [
        '/phpinfo.php', '/index.php.bak', '/config.php', '/.env', '/test.php', '/uploads', '/upload', '/data', '/backup.zip',
        '/wp-admin', '/wp-content', '/wp-login.php', '/xmlrpc.php', '/wp-json',
        '/user/login', '/sites/default/files', '/core/install.php',
        '/owa/auth/logon.aspx', '/web.config', '/trace.axd',
        '/WEB-INF/web.xml', '/admin', '/console', '/manager/html',
        '/debug', '/admin/login', '/settings.py',
        '/api', '/api/v1', '/swagger.json', '/openapi.json', '/graphql',
        '/login', '/.git/config', '/robots.txt', '/Dockerfile', '/.htaccess'
    ],
    'PHP': ['/phpinfo.php', '/index.php.bak', '/config.php', '/test.php'],
    'WordPress': ['/wp-login.php', '/wp-admin', '/wp-content'],
    'Drupal': ['/user/login', '/core/install.php'],
    'ASP.NET': ['/owa/auth/logon.aspx', '/web.config'],
    'Java': ['/WEB-INF/web.xml', '/manager/html'],
    'Python': ['/settings.py'],
}

def headers_to_string(headers):
    return "\n".join([f"{k}: {v}" for k, v in headers.items()])

def deep_detect_backend(headers, html):
    found = []
    text = headers_to_string(headers) + "\n" + html
    for tech, props in BACKEND_FINGERPRINTS.items():
        matched = False
        for regex in props.get('header', []):
            if re.search(regex, text, re.I):
                matched = True
        for regex in props.get('html', []):
            if re.search(regex, html, re.I):
                matched = True
        if matched:
            found.append(tech)
    return list(set(found))

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return "Unknown"

def fetch(url):
    try:
        return requests.get(url, timeout=8, verify=False)
    except:
        return None

def get_asn(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        d = r.json()
        return f"{d.get('org','Unknown')} - {d.get('city','')} {d.get('country','')}"
    except:
        return "Unknown"

def detect_tech(headers, html):
    found = []
    for tech, data in TECH_FINGERPRINTS.items():
        if data['type'] == 'server' and re.search(data['regex'], headers.get('Server',''), re.I):
            found.append((tech, 'Server'))
        if data['type'] == 'powered' and re.search(data['regex'], headers.get('X-Powered-By',''), re.I):
            found.append((tech, 'X-Powered-By'))
        if data['type'] == 'cookie' and re.search(data['regex'], headers.get('Set-Cookie',''), re.I):
            found.append((tech, 'Cookie'))
        if data['type'] == 'meta':
            metas = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', html, re.I)
            for m in metas:
                if re.search(data['regex'], m, re.I):
                    found.append((tech, 'Meta Tag'))
    if 'wp-content' in html:
        found.append(('WordPress', 'HTML Content'))
    return list(set(found))

def waf_detect(hostname):
    try:
        r = run(['wafw00f', hostname], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            if 'is behind' in line or 'has a' in line:
                return line
    except:
        return None
def path_fuzz(url, backend_langs):
    paths_to_check = set(CONTEXTUAL_PATHS['Generic'])  # default paths
    for lang in backend_langs:
        if lang in CONTEXTUAL_PATHS:
            paths_to_check.update(CONTEXTUAL_PATHS[lang])

    hits = []
    print("\n🔍 Contextual Path Fuzzing with SQLi Check:")
    for p in sorted(paths_to_check):
        full = urljoin(url, p)
        try:
            r = requests.get(full, timeout=5, verify=False)
            if r.status_code in [200, 403, 401] and len(r.text) > 50:
                print(f" ✅ Found path: {p} [{r.status_code}]")
                hits.append((p, r.status_code))

                # Run sqlmap if available
                if tool_exists("sqlmap"):
                    print(f" → Testing SQLi with sqlmap on: {full}")
                    try:
                        os.makedirs("output", exist_ok=True)
                        log_file = f"output/sqlmap_{p.strip('/').replace('/', '_')}.txt"
                        with open(log_file, "w") as out:
                            run(["sqlmap", "-u", full, "--batch", "--level=3", "--risk=2"],
                                stdout=out, stderr=out)
                        print(f"   [LOG] → Saved: {log_file}")
                    except Exception as e:
                        print(f"   ❌ sqlmap failed: {e}")
        except Exception as e:
            print(f"   ⚠️ Error on path {p}: {e}")
            continue

    if not hits:
        print(" ❌ No useful paths discovered.")
    return hits

def print_tools(techs):
    tools = set()
    for t, _ in techs:
        tools.update(TECH_FINGERPRINTS.get(t, {}).get('tools', []))
    tools = list(tools)[:5]
    print("\n🧨 Recommended Exploit Tools:")
    for t in tools:
        print(f" → {t}")

def tool_exists(tool):
    return which(tool) is not None

def run_exploit_tools(techs, target_url):
    # This function is basically a greatest-hits playlist of every open-source tool you might have installed.
    # It just tries everything it can find, based on the detected tech, and throws the kitchen sink at the target.
    # If you want to be honest, this isn't really "smart" automation—it's more like "run every tool you can get your hands on and hope something sticks."
    # If you want to impress anyone on GitHub, at least rename this to something like 'multi_tool_launcher' or 'open_source_tool_i_use'.
    print("\n🚀 Auto Exploit Runner (Real Tools):")
    for tech, _ in techs:
       
        # SQL Injection detection (generic across many techs)
        if tech in ['PHP', 'ASP.NET', 'Java', 'Express']:
            print(" → Running SQL injection scanner...")

            if tool_exists("sqlmap"):
                print(f" → Running sqlmap on: {target_url}")
                run(["sqlmap", "-u", target_url, "--batch", "--level=3", "--risk=2"])

            if tool_exists("nuclei"):
                print(f" → Running nuclei SQLi templates on: {target_url}")
                run(["nuclei", "-u", target_url, "-t", "vulnerabilities/sqli/", "-silent"])

            # Optional: quick scanner
            if tool_exists("sqliv"):
                print(f" → Running sqliv (lightweight sqli scanner)")
                run(["sqliv", "-u", target_url, "-d"])

        # WordPress
        if tech == 'WordPress' and tool_exists("wpscan"):
            print(f" → Running wpscan on {target_url}")
            run(["wpscan", "--url", target_url, "--enumerate", "vp"])

        # Drupal
        elif tech == 'Drupal' and tool_exists("droopescan"):
            print(f" → Running droopescan on {target_url}")
            run(["droopescan", "scan", "drupal", "-u", target_url])

        # PHP
        elif tech == 'PHP':
            if tool_exists("dalfox"):
                print(f" → Fuzzing PHP input with dalfox")
                run(["dalfox", "url", f"{target_url}/?q=test"])
            if tool_exists("phpggc"):
                print(f" → Checking for PHP unserialize gadgets via phpggc (manual inspection advised)")

        # Java
        elif tech == 'Java':
            if tool_exists("nuclei"):
                print(f" → Running nuclei CVE templates for Java-based vulns")
                run(["nuclei", "-u", target_url, "-t", "cves/", "-silent"])
            if tool_exists("ysoserial"):
                print(f" → ysoserial found (manual gadget crafting recommended)")

        # ASP.NET
        elif tech == 'ASP.NET':
            if tool_exists("ysoserial.net"):
                print(f" → ysoserial.NET available for ViewState exploit crafting (manual payload)")
            else:
                print(" → Consider using ViewStateDecoder or Burp extensions for deeper analysis.")

        # Node.js / Express
        elif tech == 'Express':
            print(" → Check for NoSQLi / prototype pollution using NoSQLMap, tplmap, or JSScan")

        # Django / Python
        elif tech == 'Python':
            print(" → Check for exposed DEBUG or SSRF with nuclei / custom SSRF payloads")
            if tool_exists("nuclei"):
                run(["nuclei", "-u", target_url, "-t", "exposures/", "-silent"])

        # Ruby on Rails
        elif tech == 'Ruby':
            print(" → Check for CVE-2019-5418 (file disclosure) manually or with custom script")

        # Cloudflare (BYPASS only, not exploit)
        elif tech == 'Cloudflare':
            print(" → Try DNSDumpster, Shodan, or bypasses via Censys / Subdomain bruteforce")



def recon(target):
    print(f"\n🔍 Target: {target}")
    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    url = parsed.geturl()
    hostname = parsed.hostname
    ip = resolve_ip(hostname)
    print(f" ├─ IP      : {ip}")

    results = {
        "server": "",
        "asn": "",
        "tech": [],
        "waf": "",
        "paths": [],
    }

    print("\n📶 Level 1: Basic Scan...")
    r = fetch(url)
    if r:
        results["server"] = r.headers.get("Server", "Unknown")
        techs = detect_tech(r.headers, r.text)
        results["tech"] = techs
        if techs:
            print(f" ✅ Found tech: {[t[0] for t in techs]}")
        else:
            print(" ❌ No backend tech found in basic.")
    else:
        print(" ❌ Could not connect.")
        return

    print("\n📡 Level 2: Medium Scan...")
    results["asn"] = get_asn(ip)
    print(f" ✅ ASN Info: {results['asn']}")

    print("\n💣 Level 3: Aggressive Scan...")
    results["waf"] = waf_detect(hostname)
    if results["waf"]:
        print(f" ✅ WAF Detected: {results['waf']}")
    else:
        print(" ❌ No WAF detected.")

    backend_langs = deep_detect_backend(r.headers, r.text)
    results["paths"] = path_fuzz(url, backend_langs)

    if results["paths"]:
        print(" ✅ Sensitive Paths Found:")
        for p, code in results["paths"]:
            print(f"   • {p} [{code}]")
    else:
        print(" ❌ No sensitive paths found.")

    if backend_langs:
        print("\n🧠 Backend Language Detection:")
        for b in backend_langs:
            print(f" → {b}")
        print("\n💣 Real Exploit Suggestions Based on Backend:")
        for b in backend_langs:
            tools = BACKEND_FINGERPRINTS.get(b, {}).get('tools', [])
            if tools:
                print(f" [ {b} ] Try: {', '.join(tools)}")
    else:
        print("\n❌ No backend language clearly detected.")

    if results['tech']:
        print_tools(results['tech'])
        print("\n🧠 Backend Technology Detected:")
        for tech, source in results['tech']:
            print(f" → {tech} (via {source})")
        run_exploit_tools(results['tech'], url)
    else:
        print(" ❌ No backend technologies detected.")

    print("\n📦 FINAL SUMMARY:")
    print(f" • Server  : {results['server']}")
    print(f" • IP      : {ip}")
    print(f" • ASN     : {results['asn']}")
    print(f" • Backend : {[t[0] for t in results['tech']] or 'Not Detected'}")
    print(f" • WAF     : {results['waf'] or 'Not Detected'}")
    print(f" • Paths   : {[p for p,_ in results['paths']] or 'None'}")

    try:
        os.makedirs('output', exist_ok=True)
        safe_host = hostname.replace('.', '_') if hostname else "unknown"
        out_file = f"output/{safe_host}_result.json"
        with open(out_file, 'w') as output_file:
            json.dump(results, output_file, indent=4)
        print(f"\n💾 Saved to: {out_file}")
    except Exception as e:
        print(f"❌ Failed to save output: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 smartrecon_backend.py <http(s)://target>")
        sys.exit(1)
    recon(sys.argv[1])

if __name__ == '__main__':
    main()
