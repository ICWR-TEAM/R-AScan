import requests, re, os, socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.exceptions import SSLError, ConnectionError
from r_ascan.config import HTTP_HEADERS, DEFAULT_TIMEOUT
from r_ascan.module.other import Other

class WebExtractor:
    def __init__(self, args):
        self.target = args.target
        self.headers = HTTP_HEADERS
        self.timeout = DEFAULT_TIMEOUT
        self.DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 3000, 3001]
        self.tld_regex = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:dev|stg|prod|local|com|net|org|edu|gov|mil|biz|xyz|co|us)\b')
        self.ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.leak_creds_regex = re.compile(r'(?i)((api_key|username|password|access_key|access_token)[a-z0-9_ .\-,@]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}["\']([0-9a-zA-Z\-_=@!#\$%\^&\*\(\)\+\[\]\{\}\|;:,<>\?~`]{1,64})["\']')
        self.cookie_regex = re.compile(r'document\.cookie\s*=\s*["\']([^"\']+)["\'];', re.IGNORECASE)
        self.local_storage_regex = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)
        self.ox_regex = re.compile(r'\b\w+(?:\.\w+)?\s*\(\s*["\']([^"\']+)["\']\s*,\s*(["\'][^"\']*["\']|{[^}]*}|[^,)]+)', re.IGNORECASE)
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()

    def is_port_open(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except:
            return False

    def detect_scheme(self, host, port):
        try:
            url = f"http://{host}:{port}"
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            return resp.url
        except SSLError:
            try:
                url = f"https://{host}:{port}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True, verify=False)
                return resp.url
            except:
                return None
        except:
            return None

    def extract(self, url):
        result = {}
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout * 2, allow_redirects=True, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            result['final_url'] = resp.url
            result['status_code'] = resp.status_code
            result['links'] = [urljoin(url, a.get('href')) for a in soup.find_all(['a', 'link']) if a.get('href')]
            result['images'] = [urljoin(url, img.get('src')) for img in soup.find_all('img') if img.get('src')]
            result['cookies'] = [f"{c.name}={c.value}" for c in resp.cookies]
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action'),
                    'method': form.get('method'),
                    'inputs': [{
                        'name': inp.get('name'),
                        'type': inp.get('type'),
                        'value': inp.get('value')
                    } for inp in form.find_all('input')]
                }
                forms.append(form_data)
            result['forms'] = forms
            scripts = [urljoin(url, s.get('src')) for s in soup.find_all('script') if s.get('src')]
            js_urls = set()
            domains = set()
            ips = set()
            leaked_creds = []
            js_cookies = []
            local_storage = []
            ox_patterns = []
            for script in scripts:
                try:
                    js_resp = requests.get(script, headers=self.headers, timeout=self.timeout, verify=False)
                    js_text = js_resp.text
                    js_urls.update(re.findall(r'https?://[^\s\'"<>]+', js_text))
                    domains.update(self.tld_regex.findall(js_text))
                    ips.update(self.ip_regex.findall(js_text))
                    leaked_creds.extend(self.leak_creds_regex.findall(js_text))
                    js_cookies.extend(self.cookie_regex.findall(js_text))
                    local_storage.extend(self.local_storage_regex.findall(js_text))
                    ox_patterns.extend(self.ox_regex.findall(js_text))
                except:
                    continue
            result['js_urls'] = list(js_urls)
            result['domains'] = list(domains)
            result['ips'] = list(ips)
            result['leaked_creds'] = leaked_creds
            result['js_cookies'] = js_cookies
            result['local_storage'] = local_storage
            result['ox_patterns'] = ox_patterns
        except Exception as e:
            result['error'] = str(e)
        return result

    def run(self):
        target = self.target
        open_ports = [port for port in self.DEFAULT_PORTS if self.is_port_open(target, port)]
        scanned_services = []
        colored_module = self.printer.color_text(self.module_name, "cyan")

        for port in open_ports:
            final_url = self.detect_scheme(target, port)
            if final_url:
                colored_url = self.printer.color_text(final_url, "yellow")
                print(f"[*] [Module: {colored_module}] [Scan URL: {colored_url}]")
                extract_result = self.extract(final_url)
                scanned_services.append({
                    "port": port,
                    "url": final_url,
                    "data": extract_result
                })

        return {
            "open_ports": open_ports,
            "services": scanned_services
        }

def scan(args=None):
    return WebExtractor(args).run()
