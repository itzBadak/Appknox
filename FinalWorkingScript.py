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
        self.target_url = urlparse(target_url).geturl()  # Keep fragments for scanning
        self.session = requests.Session()
        self.vulnerable_urls = []
        self.payloads = self.generate_numbered_payloads()
        self.encoded_payloads = self.generate_encoded_payloads()
        self.captured_requests = []  # Store intercepted requests
        self.cookies = {}  # Store captured cookies and tokens
        self.safe_fields = {"email", "phone", "password", "username", "dob", "website"}  # Fields to avoid injecting
        self.user_inputs = {}  # Store user inputs for required fields
        self.discovered_endpoints = set()  # Store new discovered URLs including fragments
    
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
    
    def capture_xhr_requests(self):
        print("[+] Opening browser for manual login. Capturing XHR requests and session tokens...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)  # Allow manual login
            context = browser.new_context()
            page = context.new_page()
            
            def intercept_response(response):
                if response.request.resource_type == "xhr":
                    print(f"[XHR] Captured: {response.url}")
                    self.captured_requests.append(response.url)
                    self.discovered_endpoints.add(response.url)  # Save for further scanning
            
            page.on("response", intercept_response)
            page.goto(self.target_url, timeout=60000)
            input("[+] Press Enter after logging in...")
            
            # Capture cookies
            self.cookies = context.cookies()
            print("[+] Captured Cookies: ", self.cookies)
            
            browser.close()
    
    def inject_payload_into_forms(self):
        print("[+] Injecting payloads into detected forms...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            page.goto(self.target_url, timeout=30000)
            
            forms = page.query_selector_all("form")
            if not forms:
                print("[-] No forms found to inject payloads.")
                return
            
            for form in forms:
                inputs = form.query_selector_all("input, textarea")
                for field in inputs:
                    field_name = field.get_attribute("name") or ""
                    if any(keyword in field_name.lower() for keyword in self.safe_fields):
                        if field_name not in self.user_inputs:
                            self.user_inputs[field_name] = input(f"Enter value for {field_name}: ")
                        field.fill(self.user_inputs[field_name])  # Fill required fields correctly
                    elif field.is_visible():
                        field.fill(self.payloads[0])  # Inject XSS payload in vulnerable fields
                
                submit_button = form.query_selector("button[type=submit], input[type=submit]")
                if submit_button:
                    submit_button.click()
                    page.wait_for_timeout(3000)
            
            browser.close()
    
    def scan_discovered_endpoints(self):
        print("[+] Scanning discovered endpoints including fragments...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            for endpoint in self.discovered_endpoints:
                print(f"[+] Checking: {endpoint}")
                page.goto(endpoint, timeout=30000)
                page.wait_for_timeout(5000)
                
                for payload in self.payloads:
                    if payload in page.content():
                        print(f"[!!!] Stored XSS triggered at {endpoint} with payload: {payload}")
            
            browser.close()
    
    def run(self):
        self.capture_xhr_requests()  # Start capturing login tokens first
        self.inject_payload_into_forms()  # Test forms after login
        self.scan_discovered_endpoints()  # Check discovered URLs, including fragments
        
if __name__ == "__main__":
    target = input("Enter target URL: ")
    scanner = StoredXSSScanner(target)
    scanner.run()
