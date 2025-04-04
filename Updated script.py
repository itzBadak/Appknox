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
        self.target_url = urlparse(target_url).geturl()
        self.session = requests.Session()
        self.vulnerable_urls = []
        self.payloads = self.generate_numbered_payloads()
        self.encoded_payloads = self.generate_encoded_payloads()
        self.captured_requests = []
        self.cookies = []
        self.csrf_token = None
        self.safe_fields = {"email", "phone", "password", "username", "dob", "website"}
        self.user_inputs = {}
        self.discovered_endpoints = set()

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

    def capture_xhr_requests_and_session(self):
        print("[+] Capturing XHR requests, CSRF tokens, and session cookies...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()
            page.goto(self.target_url, timeout=60000)

            def intercept_response(response):
                if response.request.resource_type == "xhr":
                    print(f"[XHR] Captured: {response.url}")
                    self.captured_requests.append(response.url)
                    self.discovered_endpoints.add(response.url)

            page.on("response", intercept_response)
            input("[+] login manually and press Enter after completion...")

            self.cookies = context.cookies()
            with open("cookies.json", "w") as f:
                json.dump(self.cookies, f)
            print("[+] Cookies saved.")

            try:
                csrf_token_element = page.query_selector("input[name='csrf_token']")
                if csrf_token_element:
                    self.csrf_token = csrf_token_element.input_value()
                    print(f"[+] CSRF Token Captured: {self.csrf_token}")
            except:
                print("[-] No CSRF token found.")
            
            browser.close()

    def inject_payload_into_forms(self):
        print("[+] Injecting payloads into detected forms...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            with open("cookies.json", "r") as f:
                context.add_cookies(json.load(f))

            page = context.new_page()
            page.goto(self.target_url, timeout=30000)
            page.wait_for_load_state("networkidle")

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
                        field.fill(self.user_inputs[field_name])
                    elif field.is_visible():
                        field.fill(self.payloads[0])
                
                if self.csrf_token:
                    csrf_input = form.query_selector("input[name='csrf_token']")
                    if csrf_input:
                        csrf_input.fill(self.csrf_token)
                
                submit_button = form.query_selector("button[type=submit], input[type=submit]")
                if submit_button:
                    submit_button.click()
                    page.wait_for_timeout(6000)
            browser.close()

    def scan_discovered_endpoints(self):
        print("[+] Scanning discovered endpoints...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            with open("cookies.json", "r") as f:
                context.add_cookies(json.load(f))
            
            page = context.new_page()

            for endpoint in self.discovered_endpoints:
                try:
                    print(f"[+] Checking: {endpoint}")
                    response = page.goto(endpoint, timeout=30000)
                    page.wait_for_timeout(5000)

                    if response.status != 200:
                        print(f"[-] Warning: Non-200 status code ({response.status}) for {endpoint}")
                        continue

                    for payload in self.payloads:
                        if payload in page.content():
                            print(f"[!!!] Stored XSS triggered at {endpoint} with payload: {payload}")
                            screenshot_name = f"xss_triggered_{int(time.time())}.png"
                            page.screenshot(path=screenshot_name)
                            print(f"[+] Screenshot saved as: {screenshot_name}")
                except Exception as e:
                    print(f"[!] Error visiting {endpoint}: {e}")
            browser.close()

    def run(self):
        self.capture_xhr_requests_and_session()
        self.inject_payload_into_forms()
        self.scan_discovered_endpoints()

if __name__ == "__main__":
    target = input("Enter target URL: ")
    scanner = StoredXSSScanner(target)
    scanner.run()
