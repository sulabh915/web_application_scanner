import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import hashlib

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable_to_sql_injection(response):
    errors = {
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated"
    }
    for error in errors:
        if error in response.text.lower():
            return True
    return False

def test_sql_injection(url):
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for c in "'\"":
            data = {}
            for input in details["inputs"]:
                if input["name"]:
                    data[input["name"]] = f"test{c}"
            url_action = urljoin(url, details["action"])
            if details["method"] == "post":
                res = requests.post(url_action, data=data)
            else:
                res = requests.get(url_action, params=data)
            if is_vulnerable_to_sql_injection(res):
                print(f"[!] SQL Injection vulnerability detected in form: {details}")
                break

def test_xss(url):
    forms = get_forms(url)
    js_script = "<script>alert('xss')</script>"
    for form in forms:
        details = get_form_details(form)
        data = {}
        for input in details["inputs"]:
            if input["name"]:
                data[input["name"]] = js_script
        url_action = urljoin(url, details["action"])
        if details["method"] == "post":
            res = requests.post(url_action, data=data)
        else:
            res = requests.get(url_action, params=data)
        if js_script in res.text:
            print(f"[!] XSS vulnerability detected in form: {details}")
            break

def test_open_redirect(url):
    test_url = urljoin(url, "/redirect?next=http://evil.com")
    try:
        res = requests.get(test_url, allow_redirects=False)
        if 'Location' in res.headers and 'evil.com' in res.headers['Location']:
            print(f"[!] Open Redirect vulnerability found at: {test_url}")
    except Exception as e:
        pass

def test_clickjacking(url):
    try:
        res = requests.get(url)
        if 'x-frame-options' not in res.headers:
            print(f"[!] Clickjacking vulnerability (missing X-Frame-Options) at: {url}")
    except Exception:
        pass

def test_server_info_leakage(url):
    try:
        res = requests.get(url)
        headers_to_check = ["Server", "X-Powered-By"]
        for header in headers_to_check:
            if header in res.headers:
                print(f"[!] Information Disclosure: {header} = {res.headers[header]}")
    except Exception:
        pass

def test_csrf_token(url):
    forms = get_forms(url)
    for form in forms:
        inputs = [i.get('name', '') for i in form.find_all('input')]
        if not any("csrf" in i.lower() for i in inputs):
            print(f"[!] Potential CSRF vulnerability (no CSRF token found) in form: {form}")

def test_authentication_headers(url):
    try:
        res = requests.get(url)
        if 'Set-Cookie' in res.headers:
            cookie = res.headers['Set-Cookie']
            if 'HttpOnly' not in cookie or 'Secure' not in cookie:
                print(f"[!] Authentication cookie missing HttpOnly or Secure flag: {cookie}")
    except Exception:
        pass

def test_insecure_http(url):
    if urlparse(url).scheme != 'https':
        print(f"[!] Insecure protocol used: {url}")

def test_sensitive_data_exposure(url):
    try:
        res = requests.get(url)
        if 'password' in res.text.lower() or 'ssn' in res.text.lower():
            print(f"[!] Sensitive data exposure detected at: {url}")
    except Exception:
        pass

def main():
    url = input("Enter the URL to scan: ").strip()
    if not url.startswith("http"):
        print("Invalid URL. Make sure it starts with http or https.")
        return

    print("[*] Starting scan for OWASP Top 10 vulnerabilities...")
    test_sql_injection(url)
    test_xss(url)
    test_open_redirect(url)
    test_clickjacking(url)
    test_server_info_leakage(url)
    test_csrf_token(url)
    test_authentication_headers(url)
    test_insecure_http(url)
    test_sensitive_data_exposure(url)
    print("[*] Scan completed.")

if __name__ == '__main__':
    main()

