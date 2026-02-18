import requests

site = "http://localhost:3000"

headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

xss_payloads = [
    "<script>alert(1)</script>",
    "<u>test</u>",
]

sqli_payloads = [
    "'",
    "--",
    "') OR 1=1--",
]

sqli_errors = [
    "SQLITE_ERROR",
]

alerts = set()

counts = {
    "requests_total": 0,
    "xss_tests": 0,
    "sqli_tests": 0,
    "xss_flags": 0,
    "sqli_flags": 0,
    "config_flags": 0,
}

def show(endpoint, method, payload, status, length, note=""):
    print(f"[{method}] {endpoint} || payload: {payload} || status: {status} || len: {length}")

def flag(tag, message):
    key = f"{tag}:{message}"
    if key not in alerts:
        alerts.add(key)
        print(message)
        if tag == "CONFIG":
            counts["config_flags"] += 1
        elif tag == "XSS":
            counts["xss_flags"] += 1
        elif tag.startswith("SQLI"):
            counts["sqli_flags"] += 1

def check_for_headers(response, endpoint):
    missing = [h for h in headers if h not in response.headers]
    for h in missing:
        flag("CONFIG", f"[LOW] Missing header on {endpoint}: {h}")

def detect_xss(response, endpoint):
    if "<script>" in response.text:
        flag("XSS", f"[HIGH] XSS indicator on {endpoint} (found '<script>' in response)")

def detect_sqli(response, endpoint):
    if response.status_code >= 500:
        flag("SQLI_500", f"[HIGH] SQLi indicator on {endpoint} (HTTP {response.status_code})")

    body_uppercase = response.text.upper()
    for err in sqli_errors:
        if err in body_uppercase:
            flag("SQLI_ERR", f"[HIGH] SQLi indicator on {endpoint} (error marker: {err})")
            break

def run_scans(endpoint="/rest/products/search", param_name="q"):
    url = site + endpoint

    print("\n" + "=" * 40)
    print(f"[TARGET]: {url}")
    print("=" * 40)

    print("\n" + "=" * 40)
    print(f"[TESTS] XSS / SQLi injections on {endpoint} (param: {param_name})")
    print("=" * 40)

    # XSS
    for xp in xss_payloads:
        payload = {param_name: xp}
        try:
            r = requests.get(url, params=payload, timeout=5)
            show(endpoint, "GET", payload, r.status_code, len(r.content), "XSS Test")
            detect_xss(r, endpoint)
            check_for_headers(r, endpoint)
        except requests.RequestException as e:
            show(endpoint, "GET", payload, f"ERR: {e}", 0, "XSS Test Failed")

    # SQLi
    for sqlp in sqli_payloads:
        payload = {param_name: sqlp}
        try:
            r = requests.get(url, params=payload, timeout=5)
            show(endpoint, "GET", payload, r.status_code, len(r.content), "SQLi Test")
            detect_sqli(r, endpoint)
            check_for_headers(r, endpoint)
        except requests.RequestException as e:
            show(endpoint, "GET", payload, f"ERR: {e}", 0, "SQLi Test Failed")

def main():
    run_scans()
    print("\n" + "=" * 40)
    print("VULNERABILITY SUMMARY")
    print("=" * 40)

    print(f"Requests sent  : {counts['requests_total']}")
    print(f"XSS tests      : {counts['xss_tests']}")
    print(f"SQLi tests     : {counts['sqli_tests']}")
    print(f"alerts total   : {len(alerts)}")
    print(f"Config (LOW)   : {counts['config_flags']}")
    print(f"XSS (HIGH)     : {counts['xss_flags']}")
    print(f"SQL (HIGH)     : {counts['sqli_flags']}")

    print("\nScan Results:")
    if not alerts:
        print("  None flagged.")
    else:
        for a in sorted(alerts):
            print("  " + a.split(":", 1)[1])

if __name__ == "__main__":
    main()