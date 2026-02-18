import requests

site = "http://localhost:3000"

endpoints = [
    {"path": "/", "action": "GET"},
    {"path": "/rest/products/search", "action": "GET", "payloads": [{"q": "apple"}, {"q": "banana"}]},
    {"path": "/rest/admin/application-configuration", "action": "POST", "payloads": [{"application": {"name": "test"}}]},
    {"path": "/rest/user/login", "action": "POST", "payloads": [{"email": "doki999", "password": "P@ssW0rd"}]},
    {"path": "/api/Feedbacks", "action": "GET"},
]

headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

def show(endpoint, method, payload, status, length):
    print(f"[{method}] {endpoint} || payload: {payload} || status: {status} || len: {length}")

def check_for_headers(response, endpoint):
    missing = [h for h in headers if h not in response.headers]
    for h in missing:
        print(f"[LOW SEVERITY] Missing header on {endpoint}: {h}")

def get_req(endpoint, payload):
    url = site + endpoint
    for pld in payload:
        try:
            r = requests.get(url, params=pld, timeout=5)
            show(endpoint, "GET", pld, r.status_code, len(r.content))
            check_for_headers(r, endpoint)
        except requests.RequestException as e:
            show(endpoint, "GET", pld, f"ERR: {e}", 0)

def post_req(endpoint, payload):
    url = site + endpoint
    for pld in payload:
        try:
            r = requests.post(url, json=pld, timeout=5)
            show(endpoint, "POST", pld, r.status_code, len(r.content))
            check_for_headers(r, endpoint)
        except requests.RequestException as e:
            show(endpoint, "POST", pld, f"ERR {e}", 0)

def main():
    for ep in endpoints:
        path = ep["path"]
        action = ep["action"].upper()
        payloads = ep.get("payloads") or [{}]

        print("\n" + "=" * 40)
        print(f"[TARGET]: {site}{path}")
        print("=" * 40)

        if action == "GET":
            get_req(path, payloads)
        elif action == "POST":
            post_req(path, payloads)
        else:
            print(f"Unsupported action '{action}' for {path}")
if __name__ == "__main__":
    main()