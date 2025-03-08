import requests
import logging
from flask import Flask, request, Response, render_template
from ipaddress import ip_address, AddressValueError
import os
import sys

app = Flask(__name__)

app.template_folder = os.path.join(os.path.dirname(__file__), "templates")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

def format_host_for_requests(dst):
    try:
        host, port = dst.rsplit(":", 1)
        if ":" in host and isinstance(ip_address(host), ip_address):
            return f"[{host}]:{port}"
        return f"{host}:{port}"
    except (ValueError, AddressValueError):
        return dst

@app.route("/proxy", methods=["POST"])
def proxy():
    dst = request.headers.get("X-Original-Dst")
    original_host = request.headers.get("X-Original-Host")
    original_path = request.headers.get("X-Original-Path", "/")
    original_method = request.headers.get("X-Original-Method", "GET")

    if not dst:
        return render_template("error.html", error_message="Missing target address"), 400

    protocol = "https" if dst.endswith(":443") else "http"
    target_host = original_host.strip() if original_host and original_host.strip() else dst
    target_url = f"{protocol}://{target_host}{original_path}"

    logging.info(f"Received proxy request: {original_method} {target_host}{original_path}")
    logging.info(f"Target URL: {target_url}")

    try:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'x-original-method']}
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        headers["Host"] = target_host

        resp = requests.request(
            method=original_method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
            verify=False,
            stream=True
        )

        response_content = resp.raw.read()
        logging.info(f"Target server response: {resp.status_code}")
        return Response(response_content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        logging.error(f"Proxy request timeout: {target_url}")
        return render_template("error.html", error_message="Request timeout, please try again later"), 504
    except requests.RequestException as e:
        logging.error(f"Proxy request failed: {target_url}, Error: {str(e)}")
        return render_template("error.html", error_message=f"Proxy error: {str(e)}"), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)