import requests
import logging
from flask import Flask, request, Response, render_template
from ipaddress import ip_address, AddressValueError
import os
import sys

# Initialize Flask
app = Flask(__name__)

# Set template folder
app.template_folder = os.path.join(os.path.dirname(__file__), "templates")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log", encoding="utf-8"),  # Log file
        logging.StreamHandler(sys.stdout)  # Terminal output
    ]
)

def format_host_for_requests(dst):
    """Fix IPv6 address formatting for requests."""
    try:
        host, port = dst.rsplit(":", 1)
        if ":" in host and isinstance(ip_address(host), ip_address):  # IPv6
            return f"[{host}]:{port}"
        return f"{host}:{port}"
    except (ValueError, AddressValueError):
        return dst  # Return original value if formatting fails

@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy():
    dst = request.headers.get("X-Original-Dst")  # Target IP
    original_host = request.headers.get("X-Original-Host")  # Original domain
    original_path = request.headers.get("X-Original-Path", "/")  # Default to "/"

    if not dst:
        app.logger.warning("Missing X-Original-Dst header")
        return render_template("error.html", error_message="Missing target address"), 400

    formatted_dst = format_host_for_requests(dst)  # Ensure IPv6 correctness
    protocol = "https" if formatted_dst.endswith(":443") else "http"  # Determine protocol

    # Use original_host if available, otherwise fallback to formatted_dst
    target_host = original_host if original_host else formatted_dst
    target_url = f"{protocol}://{target_host}{original_path}"

    app.logger.info(f"Received proxy request: {request.method} {target_host}{original_path}")
    app.logger.info(f"Target URL: {target_url}")

    try:
        # Copy headers and replace Host header
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        headers["Host"] = target_host  # Ensure correct Host header

        # Proxy request with corrected URL, disable SSL certificate validation
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
            verify=False  # Disable SSL certificate verification
        )

        app.logger.info(f"Target server response: {resp.status_code}")
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        app.logger.error(f"Proxy request timeout: {target_url}")
        return render_template("error.html", error_message="Request timeout, please try again later"), 504
    except requests.RequestException as e:
        app.logger.error(f"Proxy request failed: {target_url}, Error: {str(e)}")
        return render_template("error.html", error_message=f"Proxy error: {str(e)}"), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)