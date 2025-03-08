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
    dst = request.headers.get("X-Original-Dst")  # Target IP (for access)
    original_host = request.headers.get("X-Original-Host")  # Original domain (for Host header)

    if not dst:
        app.logger.warning("Missing X-Original-Dst header")
        return render_template("error.html", error_message="Missing target address"), 400

    formatted_dst = format_host_for_requests(dst)  # Ensure IPv6 formatting
    target_path = request.path  # Get original path
    query_string = request.query_string.decode()  # Get query parameters
    target_url = f"http://{formatted_dst}{target_path}" + (f"?{query_string}" if query_string else "")
    display_host = original_host or dst  # Used for logging

    app.logger.info(f"Received proxy request: {request.method} {display_host}{target_path}")

    # Log request details
    app.logger.info(f"Target URL: {target_url}")
    app.logger.info(f"Request headers: {dict(request.headers)}")
    if request.get_data():
        app.logger.info(f"Request body: {request.get_data().decode(errors='ignore')}")

    try:
        # Copy headers and replace Host header
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        if original_host:
            headers["Host"] = original_host  # Ensure server recognizes the original domain

        # Proxy request
        resp = requests.request(
            method=request.method,  # Forward original HTTP method
            url=target_url,  # Target URL
            headers=headers,  # Modified headers
            data=request.get_data(),  # Copy body
            cookies=request.cookies,  # Copy cookies
            allow_redirects=False,  # Disable automatic redirects
            timeout=10  # Timeout duration
        )

        # Log response details
        app.logger.info(f"Target server response: {resp.status_code}")
        app.logger.info(f"Response headers: {dict(resp.headers)}")
        if resp.content:
            app.logger.info(f"Response body: {resp.content[:500].decode(errors='ignore')}...")  # Avoid large logs

        # Return proxy response
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        app.logger.error(f"Proxy request timeout: {target_url}")
        return render_template("error.html", error_message="Request timeout, please try again later"), 504
    except requests.RequestException as e:
        app.logger.error(f"Proxy request failed: {target_url}, Error: {str(e)}")
        return render_template("error.html", error_message=f"Proxy error: {str(e)}"), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)