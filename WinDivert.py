import pydivert
import requests
import binascii
import re
from ipaddress import ip_address, AddressValueError

# Flask proxy server address
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# Listen for all outbound TCP traffic on ports 80 and 443
FILTER_RULE = "tcp and (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443))"


def extract_http_method(data):
    """Extract HTTP Method (GET, POST, etc.)"""
    try:
        match = re.search(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ", data, re.IGNORECASE)
        if match:
            return match.group(1).decode()
    except Exception:
        pass
    return "GET"  # Default to GET if method cannot be extracted


def extract_hostname_from_http(data):
    """Extract Host from HTTP headers."""
    try:
        match = re.search(rb"Host:\s*([^\r\n]+)", data, re.IGNORECASE)
        if match:
            return match.group(1).decode()
    except Exception:
        pass
    return None


def extract_http_path(data):
    """Extract the full HTTP request path."""
    try:
        match = re.search(rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/", data, re.IGNORECASE)
        if match:
            return match.group(2).decode()
    except Exception:
        pass
    return "/"


def send_to_flask(packet, hostname, http_path):
    """Send the intercepted packet to the Flask proxy."""
    dst_ip = packet.dst_addr
    extracted_http_method = extract_http_method(packet.payload)

    headers = {
        "X-Original-Dst": f"{dst_ip}:{packet.dst_port}",
        "X-Original-Host": hostname or dst_ip,
        "X-Original-Path": http_path,
        "X-Original-Method": extracted_http_method,
        "Content-Type": "application/octet-stream"
    }

    print(
        f"📢 Sending Request to Flask: Method={extracted_http_method}, X-Original-Host={headers['X-Original-Host']}, X-Original-Dst={headers['X-Original-Dst']}")

    try:
        response = requests.post(FLASK_PROXY, headers=headers, data=packet.raw, timeout=5)
        return response.content
    except requests.RequestException:
        return packet.raw


with pydivert.WinDivert(FILTER_RULE) as w:
    print("🚀 Transparent proxy started, intercepting HTTP/HTTPS traffic...")
    for packet in w:
        try:
            if packet.tcp and packet.payload:
                hostname = None
                http_path = "/"
                if packet.dst_port == 80:
                    hostname = extract_hostname_from_http(packet.payload)
                    http_path = extract_http_path(packet.payload)
                elif packet.dst_port == 443:
                    hostname = None  # HTTPS does not contain direct hostname in payload
                    http_path = "/"

                modified_payload = send_to_flask(packet, hostname, http_path)
                if modified_payload:
                    packet.payload = modified_payload
            w.send(packet)
        except Exception:
            pass