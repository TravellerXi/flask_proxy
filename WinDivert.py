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
    return "GET"  # Default to GET

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

def extract_sni(data):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(data) > 5 and data[0] == 0x16 and data[5] == 0x01:  # TLS Handshake + ClientHello
            session_id_length = data[43]
            extensions_start = 44 + session_id_length

            # Skip Cipher Suites
            cipher_suites_length = int.from_bytes(data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2 + cipher_suites_length

            # Skip Compression Methods
            compression_methods_length = data[extensions_start]
            extensions_start += 1 + compression_methods_length

            # Start of Extensions
            extensions_length = int.from_bytes(data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2

            while extensions_start < len(data) - 4:
                ext_type = int.from_bytes(data[extensions_start:extensions_start + 2], "big")
                ext_length = int.from_bytes(data[extensions_start + 2:extensions_start + 4], "big")
                if ext_type == 0x00 and ext_length > 5:  # SNI Extension
                    sni_length = int.from_bytes(data[extensions_start + 9:extensions_start + 11], "big")
                    extracted_sni = data[extensions_start + 11:extensions_start + 11 + sni_length].decode()
                    print(f"✅ Extracted SNI: {extracted_sni}")
                    return extracted_sni
                extensions_start += 4 + ext_length
    except Exception:
        pass
    return None

def send_to_flask(packet, hostname, http_path):
    """Send the intercepted packet to the Flask proxy."""
    dst_ip = packet.dst_addr
    extracted_http_method = extract_http_method(packet.payload)

    if not hostname:
        print(f"⚠ WARNING: No hostname extracted for {packet.dst_addr}, using IP instead.")
        hostname = packet.dst_addr  # Fallback to IP if hostname is missing

    headers = {
        "X-Original-Dst": f"{dst_ip}:{packet.dst_port}",
        "X-Original-Host": hostname,
        "X-Original-Path": http_path,
        "X-Original-Method": extracted_http_method,
        "Content-Type": "application/octet-stream"
    }

    print(f"📢 Sending Request to Flask: Method={extracted_http_method}, X-Original-Host={headers['X-Original-Host']}, X-Original-Dst={headers['X-Original-Dst']}")

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
                    hostname = extract_sni(packet.payload)  # Extract SNI from TLS ClientHello
                    http_path = "/"

                modified_payload = send_to_flask(packet, hostname, http_path)
                if modified_payload:
                    packet.payload = modified_payload
            w.send(packet)
        except Exception:
            pass
