import pydivert
import requests
import binascii
import re
from ipaddress import ip_address, AddressValueError

# Flask proxy server address
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# Listen for all outbound TCP traffic on ports 80 and 443
FILTER_RULE = "tcp and (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443))"

def hex_dump(data, length=500):
    """Convert data to a hex string to prevent encoding issues."""
    return binascii.hexlify(data[:length]).decode("utf-8") if data else "No Data"

def extract_sni(tls_data):
    """Extract SNI (Server Name Indication) from TLS ClientHello."""
    try:
        if len(tls_data) > 5 and tls_data[0] == 0x16 and tls_data[5] == 0x01:  # TLS Handshake + ClientHello
            session_id_length = tls_data[43]  # Session ID Length
            extensions_start = 44 + session_id_length  # Start of extensions

            cipher_suites_length = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2 + cipher_suites_length

            compression_methods_length = tls_data[extensions_start]
            extensions_start += 1 + compression_methods_length

            extensions_length = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2

            while extensions_start < len(tls_data) - 4:
                ext_type = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
                ext_length = int.from_bytes(tls_data[extensions_start + 2:extensions_start + 4], "big")
                if ext_type == 0x00 and ext_length > 5:
                    sni_list_length = int.from_bytes(tls_data[extensions_start + 4:extensions_start + 6], "big")
                    if sni_list_length > 0 and tls_data[extensions_start + 6] == 0x00:
                        sni_length = int.from_bytes(tls_data[extensions_start + 7:extensions_start + 9], "big")
                        return tls_data[extensions_start + 9:extensions_start + 9 + sni_length].decode()
                extensions_start += 4 + ext_length
    except Exception:
        pass
    return None

def extract_hostname_from_http(data):
    """Extract Host from HTTP headers."""
    try:
        match = re.search(rb"Host:\s*([^\r\n]+)", data, re.IGNORECASE)
        if match:
            return match.group(1).decode()
    except Exception:
        pass
    return None

def send_to_flask(packet, hostname):
    """Send the intercepted packet to the Flask proxy with full HTTPS/TCP support."""
    dst_ip = packet.dst_addr
    display_host = hostname or dst_ip
    headers = {
        "X-Original-Dst": f"{dst_ip}:{packet.dst_port}",
        "X-Original-Host": hostname or dst_ip,
        "Content-Type": "application/octet-stream"
    }

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
                if packet.dst_port == 80:
                    hostname = extract_hostname_from_http(packet.payload)
                elif packet.dst_port == 443:
                    hostname = extract_sni(packet.payload)
                modified_payload = send_to_flask(packet, hostname)
                if modified_payload:
                    packet.payload = modified_payload
            w.send(packet)
        except Exception:
            pass