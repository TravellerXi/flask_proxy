import requests
import logging
from flask import Flask, request, Response, render_template
from ipaddress import ip_address, AddressValueError
import os
import sys
import pydivert
import binascii
import re

# Flask proxy server address
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# Listen for all outbound TCP traffic on ports 80 and 443
FILTER_RULE = "tcp and (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443))"

def hex_dump(data, length=500):
    """Convert data to a hex string to prevent encoding issues."""
    return binascii.hexlify(data[:length]).decode("utf-8") if data else "No Data"

def extract_sni(tls_data):
    """Extract SNI (Server Name Indication) from TLS ClientHello more robustly."""
    try:
        if len(tls_data) > 5 and tls_data[0] == 0x16 and tls_data[5] == 0x01:  # TLS Handshake + ClientHello
            print(f"🧐 TLS Data Detected (Length: {len(tls_data)})")
            session_id_length = tls_data[43]  # Session ID Length at byte 43
            extensions_start = 44 + session_id_length  # Start of extensions

            # Skip Cipher Suites
            cipher_suites_length = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2 + cipher_suites_length

            # Skip Compression Methods
            compression_methods_length = tls_data[extensions_start]
            extensions_start += 1 + compression_methods_length

            # Start of Extensions
            extensions_length = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
            extensions_start += 2

            while extensions_start < len(tls_data) - 4:
                ext_type = int.from_bytes(tls_data[extensions_start:extensions_start + 2], "big")
                ext_length = int.from_bytes(tls_data[extensions_start + 2:extensions_start + 4], "big")
                if ext_type == 0x00 and ext_length > 5:  # SNI Extension
                    sni_list_length = int.from_bytes(tls_data[extensions_start + 4:extensions_start + 6], "big")
                    if sni_list_length > 0 and tls_data[extensions_start + 6] == 0x00:  # Type: 0x00 (SNI)
                        sni_length = int.from_bytes(tls_data[extensions_start + 7:extensions_start + 9], "big")
                        extracted_sni = tls_data[extensions_start + 9:extensions_start + 9 + sni_length].decode()
                        print(f"✅ Extracted SNI: {extracted_sni}")
                        return extracted_sni
                extensions_start += 4 + ext_length  # Move to next extension
    except Exception as e:
        print(f"❌ SNI extraction failed: {e}")
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
    display_host = hostname or dst_ip
    if not hostname:
        print(f"⚠ WARNING: No hostname extracted for {packet.dst_addr}, using IP instead.")
        hostname = packet.dst_addr
    headers = {
        "X-Original-Dst": f"{dst_ip}:{packet.dst_port}",
        "X-Original-Host": hostname,
        "X-Original-Path": http_path,
        "Content-Type": "application/octet-stream"
    }
    print(f"📢 Sending Request to Flask: X-Original-Host={headers['X-Original-Host']}, X-Original-Dst={headers['X-Original-Dst']}")
    try:
        response = requests.post(FLASK_PROXY, data=packet.raw, headers=headers, timeout=5)
        print(f"📦 [RECV] Target: {display_host}:{packet.dst_port} | Status Code: {response.status_code}")
        return response.content
    except requests.Timeout:
        print(f"⏳ [TIMEOUT] Target: {display_host}:{packet.dst_port} | Request timeout")
        return packet.raw
    except requests.ConnectionError:
        print(f"🚫 [ERROR] Target: {display_host}:{packet.dst_port} | Connection failed")
        return packet.raw
    except requests.RequestException as e:
        print(f"⚠ [ERROR] Target: {display_host}:{packet.dst_port} | Proxy request failed: {e}")
        return packet.raw

with pydivert.WinDivert(FILTER_RULE) as w:
    print("🚀 Transparent proxy started, intercepting HTTP/HTTPS traffic...")
    for packet in w:
        try:
            if packet.tcp and packet.payload:
                direction = "⬆ OUT" if packet.is_outbound else "⬇ IN"
                hostname = None
                http_path = "/"
                if packet.dst_port == 80:
                    hostname = extract_hostname_from_http(packet.payload)
                    http_path = extract_http_path(packet.payload)
                elif packet.dst_port == 443:
                    hostname = extract_sni(packet.payload)
                    http_path = "/"  # TLS packets don't include HTTP paths
                dst_display = f"{hostname}:{packet.dst_port}" if hostname else f"{packet.dst_addr}:{packet.dst_port}"
                print(f"🔄 {direction} {packet.src_addr}:{packet.src_port} → {dst_display} (Size: {len(packet.payload)} bytes)")
                modified_payload = send_to_flask(packet, hostname, http_path)
                if modified_payload:
                    packet.payload = modified_payload
                else:
                    print(f"⚠ [EMPTY] Target: {dst_display} | Proxy returned empty data, discarding packet")
            w.send(packet)
        except Exception as e:
            print(f"⚠ [ERROR] Target: {dst_display} | Error processing packet: {e}")