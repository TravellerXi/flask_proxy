import pydivert
import requests
import binascii
import re
from ipaddress import ip_address, AddressValueError

# Flask 代理服务器地址
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# 监听所有 TCP 80/443 端口的流量
FILTER_RULE = "tcp and (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443))"

def hex_dump(data, length=500):
    """将数据转换为十六进制字符串，防止乱码"""
    return binascii.hexlify(data[:length]).decode("utf-8") if data else "No Data"

def extract_sni(tls_data):
    """提取 TLS ClientHello 中的 SNI (Server Name Indication)"""
    try:
        if len(tls_data) > 5 and tls_data[0] == 0x16 and tls_data[5] == 0x01:  # TLS 记录 & ClientHello
            extensions_start = tls_data.find(b"\x00\x00") + 4
            if extensions_start > 4:
                while extensions_start < len(tls_data) - 4:
                    ext_type = int.from_bytes(tls_data[extensions_start:extensions_start+2], "big")
                    ext_length = int.from_bytes(tls_data[extensions_start+2:extensions_start+4], "big")
                    if ext_type == 0x00 and ext_length > 5:  # SNI 扩展
                        sni_length = int.from_bytes(tls_data[extensions_start+7:extensions_start+9], "big")
                        return tls_data[extensions_start+9:extensions_start+9+sni_length].decode()
                    extensions_start += ext_length + 4
    except Exception:
        pass
    return None

def extract_hostname_from_http(data):
    """从 HTTP 头部解析 Host"""
    try:
        match = re.search(rb"Host:\s*([^\r\n]+)", data, re.IGNORECASE)
        if match:
            return match.group(1).decode()
    except Exception:
        pass
    return None

def format_dst_url(ip, port):
    """修正 IPv6 地址格式，确保正确解析"""
    try:
        if ":" in ip and isinstance(ip_address(ip), ip_address):  # IPv6
            return f"http://[{ip}]:{port}"
        else:
            return f"http://{ip}:{port}"
    except AddressValueError:
        return f"http://{ip}:{port}"

def send_to_flask(packet, hostname):
    """将拦截的完整数据包发送到 Flask 代理"""
    dst_ip = packet.dst_addr
    dst_url = format_dst_url(dst_ip, packet.dst_port)  # IP 形式的目标
    display_host = hostname or dst_ip  # 日志显示的域名或 IP

    try:
        headers = {
            "X-Original-Dst": f"{dst_ip}:{packet.dst_port}",  # 仍然使用 IP 访问目标
            "X-Original-Host": hostname or dst_ip,  # 额外传递 Host
            "Content-Type": "application/octet-stream"
        }

        # 记录原始数据包内容（防止日志太长，截取前 500 字节）
        payload_hex = hex_dump(packet.raw)
        print(f"📦 [SEND] 目标: {display_host}:{packet.dst_port} (访问 {dst_url}) | HEX(前 500 字节): {payload_hex}...")

        response = requests.post(FLASK_PROXY, data=packet.raw, headers=headers, timeout=5)

        # 记录代理服务器返回的数据（同样截取前 500 字节）
        response_hex = hex_dump(response.content)
        print(f"📦 [RECV] 目标: {display_host}:{packet.dst_port} | 状态码: {response.status_code} | HEX(前 500 字节): {response_hex}...")

        return response.content
    except requests.Timeout:
        print(f"⏳ [TIMEOUT] 目标: {display_host}:{packet.dst_port} | 请求超时")
        return packet.raw
    except requests.ConnectionError:
        print(f"🚫 [ERROR] 目标: {display_host}:{packet.dst_port} | 连接失败")
        return packet.raw
    except requests.RequestException as e:
        print(f"⚠ [ERROR] 目标: {display_host}:{packet.dst_port} | 代理请求失败: {e}")
        return packet.raw  # 代理失败时，返回原始数据包

# 监听 TCP 流量并转发
with pydivert.WinDivert(FILTER_RULE) as w:
    print("🚀 透明代理已启动，拦截 HTTP/HTTPS 流量中...")

    for packet in w:
        try:
            if packet.tcp and packet.payload:
                direction = "⬆ OUT" if packet.is_outbound else "⬇ IN"

                # **获取域名**
                hostname = None
                if packet.dst_port == 80:
                    hostname = extract_hostname_from_http(packet.payload)  # HTTP 解析 Host
                elif packet.dst_port == 443:
                    hostname = extract_sni(packet.payload)  # HTTPS 解析 SNI

                dst_display = f"{hostname}:{packet.dst_port}" if hostname else f"{packet.dst_addr}:{packet.dst_port}"
                print(f"🔄 {direction} {packet.src_addr}:{packet.src_port} → {dst_display} (大小: {len(packet.payload)} 字节)")

                # **传输完整 TCP 数据流**
                modified_payload = send_to_flask(packet, hostname)

                # **确保返回的数据不是空的**
                if modified_payload:
                    packet.payload = modified_payload
                else:
                    print(f"⚠ [EMPTY] 目标: {dst_display} | 代理返回空数据，丢弃数据包")

            # 重新注入数据包到 TCP 流量
            w.send(packet)

        except Exception as e:
            print(f"⚠ [ERROR] 目标: {dst_display} | 处理数据包时出错: {e}")
