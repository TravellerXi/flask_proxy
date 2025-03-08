import pydivert
import requests
import binascii

# Flask 代理服务器地址
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# 监听所有 TCP 80/443 端口的流量（完整捕获 HTTP / HTTPS）
FILTER_RULE = "tcp and (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443))"

def hex_dump(data, length=500):
    """将数据转换为十六进制字符串，防止乱码"""
    return binascii.hexlify(data[:length]).decode("utf-8") if data else "No Data"

def send_to_flask(packet):
    """将拦截的完整数据包发送到 Flask 代理"""
    try:
        headers = {
            "X-Original-Dst": f"{packet.dst_addr}:{packet.dst_port}",
            "Content-Type": "application/octet-stream"
        }

        # 记录原始数据包内容（防止日志太长，截取前 500 字节）
        payload_hex = hex_dump(packet.raw)
        print(f"📦 [SEND] 发送数据到 Flask (HEX 前 500 字节): {payload_hex}...")

        response = requests.post(FLASK_PROXY, data=packet.raw, headers=headers, timeout=5)

        # 记录代理服务器返回的数据（同样截取前 500 字节）
        response_hex = hex_dump(response.content)
        print(f"📦 [RECV] 代理返回数据 (HEX 前 500 字节): {response_hex}...")

        return response.content
    except requests.RequestException as e:
        print(f"⚠ 代理请求失败: {e}")
        return packet.raw  # 代理失败时，返回原始数据包

# 监听 TCP 流量并转发
with pydivert.WinDivert(FILTER_RULE) as w:
    print("🚀 透明代理已启动，拦截 HTTP/HTTPS 流量中...")

    for packet in w:
        try:
            if packet.tcp and packet.payload:
                direction = "⬆ OUT" if packet.is_outbound else "⬇ IN"
                print(f"🔄 {direction} {packet.src_addr}:{packet.src_port} → {packet.dst_addr}:{packet.dst_port} (大小: {len(packet.payload)} 字节)")

                # **传输完整 TCP 数据流**
                modified_payload = send_to_flask(packet)

                # **确保返回的数据不是空的**
                if modified_payload:
                    packet.payload = modified_payload
                else:
                    print(f"⚠ 代理返回空数据，丢弃数据包 {packet.src_addr}:{packet.src_port}")

            # 重新注入数据包到 TCP 流量
            w.send(packet)

        except Exception as e:
            print(f"⚠ 处理数据包时出错: {e}")
