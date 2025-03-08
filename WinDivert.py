import pydivert
import requests
import struct

# 远程 Flask 代理服务器地址
FLASK_PROXY = "http://192.168.0.115:5555/proxy"

# 监听 HTTP / HTTPS 流量
FILTER_RULE = "tcp and (outbound and tcp.DstPort == 80 or tcp.DstPort == 443)"

def send_to_flask(data, dst_addr, dst_port):
    """将拦截到的数据发送到远程 Flask 代理"""
    try:
        headers = {
            "X-Original-Dst": f"{dst_addr}:{dst_port}",
            "Content-Type": "application/octet-stream"
        }
        response = requests.post(FLASK_PROXY, data=data, headers=headers, timeout=5)

        return response.content
    except requests.RequestException as e:
        print(f"⚠ 代理请求失败: {e}")
        return data  # 如果 Flask 代理失败，返回原始数据

# 监听流量并转发
with pydivert.WinDivert(FILTER_RULE) as w:
    print("🚀 透明代理已启动，拦截流量中...")
    for packet in w:
        try:
            if packet.is_outbound and packet.tcp and packet.payload:
                # 解析目标地址
                dst_addr = packet.dst_addr
                dst_port = packet.dst_port

                print(f"🔄 捕获数据包 {packet.src_addr}:{packet.src_port} → {dst_addr}:{dst_port}")

                # 发送数据到 Flask 代理
                modified_payload = send_to_flask(packet.payload, dst_addr, dst_port)

                # 修改数据包负载
                packet.payload = modified_payload

            # 重新注入数据包
            w.send(packet)

        except Exception as e:
            print(f"⚠ 处理数据包时出错: {e}")
