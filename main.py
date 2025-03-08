import requests
import logging
from flask import Flask, request, Response, render_template
from ipaddress import ip_address, AddressValueError
import os
import sys

# 初始化 Flask
app = Flask(__name__)

# 设置模板文件夹
app.template_folder = os.path.join(os.path.dirname(__file__), "templates")

# 配置日志格式
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log", encoding="utf-8"),  # 日志文件
        logging.StreamHandler(sys.stdout)  # 终端输出
    ]
)

def format_host_for_requests(dst):
    """修正 IPv6 地址，确保 requests 正确解析"""
    try:
        host, port = dst.rsplit(":", 1)
        if ":" in host and isinstance(ip_address(host), ip_address):  # IPv6
            return f"[{host}]:{port}"
        return f"{host}:{port}"
    except (ValueError, AddressValueError):
        return dst  # 如果格式错误，直接返回原值

@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy():
    dst = request.headers.get("X-Original-Dst")  # 目标 IP（用于访问）
    original_host = request.headers.get("X-Original-Host")  # 原始域名（用于 Host 头）

    if not dst:
        app.logger.warning("缺少 X-Original-Dst 头")
        return render_template("error.html", error_message="缺少目标地址"), 400

    formatted_dst = format_host_for_requests(dst)  # 确保 IPv6 正确
    target_path = request.path  # 获取原始路径
    query_string = request.query_string.decode()  # 获取查询参数
    target_url = f"http://{formatted_dst}{target_path}" + (f"?{query_string}" if query_string else "")
    display_host = original_host or dst  # 用于日志的显示

    app.logger.info(f"收到代理请求: {request.method} {display_host}{target_path}")

    # 记录请求详情
    app.logger.info(f"目标访问 URL: {target_url}")
    app.logger.info(f"请求头: {dict(request.headers)}")
    if request.get_data():
        app.logger.info(f"请求 Body: {request.get_data().decode(errors='ignore')}")

    try:
        # 复制 Headers，并替换 Host 头
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        if original_host:
            headers["Host"] = original_host  # 让服务器识别原始域名

        # 代理请求
        resp = requests.request(
            method=request.method,  # 转发原始 HTTP 方法
            url=target_url,  # 目标 URL
            headers=headers,  # 修改 Host
            data=request.get_data(),  # 复制 Body
            cookies=request.cookies,  # 复制 Cookies
            allow_redirects=False,  # 禁止自动重定向
            timeout=10  # 超时时间
        )

        # 记录响应信息
        app.logger.info(f"目标服务器响应: {resp.status_code}")
        app.logger.info(f"响应头: {dict(resp.headers)}")
        if resp.content:
            app.logger.info(f"响应 Body: {resp.content[:500].decode(errors='ignore')}...")  # 避免日志过大

        # 返回代理响应
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        app.logger.error(f"代理请求超时: {target_url}")
        return render_template("error.html", error_message="请求超时，请稍后再试"), 504
    except requests.RequestException as e:
        app.logger.error(f"代理请求失败: {target_url}，错误: {str(e)}")
        return render_template("error.html", error_message=f"代理错误: {str(e)}"), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)