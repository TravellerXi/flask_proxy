import requests
import logging
from flask import Flask, request, Response
import sys

# 初始化 Flask
app = Flask(__name__)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log", encoding="utf-8"),  # 日志文件
        logging.StreamHandler(sys.stdout)  # 终端输出
    ]
)

@app.route("/proxy", methods=["POST"])
def proxy():
    """处理 HTTP 和 HTTPS 代理请求"""
    dst = request.headers.get("X-Original-Dst")  # 目标 IP 或域名
    original_host = request.headers.get("X-Original-Host")  # 真实域名
    original_path = request.headers.get("X-Original-Path", "/")  # 请求路径
    original_method = request.headers.get("X-Original-Method", "GET")  # HTTP 方法

    if not dst:
        return Response("Missing X-Original-Dst header", status=400)

    # 解析目标 URL
    protocol = "https" if dst.endswith(":443") else "http"
    target_host = original_host if original_host else dst.split(":")[0]
    target_url = f"{protocol}://{target_host}{original_path}"

    logging.info(f"Received proxy request: {original_method} {target_url}")

    try:
        # 复制请求头（去掉代理相关头部）
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "x-original-method"]}
        headers["Host"] = target_host

        # 代理请求
        resp = requests.request(
            method=original_method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
            verify=False,
            stream=True
        )

        # 读取返回数据
        response_content = resp.raw.read()
        logging.info(f"Target server response: {resp.status_code}")

        return Response(response_content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        logging.error(f"Proxy request timeout: {target_url}")
        return Response("Request timeout, please try again later", status=504)
    except requests.RequestException as e:
        logging.error(f"Proxy request failed: {target_url}, Error: {str(e)}")
        return Response(f"Proxy error: {str(e)}", status=502)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)
