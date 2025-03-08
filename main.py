import requests
import logging
from flask import Flask, request, Response

# 初始化 Flask
app = Flask(__name__)

# 配置日志格式
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log"),  # 日志文件
        logging.StreamHandler()  # 终端输出
    ]
)

@app.route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy():
    dst = request.headers.get("X-Original-Dst")  # 获取目标地址
    if not dst:
        app.logger.warning("❌ 缺少 X-Original-Dst 头")
        return "Missing destination", 400

    app.logger.info(f"🌍 收到代理请求: {request.method} {dst}{request.full_path}")

    # 解析目标地址
    try:
        host, port = dst.rsplit(":", 1)
        target_url = f"http://{host}:{port}{request.full_path}"
    except ValueError:
        app.logger.error(f"❌ 错误的目标地址格式: {dst}")
        return f"Invalid destination format: {dst}", 400

    # 记录请求详情
    app.logger.info(f"🔗 转发到: {target_url}")
    app.logger.info(f"📌 请求头: {dict(request.headers)}")
    if request.get_data():
        app.logger.info(f"📦 请求 Body: {request.get_data().decode(errors='ignore')}")

    try:
        # 代理请求
        resp = requests.request(
            method=request.method,  # 转发原始 HTTP 方法
            url=target_url,  # 目标 URL
            headers={k: v for k, v in request.headers if k.lower() != 'host'},  # 复制 Headers，避免 Host 冲突
            data=request.get_data(),  # 复制 Body
            cookies=request.cookies,  # 复制 Cookies
            allow_redirects=False,  # 禁止自动重定向
            timeout=10  # 超时时间
        )

        # 记录响应信息
        app.logger.info(f"✅ 目标服务器响应: {resp.status_code}")
        app.logger.info(f"📌 响应头: {dict(resp.headers)}")
        if resp.content:
            app.logger.info(f"📦 响应 Body: {resp.content[:500].decode(errors='ignore')}...")  # 避免日志过大

        # 返回代理响应
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except requests.Timeout:
        app.logger.error(f"⏳ 代理请求超时: {target_url}")
        return "Request Timeout", 504
    except requests.RequestException as e:
        app.logger.error(f"🚨 代理请求失败: {target_url}，错误: {str(e)}")
        return f"Proxy Error: {str(e)}", 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)
