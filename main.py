import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/proxy", methods=["POST"])
def proxy():
    dst = request.headers.get("X-Original-Dst")  # 目标地址
    if not dst:
        return "Missing destination", 400

    print(f"🌍 收到代理请求: {dst}")

    # 解析目标地址
    try:
        host, port = dst.rsplit(":", 1)
    except ValueError:
        raise ValueError(f"Invalid dst format: {dst}")
    target_url = f"http://{host}:{port}"

    try:
        # 代理请求
        resp = requests.request(
            method="POST",
            url=target_url,
            data=request.data,
            headers=request.headers,
            timeout=5
        )
        return Response(resp.content, status=resp.status_code, headers=resp.headers.items())
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
