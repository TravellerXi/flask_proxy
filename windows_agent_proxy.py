import socket
import threading
import requests
import select
import winreg
import atexit

# Flask 代理服务器地址
FLASK_PROXY_URL = "http://your-server-ip:5555/proxy"
LOCAL_PROXY_PORT = 8080  # 本地代理端口

# 修改 Windows 代理
def set_proxy(proxy):
    key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg:
            winreg.SetValueEx(reg, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(reg, "ProxyServer", 0, winreg.REG_SZ, proxy)
        print(f"已设置 Windows 代理: {proxy}")
    except Exception as e:
        print(f"设置代理失败: {e}")

# 关闭 Windows 代理
def disable_proxy():
    key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg:
            winreg.SetValueEx(reg, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        print("已关闭 Windows 代理")
    except Exception as e:
        print(f"关闭代理失败: {e}")

# 处理 HTTP 请求
def handle_http_request(client_socket, request_data):
    try:
        lines = request_data.split(b"\r\n")
        first_line = lines[0].decode("utf-8")
        method, url, _ = first_line.split(" ", 2)

        headers = {}
        body = None
        is_body = False

        for line in lines[1:]:
            if line == b"":
                is_body = True
                continue
            if is_body:
                body = line
                break
            key, value = line.decode("utf-8").split(":", 1)
            headers[key.strip()] = value.strip()

        # 转发到 Flask 服务器
        response = requests.post(FLASK_PROXY_URL, headers={
            "X-Original-Dst": url,
            "X-Original-Host": url.split("//")[-1].split("/")[0],
            "X-Original-Path": "/" + "/".join(url.split("//")[-1].split("/")[1:]),
            "X-Original-Method": method
        }, data=body)

        # 发送响应给客户端
        client_socket.sendall(f"HTTP/1.1 {response.status_code} OK\r\n".encode())
        for key, value in response.headers.items():
            client_socket.sendall(f"{key}: {value}\r\n".encode())
        client_socket.sendall(b"\r\n")
        client_socket.sendall(response.content)

    except Exception as e:
        client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        client_socket.sendall(f"Error: {e}".encode())
    finally:
        client_socket.close()

# 处理 HTTPS 请求
def handle_https_request(client_socket, address, port):
    try:
        remote_socket = socket.create_connection((address, int(port)))
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        sockets = [client_socket, remote_socket]
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                data = sock.recv(4096)
                if not data:
                    break
                if sock is client_socket:
                    remote_socket.sendall(data)
                else:
                    client_socket.sendall(data)

    except Exception as e:
        print(f"HTTPS 代理错误: {e}")
    finally:
        client_socket.close()

# 代理服务器主线程
def proxy_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", LOCAL_PROXY_PORT))
    server.listen(100)

    print(f"本地代理服务器运行在 127.0.0.1:{LOCAL_PROXY_PORT}")

    while True:
        client_socket, _ = server.accept()
        request_data = client_socket.recv(4096)

        # 解析请求类型
        if request_data.startswith(b"CONNECT"):
            first_line = request_data.split(b"\r\n")[0].decode("utf-8")
            _, address_port, _ = first_line.split()
            address, port = address_port.split(":")
            threading.Thread(target=handle_https_request, args=(client_socket, address, port)).start()
        else:
            threading.Thread(target=handle_http_request, args=(client_socket, request_data)).start()

if __name__ == "__main__":
    # 设置代理，并确保退出时恢复系统代理
    set_proxy("127.0.0.1:8080")
    atexit.register(disable_proxy)

    try:
        proxy_server()
    except KeyboardInterrupt:
        print("程序退出...")
        disable_proxy()
