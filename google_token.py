import hashlib
import json
import os
import re
import socket
import threading
import tkinter as tk
import urllib.parse
import urllib.request
from tkinter import filedialog, messagebox, ttk


class OAuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Google OAuth Token Generator")
        self.root.geometry("800x600")

        # 初始化参数
        self.host = "127.0.0.1"
        self.port = 8080
        self.authorization_url = None
        self.client_id = None
        self.client_secret = None
        self.redirect_uri = f"http://{self.host}:{self.port}"
        self.scope = "https://www.googleapis.com/auth/drive"
        self.state = hashlib.sha256(os.urandom(1024)).hexdigest()

        self.code = None
        self.refresh_token = None
        self.error_message = None
        self.client_secrets_path = None

        self._build_ui()

    def _build_ui(self):
        # 使用 ttk 主题控件，美化UI

        frm_main = ttk.Frame(self.root, padding=10)
        frm_main.pack(fill=tk.BOTH, expand=True)

        # -------- 配置区域 --------
        frm_config = ttk.LabelFrame(frm_main, text="配置参数")
        frm_config.pack(fill=tk.X, pady=5)

        # client_secret文件选择
        ttk.Label(frm_config, text="client_secret.json:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_client_secret = ttk.Entry(frm_config, width=60)
        self.entry_client_secret.grid(row=0, column=1, padx=5)
        btn_browse = ttk.Button(frm_config, text="选择文件", command=self.select_client_secret)
        btn_browse.grid(row=0, column=2, padx=5)

        # 回调地址可编辑
        ttk.Label(frm_config, text="回调地址:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_redirect_uri = ttk.Entry(frm_config, width=60)
        self.entry_redirect_uri.grid(row=1, column=1, padx=5, pady=5)
        self.entry_redirect_uri.insert(0, f"http://{self.host}:{self.port}")

        # scope 多个用逗号分隔
        ttk.Label(frm_config, text="Scope (逗号分隔):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_scope = ttk.Entry(frm_config, width=60)
        self.entry_scope.grid(row=2, column=1, padx=5, pady=5)
        self.entry_scope.insert(0, self.scope)

        # -------- 操作区域 --------
        frm_ops = ttk.LabelFrame(frm_main, text="操作")
        frm_ops.pack(fill=tk.X, pady=10)

        self.btn_generate_url = ttk.Button(frm_ops, text="生成授权链接", command=self.generate_authorization_url, state="disabled")
        self.btn_generate_url.grid(row=0, column=0, padx=10, pady=5)

        self.btn_wait_auth = ttk.Button(frm_ops, text="等待授权并获取 Refresh Token", command=self.start_listening, state="disabled")
        self.btn_wait_auth.grid(row=0, column=1, padx=10, pady=5)

        self.btn_open_url = ttk.Button(frm_ops, text="打开授权链接", command=self.open_authorization_url, state="disabled")
        self.btn_open_url.grid(row=0, column=2, padx=10, pady=5)

        # -------- 授权链接显示 --------
        frm_url = ttk.LabelFrame(frm_main, text="授权链接（点击复制）")
        frm_url.pack(fill=tk.BOTH, expand=False, pady=5)

        self.text_url = tk.Text(frm_url, height=3, wrap="word")
        self.text_url.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.text_url.bind("<Button-1>", lambda e: self.copy_text(self.text_url))

        # -------- Refresh Token显示 --------
        frm_token = ttk.LabelFrame(frm_main, text="Refresh Token")
        frm_token.pack(fill=tk.BOTH, expand=False, pady=5)

        self.text_token = tk.Text(frm_token, height=4, wrap="word")
        self.text_token.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.text_token.bind("<Button-1>", lambda e: self.copy_text(self.text_token))

        # -------- 日志输出 --------
        frm_log = ttk.LabelFrame(frm_main, text="日志输出")
        frm_log.pack(fill=tk.BOTH, expand=True, pady=5)

        self.text_log = tk.Text(frm_log, height=10, wrap="word", bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.text_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.text_log.configure(state="disabled")

    def copy_text(self, widget):
        try:
            text = widget.get("1.0", tk.END).strip()
            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.log("已复制到剪贴板")
        except Exception as e:
            self.log(f"复制失败: {e}")

    def log(self, message: str):
        # 线程安全写日志
        def append():
            self.text_log.configure(state="normal")
            self.text_log.insert(tk.END, message + "\n")
            self.text_log.see(tk.END)
            self.text_log.configure(state="disabled")

        self.root.after(0, append)

    def select_client_secret(self):
        path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if path:
            self.client_secrets_path = path
            self.entry_client_secret.delete(0, tk.END)
            self.entry_client_secret.insert(0, path)
            self.log(f"选择 client_secret 文件: {path}")
            self.btn_generate_url.config(state="normal")
        else:
            self.log("未选择 client_secret 文件")

    def generate_authorization_url(self):
        try:
            with open(self.entry_client_secret.get(), "r") as f:
                secrets = json.load(f)["web"]
                self.client_id = secrets["client_id"]
                self.client_secret = secrets["client_secret"]

            # 更新host,port,redirect_uri
            self.redirect_uri = self.entry_redirect_uri.get().strip()
            if not self.redirect_uri.startswith("http"):
                raise ValueError("回调地址必须以 http:// 或 https:// 开头")

            scopes = [s.strip() for s in self.entry_scope.get().split(",") if s.strip()]
            if not scopes:
                raise ValueError("Scope不能为空")
            self.scope = " ".join(scopes)

            params = {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": self.scope,
                "access_type": "offline",
                "state": self.state,
                "prompt": "consent",
            }

            self.authorization_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)

            self.text_url.configure(state="normal")
            self.text_url.delete("1.0", tk.END)
            self.text_url.insert(tk.END, self.authorization_url)
            self.text_url.configure(state="disabled")

            self.log("生成授权链接成功，请打开链接完成授权")
            self.btn_wait_auth.config(state="normal")
            self.btn_open_url.config(state="normal")
            self.text_token.configure(state="normal")
            self.text_token.delete("1.0", tk.END)
            self.text_token.configure(state="disabled")
            self.status_clear()

        except Exception as e:
            self.log(f"生成授权链接失败: {e}")
            messagebox.showerror("错误", f"生成授权链接失败: {e}")

    def open_authorization_url(self):
        if self.authorization_url:
            # webbrowser.open(self.authorization_url)
            self.log("暂不支持直接使用浏览器打开授权链接")
        else:
            messagebox.showwarning("警告", "请先生成授权链接")

    def start_listening(self):
        self.log("开始监听回调请求...")
        self.btn_wait_auth.config(state="disabled")
        threading.Thread(target=self.listen_for_code, daemon=True).start()

    def listen_for_code(self):
        try:
            parsed = urllib.parse.urlparse(self.redirect_uri)
            host = parsed.hostname or self.host
            port = parsed.port or self.port

            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(1)
            self.log(f"Socket监听 {host}:{port} 等待回调...")

            conn, addr = sock.accept()
            self.log(f"接收到来自 {addr} 的连接")
            data = conn.recv(4096).decode("utf-8")
            self.log(f"接收数据: {data.splitlines()[0]} ...")

            match = re.search(r"GET\s/\?(.*?)\sHTTP/", data)
            if not match:
                raise ValueError("无法解析回调数据")

            query = match.group(1)
            params = dict(urllib.parse.parse_qsl(query))

            if params.get("state") != self.state:
                raise ValueError("状态码不一致，可能存在 CSRF 攻击")

            code = params.get("code")
            if not code:
                raise ValueError(f"授权失败: {params.get('error', '未知错误')}")

            response = "HTTP/1.1 200 OK\r\n" "Content-Type: text/html\r\n\r\n" "<h2>授权成功</h2><p>请关闭此窗口并返回程序。</p>"
            conn.sendall(response.encode())
            conn.close()
            sock.close()

            self.code = code
            self.log("授权码接收成功，准备交换Refresh Token")
            self.root.after(0, self.exchange_code_for_refresh_token)

        except Exception as e:
            self.error_message = str(e)
            self.log(f"监听回调出错: {self.error_message}")
            self.root.after(0, self.show_error)

    def exchange_code_for_refresh_token(self):
        token_url = "https://oauth2.googleapis.com/token"
        post_data = urllib.parse.urlencode(
            {
                "code": self.code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(token_url, data=post_data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            self.log("发送请求获取 Refresh Token...")
            with urllib.request.urlopen(req) as resp:
                resp_data = json.load(resp)
                self.refresh_token = resp_data.get("refresh_token", "")

            if self.refresh_token:
                self.log("成功获取 Refresh Token")
                self.text_token.configure(state="normal")
                self.text_token.delete("1.0", tk.END)
                self.text_token.insert(tk.END, self.refresh_token)
                self.text_token.configure(state="disabled")
            else:
                self.log("未获取到 Refresh Token，请确认授权是否选择了离线访问权限")
                messagebox.showwarning("警告", "未获取到 Refresh Token，请检查授权流程。")

        except urllib.error.HTTPError as e:
            error_msg = e.read().decode()
            self.log(f"HTTP错误: {error_msg}")
            messagebox.showerror("HTTP错误", error_msg)
        except Exception as e:
            self.log(f"请求出错: {e}")
            messagebox.showerror("错误", str(e))

        self.btn_wait_auth.config(state="normal")

    def show_error(self):
        self.status_clear()
        self.log(f"错误: {self.error_message}")
        messagebox.showerror("错误", self.error_message)
        self.btn_wait_auth.config(state="normal")

    def status_clear(self):
        pass  # 占位，可以扩展状态栏显示


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")  # 切换到较为现代主题
    app = OAuthApp(root)
    root.mainloop()
