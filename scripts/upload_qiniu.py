#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把构建产物上传到七牛云对象存储，生成国内可直连的订阅地址。

需要的环境变量：
  QINIU_AK       七牛 AccessKey
  QINIU_SK       七牛 SecretKey
  QINIU_BUCKET   存储空间名
  QINIU_UPLOAD_HOST  上传入口（默认 upload.qiniup.com，华南用 upload-z2.qiniup.com）
  QINIU_DOMAIN   可选，绑定的访问域名，仅用于打印最终链接

不上传 apps/*.txt 时可设 QINIU_SKIP_APPS=1
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT_FILES = [
    "hosts.txt",
    "adguard.txt",
    "domains.txt",
    "whitelist.txt",
    "gkd.json",
    "gkd-custom.json",
    "gkd.version.json5",
]

AK = os.environ.get("QINIU_AK", "").strip()
SK = os.environ.get("QINIU_SK", "").strip()
BUCKET = os.environ.get("QINIU_BUCKET", "").strip()
UP_HOST = os.environ.get("QINIU_UPLOAD_HOST", "upload.qiniup.com").strip()
DOMAIN = os.environ.get("QINIU_DOMAIN", "").strip().rstrip("/")


def make_token(bucket, key, ttl=3600):
    policy = json.dumps({"scope": "%s:%s" % (bucket, key), "deadline": int(time.time()) + ttl})
    b64_policy = base64.urlsafe_b64encode(policy.encode()).decode()
    sign = hmac.new(SK.encode(), b64_policy.encode(), hashlib.sha1).digest()
    return "%s:%s:%s" % (AK, base64.urlsafe_b64encode(sign).decode(), b64_policy)


def upload_one(path, key, retry=3):
    boundary = "----qiniuboundary%s" % os.urandom(8).hex()
    with open(path, "rb") as f:
        data = f.read()

    body = []
    for name, value in (("token", make_token(BUCKET, key)), ("key", key)):
        body.append(
            ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
             % (boundary, name, value)).encode()
        )
    body.append(
        ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
         'Content-Type: application/octet-stream\r\n\r\n'
         % (boundary, os.path.basename(path))).encode()
    )
    body.append(data)
    body.append(("\r\n--%s--\r\n" % boundary).encode())
    payload = b"".join(body)

    last_err = None
    for attempt in range(1, retry + 1):
        req = urllib.request.Request(
            "https://%s/" % UP_HOST,
            data=payload,
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode() or "{}")
            if "key" in result or "hash" in result:
                return True, ""
            last_err = json.dumps(result, ensure_ascii=False)
        except urllib.error.HTTPError as e:
            last_err = "HTTP %s %s" % (e.code, e.read().decode("utf-8", "ignore")[:200])
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
        if attempt < retry:
            time.sleep(2 * attempt)
    return False, last_err


def collect_files():
    files = []
    for name in ROOT_FILES:
        if os.path.exists(name) and os.path.getsize(name) > 0:
            files.append((name, name))
    if os.environ.get("QINIU_SKIP_APPS") != "1" and os.path.isdir("apps"):
        for name in sorted(os.listdir("apps")):
            if name.endswith(".txt"):
                files.append((os.path.join("apps", name), "apps/%s" % name))
    return files


def main():
    if not (AK and SK and BUCKET):
        print("未配置 QINIU_AK / QINIU_SK / QINIU_BUCKET，跳过七牛上传")
        return 0

    files = collect_files()
    if not files:
        print("没有可上传的文件")
        return 1

    print("准备上传 %d 个文件到 %s（入口 %s）" % (len(files), BUCKET, UP_HOST))
    ok = 0
    failed = []
    for path, key in files:
        success, err = upload_one(path, key)
        if success:
            ok += 1
            if ok % 50 == 0 or ok <= 7:
                print("  [%d/%d] %s" % (ok, len(files), key))
        else:
            failed.append((key, err))
            print("  失败 %s: %s" % (key, err))

    print("上传完成：成功 %d，失败 %d" % (ok, len(failed)))
    if DOMAIN:
        print("订阅地址前缀：%s" % DOMAIN)
        for name in ROOT_FILES:
            if os.path.exists(name):
                print("  %s/%s" % (DOMAIN, name))

    if failed:
        print("::warning::有 %d 个文件上传失败" % len(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
