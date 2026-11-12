#!/usr/bin/env python3
"""Smoke-проверка деплоя APS: health/ready/JWKS/логин/профиль.

Читает .env текущего каталога (APS_ADMIN_BOOTSTRAP_USER/PASSWORD) либо
переменные окружения. База: http://auth-ldap-web:80 из job-контейнера
(в CI) или http://localhost:8006 локально (передайте первым аргументом).
"""
import json
import os
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://auth-ldap-web:80"


def load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


# Прокси job-контейнера (HTTP(S)_PROXY) не знает docker-имён — ходим напрямую.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    with _opener.open(req, timeout=15) as r:
        raw = r.read().decode()
        try:
            return r.status, json.loads(raw)
        except json.JSONDecodeError:
            return r.status, raw


def post(path, body, headers=None):
    h = {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
    h.update(headers or {})
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with _opener.open(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main():
    load_env()
    user = os.environ.get("APS_ADMIN_BOOTSTRAP_USER", "")
    pwd = os.environ.get("APS_ADMIN_PASSWORD", "")
    if not user or not pwd:
        raise SystemExit("нет APS_ADMIN_BOOTSTRAP_USER/PASSWORD в .env")

    for _ in range(30):
        try:
            get("/health")
            break
        except Exception:
            time.sleep(2)
    else:
        raise SystemExit("/health недоступен")

    st, _ = get("/health");  assert st == 200, "health"
    st, _ = get("/ready");   assert st == 200, "ready"
    st, jwks = get("/.well-known/jwks.json")
    assert st == 200 and '"kid"' in jwks, "JWKS"

    st, tok = post("/api/v1/auth/login", {"username": user, "password": pwd})
    assert st == 200 and tok.get("access_token"), f"login: {st}"
    access = tok["access_token"]

    st, me = get("/api/v1/auth/me", {"Authorization": "Bearer " + access})
    assert st == 200 and me.get("username") == user, f"me: {st} {me}"

    print(f"Smoke OK: health/ready/JWKS/login/me ({user}) — пройдено")


if __name__ == "__main__":
    main()
