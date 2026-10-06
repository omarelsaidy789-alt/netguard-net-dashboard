
"""
Network Traffic Analyzer & Intrusion Detector - Backend (Flask)
"""

import csv
import io
import itertools
import os
import platform
import random
import re
import socket
import subprocess
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import psutil
from flask import Flask, Response, jsonify, render_template, request


try:
    from scapy.all import IP, TCP, sniff
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

LIVE_SNIFFING = os.environ.get("NTA_LIVE", "0") == "1" 
HISTORY_SIZE = 60            
SCAN_INTERVAL = 60          
PORTSCAN_THRESHOLD = 15     
PORTSCAN_WINDOW = 10        
ALERT_COOLDOWN = 60       
app = Flask(__name__)

lock = threading.RLock()
traffic_history = deque(maxlen=HISTORY_SIZE)
devices = {}                      
trusted_macs = set()              
alerts = deque(maxlen=200)
alert_counter = itertools.count(1)
baseline_done = False            
scan_state = {"scanning": False, "last_scan": None}


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add_alert(severity, kind, message, source="-"):
    """إضافة تنبيه جديد (severity: high / medium / low)."""
    with lock:
        alerts.appendleft({
            "id": next(alert_counter),
            "time": now_str(),
            "severity": severity,
            "type": kind,
            "message": message,
            "source": source,
        })


# ----------------------------------------------------------------------
# اكتشاف الأجهزة (Device Discovery)
# ----------------------------------------------------------------------
def get_local_ip():
    """معرفة IP الجهاز على الشبكة المحلية (مفيش بيانات بتتبعت فعليًا)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_local_mac():
    node = uuid.getnode()
    return ":".join(f"{(node >> i) & 0xff:02X}" for i in range(40, -1, -8))


def ping_host(ip):
    """ping واحد لملء جدول ARP."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "300", ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-t", "1", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        pass


def ping_sweep(prefix):
    """ping لكل العناوين من 1 إلى 254 بالتوازي."""
    ips = [f"{prefix}{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping_host, ips))


def normalize_mac(mac):
    parts = re.split(r"[:-]", mac)
    return ":".join(p.zfill(2) for p in parts).upper()


def read_arp_table(prefix):
    """قراءة جدول ARP (يشتغل على Windows / Linux / macOS)."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True,
                                      errors="ignore", timeout=10)
    except Exception:
        return {}

    result = {}
    for line in out.splitlines():
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac_m = re.search(r"([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})", line)
        if not ip_m or not mac_m:
            continue
        ip = ip_m.group(1)
        mac = normalize_mac(mac_m.group(1))
       
        if not ip.startswith(prefix) or ip.endswith(".255"):
            continue
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        result[ip] = mac
    return result


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def scan_network():
    """فحص الشبكة وتحديث قائمة الأجهزة + إنشاء تنبيهات للأجهزة الغريبة."""
    global baseline_done
    with lock:
        if scan_state["scanning"]:
            return
        scan_state["scanning"] = True

    try:
        local_ip = get_local_ip()
        prefix = local_ip.rsplit(".", 1)[0] + "."
        ping_sweep(prefix)
        arp = read_arp_table(prefix)
        arp.setdefault(local_ip, get_local_mac()) 

        ips = list(arp.keys())
        with ThreadPoolExecutor(max_workers=32) as ex:
            names = dict(zip(ips, ex.map(resolve_hostname, ips)))

        now = now_str()
        with lock:
            first_scan = not baseline_done
            seen_macs = set()
            for ip, mac in arp.items():
                seen_macs.add(mac)
                prev = devices.get(mac)
                if first_scan:
                    trusted_macs.add(mac)
                is_new = prev is None and not first_scan and mac not in trusted_macs
                devices[mac] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": names.get(ip, "Unknown"),
                    "status": "online",
                    "trusted": mac in trusted_macs,
                    "is_self": ip == local_ip,
                    "first_seen": prev["first_seen"] if prev else now,
                    "last_seen": now,
                }
                if is_new:
                    add_alert("high", "Unknown Device",
                              f"جهاز غريب جديد انضم للشبكة: {ip} ({mac})", ip)

            for mac, dev in devices.items():
                if mac not in seen_macs:
                    dev["status"] = "offline"

            baseline_done = True
            scan_state["last_scan"] = now
    finally:
        with lock:
            scan_state["scanning"] = False


def scan_scheduler():
    """فحص دوري في الخلفية."""
    while True:
        try:
            scan_network()
        except Exception as e:
            add_alert("low", "Scanner", f"خطأ أثناء الفحص: {e}")
        time.sleep(SCAN_INTERVAL)

def traffic_monitor():
    prev = psutil.net_io_counters()
    prev_t = time.time()
    while True:
        time.sleep(1)
        cur = psutil.net_io_counters()
        t = time.time()
        dt = max(t - prev_t, 0.001)
        point = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "down_bps": (cur.bytes_recv - prev.bytes_recv) / dt,
            "up_bps": (cur.bytes_sent - prev.bytes_sent) / dt,
            "pps": ((cur.packets_recv - prev.packets_recv) +
                    (cur.packets_sent - prev.packets_sent)) / dt,
        }
        with lock:
            traffic_history.append(point)
        prev, prev_t = cur, t


class PortScanDetector:
    """لو مصدر واحد جرّب منافذ كتير مختلفة في وقت قصير = تفحص منافذ."""

    def __init__(self):
        self.hits = defaultdict(deque)
        self.last_alert = {}
        self._lock = threading.Lock()

    def record(self, src, port):
        ts = time.time()
        fire = False
        count = 0
        with self._lock:
            dq = self.hits[src]
            dq.append((ts, port))
            while dq and ts - dq[0][0] > PORTSCAN_WINDOW:
                dq.popleft()
            ports = {p for _, p in dq}
            count = len(ports)
            if (count >= PORTSCAN_THRESHOLD and
                    ts - self.last_alert.get(src, 0) > ALERT_COOLDOWN):
                self.last_alert[src] = ts
                fire = True
        if fire:
            add_alert("high", "Port Scan",
                      f"تفحص منافذ من {src}: {count} منفذ خلال "
                      f"{PORTSCAN_WINDOW} ثانية", src)


detector = PortScanDetector()


def handle_packet(pkt):
    """نعدّ حزم SYN (بدون ACK) لأنها علامة التفحص."""
    try:
        if IP in pkt and TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x02 and not flags & 0x10:
                detector.record(pkt[IP].src, int(pkt[TCP].dport))
    except Exception:
        pass


def sniff_worker():
    """sniffing حقيقي (يحتاج صلاحيات Admin/root + Npcap على Windows)."""
    try:
        sniff(filter="tcp", prn=handle_packet, store=False)
    except Exception as e:
        add_alert("medium", "Sniffer",
                  f"تعذر تشغيل الـ sniffing الحقيقي: {e}")


def simulate_port_scan():
    prefix = get_local_ip().rsplit(".", 1)[0] + "."
    src = f"{prefix}{random.randint(100, 200)}"
    for port in range(20, 20 + PORTSCAN_THRESHOLD + 5):
        detector.record(src, port)


def simulate_rogue_device():
    prefix = get_local_ip().rsplit(".", 1)[0] + "."
    ip = f"{prefix}{random.randint(201, 250)}"
    mac = "02:" + ":".join(f"{random.randint(0, 255):02X}" for _ in range(5))
    now = now_str()
    with lock:
        devices[mac] = {
            "ip": ip, "mac": mac, "hostname": "rogue-device",
            "status": "online", "trusted": False, "is_self": False,
            "first_seen": now, "last_seen": now,
        }
    add_alert("high", "Unknown Device",
              f"جهاز غريب جديد انضم للشبكة: {ip} ({mac})", ip)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    with lock:
        return jsonify({
            "local_ip": get_local_ip(),
            "scanning": scan_state["scanning"],
            "last_scan": scan_state["last_scan"],
            "device_count": len(devices),
            "online_count": sum(1 for d in devices.values() if d["status"] == "online"),
            "alert_count": len(alerts),
            "scapy_available": SCAPY_AVAILABLE,
            "live_sniffing": LIVE_SNIFFING and SCAPY_AVAILABLE,
        })


@app.route("/api/devices")
def api_devices():
    with lock:
        data = sorted(devices.values(),
                      key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
        return jsonify(data)


@app.route("/api/traffic")
def api_traffic():
    with lock:
        return jsonify(list(traffic_history))


@app.route("/api/alerts")
def api_alerts():
    with lock:
        return jsonify(list(alerts))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    threading.Thread(target=scan_network, daemon=True).start()
    return jsonify({"ok": True}), 202


@app.route("/api/trust", methods=["POST"])
def api_trust():
    mac = (request.get_json(silent=True) or {}).get("mac", "")
    with lock:
        if mac in devices:
            trusted_macs.add(mac)
            devices[mac]["trusted"] = True
            return jsonify({"ok": True})
    return jsonify({"ok": False}), 404


@app.route("/api/simulate/<kind>", methods=["POST"])
def api_simulate(kind):
    if kind == "portscan":
        simulate_port_scan()
    elif kind == "rogue":
        simulate_rogue_device()
    else:
        return jsonify({"ok": False}), 400
    return jsonify({"ok": True})


def safe_cell(value):
    """حماية CSV من CSV Injection (قيم تبدأ بـ = + - @)."""
    s = str(value)
    return "'" + s if s and s[0] in "=+-@" else s


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json").lower()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    with lock:
        snapshot = {
            "generated_at": now_str(),
            "local_ip": get_local_ip(),
            "devices": list(devices.values()),
            "alerts": list(alerts),
            "traffic": list(traffic_history),
        }

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)

        w.writerow(["# DEVICES"])
        w.writerow(["ip", "mac", "hostname", "status", "trusted", "first_seen", "last_seen"])
        for d in snapshot["devices"]:
            w.writerow([safe_cell(d["ip"]), d["mac"], safe_cell(d["hostname"]),
                        d["status"], d["trusted"], d["first_seen"], d["last_seen"]])

        w.writerow([])
        w.writerow(["# ALERTS"])
        w.writerow(["id", "time", "severity", "type", "source", "message"])
        for a in snapshot["alerts"]:
            w.writerow([a["id"], a["time"], a["severity"], a["type"],
                        safe_cell(a["source"]), safe_cell(a["message"])])

        w.writerow([])
        w.writerow(["# TRAFFIC"])
        w.writerow(["time", "down_bytes_per_sec", "up_bytes_per_sec", "packets_per_sec"])
        for t in snapshot["traffic"]:
            w.writerow([t["time"], round(t["down_bps"], 2),
                        round(t["up_bps"], 2), round(t["pps"], 2)])

        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{stamp}.csv"})

    resp = jsonify(snapshot)
    resp.headers["Content-Disposition"] = f"attachment; filename=report_{stamp}.json"
    return resp


def start_background_threads():
    threading.Thread(target=traffic_monitor, daemon=True).start()
    threading.Thread(target=scan_scheduler, daemon=True).start()
    if LIVE_SNIFFING and SCAPY_AVAILABLE:
        threading.Thread(target=sniff_worker, daemon=True).start()


if __name__ == "__main__":
    start_background_threads()
    
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)