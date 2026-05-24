"""
Monitor de Red en Tiempo Real
Dashboard de monitoreo de tráfico de red local con alertas automáticas.
Proyecto Integrador - Redes Convergentes 2026-1
Universidad de la Costa (CUC)

Autores: Rafael Romo & Álvaro Araque
"""

import time
import threading
from datetime import datetime
from collections import defaultdict, deque

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

# Scapy: importar sin warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, ARP, Ether, IP, TCP, UDP, ICMP, conf

# ============================================================
# CONFIGURACIÓN
# ============================================================
INTERFACE = None  # None = interfaz por defecto del sistema
NETWORK = "192.168.1.0/24"  # Rango de red para ARP scan
UPDATE_INTERVAL = 1  # Segundos entre actualizaciones al dashboard
BANDWIDTH_ALERT_MBPS = 50  # Alerta si supera este ancho de banda (Mbps)
ICMP_ALERT_THRESHOLD = 100  # Paquetes ICMP por minuto para alerta
HISTORY_SIZE = 60  # Puntos en el gráfico de tiempo real (últimos 60s)

# ============================================================
# ESTADO GLOBAL
# ============================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = "netmonitor-cuc-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Métricas
packet_count = 0
bytes_total = 0
protocol_counts = defaultdict(int)
devices = {}  # {ip: {mac, last_seen, packets, bytes}}
alerts = deque(maxlen=200)
bandwidth_history = deque(maxlen=HISTORY_SIZE)
icmp_window = deque()  # timestamps de paquetes ICMP (último minuto)

# Control
lock = threading.Lock()
prev_bytes = 0
prev_time = time.time()
running = True

# ============================================================
# MAPEO DE PUERTOS A PROTOCOLOS
# ============================================================
PORT_MAP = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP", 8443: "HTTPS",
}


def classify_protocol(pkt):
    """Clasifica el protocolo de un paquete."""
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = PORT_MAP.get(dport) or PORT_MAP.get(sport)
        return proto if proto else "TCP"
    if pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = PORT_MAP.get(dport) or PORT_MAP.get(sport)
        return proto if proto else "UDP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "Otro"


# ============================================================
# PROCESAMIENTO DE PAQUETES
# ============================================================
def process_packet(pkt):
    """Callback para cada paquete capturado por Scapy."""
    global packet_count, bytes_total

    pkt_size = len(pkt)
    proto = classify_protocol(pkt)

    with lock:
        packet_count += 1
        bytes_total += pkt_size
        protocol_counts[proto] += 1

        # Registrar dispositivo por IP
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"

            if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."):
                if src_ip not in devices:
                    devices[src_ip] = {
                        "mac": src_mac,
                        "first_seen": datetime.now().strftime("%H:%M:%S"),
                        "last_seen": datetime.now().strftime("%H:%M:%S"),
                        "packets": 0,
                        "bytes": 0,
                    }
                    add_alert("info", f"Nuevo dispositivo detectado: {src_ip} ({src_mac})")
                devices[src_ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")
                devices[src_ip]["packets"] += 1
                devices[src_ip]["bytes"] += pkt_size

        # Registrar dispositivo por ARP
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            arp_ip = pkt[ARP].psrc
            arp_mac = pkt[ARP].hwsrc
            if arp_ip not in devices:
                devices[arp_ip] = {
                    "mac": arp_mac,
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                    "last_seen": datetime.now().strftime("%H:%M:%S"),
                    "packets": 0,
                    "bytes": 0,
                }
                add_alert("info", f"Dispositivo ARP detectado: {arp_ip} ({arp_mac})")
            devices[arp_ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")

        # Rastrear ICMP para detección de flood
        if proto == "ICMP":
            icmp_window.append(time.time())


def add_alert(severity, message):
    """Agrega una alerta al historial."""
    alert = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "severity": severity,
        "message": message,
    }
    alerts.appendleft(alert)
    # Emitir al dashboard
    try:
        socketio.emit("new_alert", alert)
    except Exception:
        pass


# ============================================================
# HILO DE CAPTURA
# ============================================================
def capture_thread():
    """Ejecuta la captura de paquetes en un hilo separado."""
    print(f"[*] Iniciando captura en interfaz: {INTERFACE or 'por defecto'}...")
    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: not running,
        )
    except PermissionError:
        print("\n[!] ERROR: Se necesitan permisos de administrador.")
        print("    Ejecuta con: sudo python app.py")
        add_alert("critical", "Sin permisos de captura. Ejecutar con sudo.")
    except Exception as e:
        print(f"\n[!] Error en captura: {e}")
        add_alert("critical", f"Error en captura: {str(e)}")


# ============================================================
# HILO DE MÉTRICAS Y ALERTAS
# ============================================================
def metrics_thread():
    """Calcula métricas periódicas y envía al dashboard."""
    global prev_bytes, prev_time

    while running:
        time.sleep(UPDATE_INTERVAL)

        with lock:
            now = time.time()
            elapsed = now - prev_time
            if elapsed > 0:
                bps = (bytes_total - prev_bytes) * 8 / elapsed
                mbps = bps / 1_000_000
            else:
                mbps = 0.0

            prev_bytes = bytes_total
            prev_time = now

            # Historial de ancho de banda
            bandwidth_history.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "mbps": round(mbps, 3),
            })

            # Verificar alertas
            # 1. Ancho de banda alto
            if mbps > BANDWIDTH_ALERT_MBPS:
                add_alert("warning", f"Ancho de banda elevado: {mbps:.2f} Mbps")

            # 2. Posible ICMP flood
            cutoff = now - 60
            while icmp_window and icmp_window[0] < cutoff:
                icmp_window.popleft()
            if len(icmp_window) > ICMP_ALERT_THRESHOLD:
                add_alert("critical", f"Posible ICMP flood: {len(icmp_window)} paquetes/min")

            # Preparar datos para el dashboard
            data = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "packet_count": packet_count,
                "bytes_total": bytes_total,
                "bandwidth_mbps": round(mbps, 3),
                "protocols": dict(protocol_counts),
                "devices_count": len(devices),
                "bandwidth_history": list(bandwidth_history),
            }

        socketio.emit("update_metrics", data)


# ============================================================
# RUTAS
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    with lock:
        return jsonify(list(
            {"ip": ip, **info} for ip, info in sorted(devices.items())
        ))


@app.route("/api/alerts")
def api_alerts():
    with lock:
        return jsonify(list(alerts))


@app.route("/api/stats")
def api_stats():
    with lock:
        return jsonify({
            "packet_count": packet_count,
            "bytes_total": bytes_total,
            "protocols": dict(protocol_counts),
            "devices_count": len(devices),
        })


# ============================================================
# ARRANQUE
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("  MONITOR DE RED EN TIEMPO REAL")
    print("  Proyecto Integrador - Redes Convergentes 2026-1")
    print("  Universidad de la Costa (CUC)")
    print("=" * 55)
    print()

    # Iniciar hilo de captura
    t_capture = threading.Thread(target=capture_thread, daemon=True)
    t_capture.start()

    # Iniciar hilo de métricas
    t_metrics = threading.Thread(target=metrics_thread, daemon=True)
    t_metrics.start()

    print("[*] Dashboard disponible en: http://localhost:5000")
    print("[*] Presiona Ctrl+C para detener.\n")

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
