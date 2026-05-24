
"""
Monitor de Red en Tiempo Real
Backend: FastAPI + Scapy + WebSockets
Captura tráfico de red local, analiza métricas y transmite en tiempo real.
 
Capas TCP/IP involucradas:
- Capa Física/Enlace: Captura de tramas Ethernet (MAC src/dst)
- Capa de Red: Análisis de paquetes IP (src/dst, TTL)
- Capa de Transporte: Puertos TCP/UDP, flags, protocolos
- Capa de Aplicación: Detección de HTTP, DNS, HTTPS, etc.
"""
 
import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Set
 
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
 
# ─── Intentar importar Scapy (captura real) ────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy no disponible. Usando modo simulación.")
 
import random
import math
 
# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════
 
app = FastAPI(title="NetMonitor CUC", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
 
# Almacenamiento en memoria
class NetworkState:
    def __init__(self):
        self.lock = threading.Lock()
        # Dispositivos detectados: {ip: {mac, hostname, first_seen, last_seen, packets, bytes}}
        self.devices: Dict[str, dict] = {}
        # Contadores de protocolos
        self.protocols: Dict[str, int] = defaultdict(int)
        # Historial de ancho de banda (últimos 60 puntos = 60 segundos)
        self.bandwidth_history: deque = deque(maxlen=120)
        # Paquetes por segundo actual
        self.current_pps: int = 0
        self.current_bps: int = 0
        # Contadores acumulados
        self.total_packets: int = 0
        self.total_bytes: int = 0
        # Alertas
        self.alerts: deque = deque(maxlen=50)
        # Puertos detectados
        self.ports: Dict[int, int] = defaultdict(int)
        # Paquetes recientes para análisis
        self.recent_packets: deque = deque(maxlen=200)
        # Ventana de detección de anomalías
        self.pps_window: deque = deque(maxlen=30)
        # Contadores por intervalo
        self._interval_packets: int = 0
        self._interval_bytes: int = 0
        # Distribución por capa
        self.layer_stats = {
            "Enlace (L2)": 0,
            "Red (L3)": 0,
            "Transporte (L4)": 0,
            "Aplicación (L7)": 0
        }
        # Top conexiones (src -> dst)
        self.connections: Dict[str, int] = defaultdict(int)
 
state = NetworkState()
 
# ═══════════════════════════════════════════════════════════════════
# ANÁLISIS DE PAQUETES (SCAPY)
# ═══════════════════════════════════════════════════════════════════
 
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 1883: "MQTT", 5060: "SIP"
}
 
def identify_protocol(sport: int, dport: int) -> str:
    """Identifica el protocolo de capa de aplicación por puerto."""
    if dport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[dport]
    if sport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[sport]
    return "Otro"
 
def add_alert(level: str, message: str, detail: str = ""):
    """Registra una alerta en el sistema."""
    alert = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level,       # info, warning, critical
        "message": message,
        "detail": detail
    }
    state.alerts.appendleft(alert)
 
def check_anomalies():
    """Detección de anomalías basada en desviación estándar del tráfico."""
    if len(state.pps_window) < 10:
        return
    values = list(state.pps_window)
    mean = sum(values) / len(values)
    if mean == 0:
        return
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    std_dev = math.sqrt(variance)
    current = values[-1]
    # Pico de tráfico > 2 desviaciones estándar
    if std_dev > 0 and current > mean + 2 * std_dev:
        add_alert("warning", "Pico de tráfico detectado",
                  f"{current} pkt/s (promedio: {mean:.0f}, σ: {std_dev:.0f})")
    # Tráfico excesivo > 3 desviaciones estándar
    if std_dev > 0 and current > mean + 3 * std_dev:
        add_alert("critical", "Tráfico anómalo — posible flood/DDoS",
                  f"{current} pkt/s excede 3σ del promedio")
 
def process_packet_real(packet):
    """Procesa un paquete real capturado por Scapy."""
    with state.lock:
        pkt_len = len(packet)
        state._interval_packets += 1
        state._interval_bytes += pkt_len
        state.total_packets += 1
        state.total_bytes += pkt_len
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
 
        # ── Capa 2: Enlace ──
        src_mac = dst_mac = "N/A"
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            state.layer_stats["Enlace (L2)"] += 1
 
        # ── ARP ──
        if packet.haslayer(ARP):
            state.protocols["ARP"] += 1
            arp = packet[ARP]
            if arp.op == 1:
                add_alert("info", f"ARP Request: ¿Quién tiene {arp.pdst}?",
                          f"Desde {arp.psrc} ({src_mac})")
            return
 
        # ── Capa 3: Red ──
        src_ip = dst_ip = "N/A"
        ttl = 0
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            state.layer_stats["Red (L3)"] += 1
 
            # Registrar dispositivo
            for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
                if ip != "N/A" and not ip.startswith("255.") and ip != "0.0.0.0":
                    if ip not in state.devices:
                        state.devices[ip] = {
                            "mac": mac, "first_seen": timestamp,
                            "last_seen": timestamp, "packets": 0, "bytes": 0
                        }
                        add_alert("info", f"Nuevo dispositivo: {ip}", f"MAC: {mac}")
                    state.devices[ip]["last_seen"] = timestamp
                    state.devices[ip]["packets"] += 1
                    state.devices[ip]["bytes"] += pkt_len
 
        # ── Capa 4: Transporte ──
        sport = dport = 0
        proto_name = "Otro"
        flags = ""
 
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = str(packet[TCP].flags)
            proto_name = "TCP"
            state.protocols["TCP"] += 1
            state.layer_stats["Transporte (L4)"] += 1
            state.ports[dport] += 1
            # Detectar escaneo de puertos (SYN sin ACK)
            if "S" in flags and "A" not in flags:
                state.protocols["TCP-SYN"] += 1
 
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = "UDP"
            state.protocols["UDP"] += 1
            state.layer_stats["Transporte (L4)"] += 1
            state.ports[dport] += 1
 
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            state.protocols["ICMP"] += 1
            state.layer_stats["Transporte (L4)"] += 1
 
        # ── Capa 7: Aplicación ──
        app_proto = identify_protocol(sport, dport)
        if app_proto != "Otro":
            state.protocols[app_proto] += 1
            state.layer_stats["Aplicación (L7)"] += 1
 
        if packet.haslayer(DNS):
            state.protocols["DNS"] += 1
            state.layer_stats["Aplicación (L7)"] += 1
 
        # Registrar conexión
        if src_ip != "N/A" and dst_ip != "N/A":
            conn_key = f"{src_ip}→{dst_ip}"
            state.connections[conn_key] += 1
 
        # Paquete reciente para la tabla
        state.recent_packets.appendleft({
            "time": timestamp,
            "src": f"{src_ip}:{sport}" if sport else src_ip,
            "dst": f"{dst_ip}:{dport}" if dport else dst_ip,
            "proto": app_proto if app_proto != "Otro" else proto_name,
            "size": pkt_len,
            "ttl": ttl,
            "flags": flags,
            "layer": "L7" if app_proto != "Otro" else ("L4" if proto_name != "Otro" else "L3")
        })
 
 
# ═══════════════════════════════════════════════════════════════════
# MODO SIMULACIÓN (cuando Scapy no está disponible)
# ═══════════════════════════════════════════════════════════════════
 
SIM_DEVICES = [
    {"ip": "192.168.1.1", "mac": "AA:BB:CC:00:00:01", "role": "Router/Gateway"},
    {"ip": "192.168.1.10", "mac": "AA:BB:CC:00:00:0A", "role": "PC-Admin"},
    {"ip": "192.168.1.20", "mac": "AA:BB:CC:00:00:14", "role": "Servidor-Web"},
    {"ip": "192.168.1.30", "mac": "AA:BB:CC:00:00:1E", "role": "PC-Lab01"},
    {"ip": "192.168.1.31", "mac": "AA:BB:CC:00:00:1F", "role": "PC-Lab02"},
    {"ip": "192.168.1.40", "mac": "AA:BB:CC:00:00:28", "role": "Impresora"},
    {"ip": "192.168.1.50", "mac": "AA:BB:CC:00:00:32", "role": "IoT-Sensor"},
    {"ip": "192.168.1.100", "mac": "AA:BB:CC:00:00:64", "role": "Smartphone"},
    {"ip": "10.0.0.1", "mac": "DD:EE:FF:00:00:01", "role": "DNS-Externo"},
    {"ip": "172.217.14.206", "mac": "DD:EE:FF:00:00:02", "role": "Google"},
]
 
SIM_TRAFFIC_PROFILES = [
    {"proto": "HTTPS", "dport": 443, "sport_range": (49152, 65535), "weight": 35, "size_range": (60, 1500)},
    {"proto": "HTTP", "dport": 80, "sport_range": (49152, 65535), "weight": 15, "size_range": (60, 1200)},
    {"proto": "DNS", "dport": 53, "sport_range": (49152, 65535), "weight": 20, "size_range": (40, 512)},
    {"proto": "SSH", "dport": 22, "sport_range": (49152, 65535), "weight": 5, "size_range": (60, 300)},
    {"proto": "ICMP", "dport": 0, "sport_range": (0, 0), "weight": 5, "size_range": (64, 64)},
    {"proto": "TCP", "dport": 3306, "sport_range": (49152, 65535), "weight": 8, "size_range": (60, 800)},
    {"proto": "SMTP", "dport": 25, "sport_range": (49152, 65535), "weight": 3, "size_range": (100, 2000)},
    {"proto": "ARP", "dport": 0, "sport_range": (0, 0), "weight": 4, "size_range": (42, 42)},
    {"proto": "UDP", "dport": 1883, "sport_range": (49152, 65535), "weight": 5, "size_range": (50, 200)},
]
 
def generate_simulated_packet():
    """Genera un paquete simulado realista."""
    # Seleccionar perfil de tráfico ponderado
    weights = [p["weight"] for p in SIM_TRAFFIC_PROFILES]
    profile = random.choices(SIM_TRAFFIC_PROFILES, weights=weights, k=1)[0]
 
    # Seleccionar dispositivos (origen interno, destino puede ser externo)
    internal = [d for d in SIM_DEVICES if d["ip"].startswith("192.168")]
    external = [d for d in SIM_DEVICES if not d["ip"].startswith("192.168")]
 
    if profile["proto"] == "ARP":
        src_dev = random.choice(internal)
        dst_dev = random.choice(internal)
        proto = "ARP"
        layer = "L2"
    elif random.random() < 0.7:  # 70% tráfico saliente
        src_dev = random.choice(internal)
        dst_dev = random.choice(external) if external and random.random() < 0.5 else random.choice(internal)
    else:
        dst_dev = random.choice(internal)
        src_dev = random.choice(external) if external and random.random() < 0.3 else random.choice(internal)
 
    sport = random.randint(*profile["sport_range"]) if profile["sport_range"][1] > 0 else 0
    dport = profile["dport"]
    pkt_size = random.randint(*profile["size_range"])
    ttl = random.choice([64, 128, 255]) - random.randint(0, 15)
    flags = random.choice(["S", "SA", "A", "PA", "FA", "R", ""]) if "TCP" in profile["proto"] or profile["dport"] in [80, 443, 22, 25, 3306] else ""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
 
    proto_name = profile["proto"]
    if proto_name in ["HTTP", "HTTPS", "DNS", "SSH", "SMTP"]:
        layer = "L7"
        transport = "TCP" if proto_name != "DNS" else "UDP"
    elif proto_name in ["TCP", "UDP"]:
        layer = "L4"
        transport = proto_name
        proto_name = identify_protocol(sport, dport)
        if proto_name == "Otro":
            proto_name = transport
    elif proto_name == "ICMP":
        layer = "L4"
        transport = "ICMP"
    elif proto_name == "ARP":
        layer = "L2"
        transport = "ARP"
    else:
        layer = "L3"
        transport = "IP"
 
    return {
        "time": timestamp,
        "src_ip": src_dev["ip"],
        "dst_ip": dst_dev["ip"],
        "src_mac": src_dev["mac"],
        "dst_mac": dst_dev["mac"],
        "sport": sport,
        "dport": dport,
        "proto": proto_name,
        "transport": transport,
        "size": pkt_size,
        "ttl": ttl,
        "flags": flags,
        "layer": layer
    }
 
def process_simulated_packet(pkt: dict):
    """Procesa un paquete simulado igual que uno real."""
    with state.lock:
        state._interval_packets += 1
        state._interval_bytes += pkt["size"]
        state.total_packets += 1
        state.total_bytes += pkt["size"]
 
        # Registrar dispositivo
        for ip, mac in [(pkt["src_ip"], pkt["src_mac"]), (pkt["dst_ip"], pkt["dst_mac"])]:
            if ip not in state.devices:
                state.devices[ip] = {
                    "mac": mac, "first_seen": pkt["time"],
                    "last_seen": pkt["time"], "packets": 0, "bytes": 0
                }
                add_alert("info", f"Nuevo dispositivo: {ip}", f"MAC: {mac}")
            state.devices[ip]["last_seen"] = pkt["time"]
            state.devices[ip]["packets"] += 1
            state.devices[ip]["bytes"] += pkt["size"]
 
        # Protocolos
        state.protocols[pkt["proto"]] += 1
        if pkt["transport"] != pkt["proto"]:
            state.protocols[pkt["transport"]] += 1
 
        # Puertos
        if pkt["dport"] > 0:
            state.ports[pkt["dport"]] += 1
 
        # Capas
        state.layer_stats["Enlace (L2)"] += 1
        if pkt["layer"] in ["L3", "L4", "L7"]:
            state.layer_stats["Red (L3)"] += 1
        if pkt["layer"] in ["L4", "L7"]:
            state.layer_stats["Transporte (L4)"] += 1
        if pkt["layer"] == "L7":
            state.layer_stats["Aplicación (L7)"] += 1
 
        # Conexiones
        conn_key = f"{pkt['src_ip']}→{pkt['dst_ip']}"
        state.connections[conn_key] += 1
 
        # Alertas de SYN scan
        if pkt["flags"] == "S":
            state.protocols["TCP-SYN"] += 1
 
        # Paquete reciente
        state.recent_packets.appendleft({
            "time": pkt["time"],
            "src": f"{pkt['src_ip']}:{pkt['sport']}" if pkt["sport"] else pkt["src_ip"],
            "dst": f"{pkt['dst_ip']}:{pkt['dport']}" if pkt["dport"] else pkt["dst_ip"],
            "proto": pkt["proto"],
            "size": pkt["size"],
            "ttl": pkt["ttl"],
            "flags": pkt["flags"],
            "layer": pkt["layer"]
        })
 
 
# ═══════════════════════════════════════════════════════════════════
# HILO DE CAPTURA / SIMULACIÓN
# ═══════════════════════════════════════════════════════════════════
 
capture_active = False
 
def start_capture_thread():
    """Inicia la captura de paquetes o la simulación."""
    global capture_active
    capture_active = True
 
    if SCAPY_AVAILABLE:
        print("[*] Iniciando captura real con Scapy...")
        try:
            sniff(prn=process_packet_real, store=False,
                  stop_filter=lambda _: not capture_active)
        except PermissionError:
            print("[!] Sin permisos de root para captura. Cambiando a simulación.")
            run_simulation()
        except Exception as e:
            print(f"[!] Error en captura: {e}. Cambiando a simulación.")
            run_simulation()
    else:
        run_simulation()
 
def run_simulation():
    """Genera tráfico simulado realista."""
    print("[*] Modo simulación activo — generando tráfico sintético...")
    tick = 0
    while capture_active:
        # Variación de carga: simula picos y valles
        hour_factor = 1.0 + 0.3 * math.sin(tick / 30)  # Onda lenta
        burst_factor = 1.0
        if random.random() < 0.02:  # 2% chance de ráfaga
            burst_factor = random.uniform(3.0, 6.0)
            add_alert("warning", "Ráfaga de tráfico detectada",
                      f"Factor: {burst_factor:.1f}x")
 
        packets_this_tick = int(random.randint(8, 25) * hour_factor * burst_factor)
        for _ in range(packets_this_tick):
            pkt = generate_simulated_packet()
            process_simulated_packet(pkt)
 
        # Evento especial ocasional
        if random.random() < 0.005:
            add_alert("critical", "Posible escaneo de puertos",
                      f"Múltiples SYN desde 192.168.1.{random.randint(30,100)}")
 
        time.sleep(0.5)
        tick += 1
 
def metrics_updater():
    """Actualiza métricas cada segundo."""
    while True:
        time.sleep(1)
        with state.lock:
            pps = state._interval_packets
            bps = state._interval_bytes
            state.current_pps = pps
            state.current_bps = bps
            state._interval_packets = 0
            state._interval_bytes = 0
            state.pps_window.append(pps)
            state.bandwidth_history.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "pps": pps,
                "kbps": round(bps * 8 / 1024, 2)
            })
        check_anomalies()
 
 
# ═══════════════════════════════════════════════════════════════════
# RUTAS Y WEBSOCKET
# ═══════════════════════════════════════════════════════════════════
 
@app.on_event("startup")
async def startup():
    # Iniciar hilos en background
    threading.Thread(target=start_capture_thread, daemon=True).start()
    threading.Thread(target=metrics_updater, daemon=True).start()
 
@app.get("/")
async def root():
    return FileResponse("templates/index.html")
 
@app.get("/api/snapshot")
async def api_snapshot():
    """Snapshot completo del estado actual."""
    return build_snapshot()
 
def build_snapshot() -> dict:
    """Construye el snapshot de datos para enviar al frontend."""
    with state.lock:
        # Top protocolos
        sorted_protos = sorted(state.protocols.items(), key=lambda x: x[1], reverse=True)[:12]
        # Top puertos
        sorted_ports = sorted(state.ports.items(), key=lambda x: x[1], reverse=True)[:10]
        # Top conexiones
        sorted_conns = sorted(state.connections.items(), key=lambda x: x[1], reverse=True)[:10]
        # Dispositivos
        devices_list = [
            {"ip": ip, **info} for ip, info in state.devices.items()
        ]
        devices_list.sort(key=lambda x: x["bytes"], reverse=True)
 
        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "mode": "real" if SCAPY_AVAILABLE else "simulación",
            "summary": {
                "total_packets": state.total_packets,
                "total_bytes": state.total_bytes,
                "current_pps": state.current_pps,
                "current_kbps": round(state.current_bps * 8 / 1024, 2),
                "device_count": len(state.devices),
                "alert_count": len(state.alerts),
            },
            "bandwidth": list(state.bandwidth_history),
            "protocols": [{"name": k, "count": v} for k, v in sorted_protos],
            "ports": [{"port": p, "count": c, "service": WELL_KNOWN_PORTS.get(p, "Desconocido")} for p, c in sorted_ports],
            "layers": state.layer_stats.copy(),
            "devices": devices_list[:20],
            "connections": [{"flow": k, "packets": v} for k, v in sorted_conns],
            "packets": list(state.recent_packets)[:30],
            "alerts": list(state.alerts)[:20],
        }
 
# WebSocket para actualizaciones en tiempo real
connected_clients: Set[WebSocket] = set()
 
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    print(f"[+] Cliente WebSocket conectado ({len(connected_clients)} activos)")
    try:
        # Enviar snapshot inicial
        await websocket.send_json(build_snapshot())
        # Enviar actualizaciones cada segundo
        while True:
            await asyncio.sleep(1)
            data = build_snapshot()
            await websocket.send_json(data)
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        print(f"[-] Cliente desconectado ({len(connected_clients)} activos)")
    except Exception:
        connected_clients.discard(websocket)
 
 
# ═══════════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA
# ═══════════════════════════════════════════════════════════════════
 
if __name__ == "__main__":
    import uvicorn
    print("╔══════════════════════════════════════════════╗")
    print("║   MONITOR DE RED EN TIEMPO REAL v1.0        ║")
    print("║   Redes Convergentes — CUC 2026-1           ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"[*] Scapy: {'Disponible' if SCAPY_AVAILABLE else 'No disponible (modo simulación)'}")
    print("[*] Dashboard: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
 
