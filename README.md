# Monitor de Red en Tiempo Real 🖥️

**Dashboard de monitoreo de tráfico de red local con alertas automáticas.**

Proyecto Integrador — Redes Convergentes 2026-1  
Universidad de la Costa (CUC)  
Autores: Rafael Romo & Álvaro Araque

---

## ¿Qué hace?

- Captura paquetes de la red local en tiempo real usando Scapy
- Muestra el ancho de banda consumido en un gráfico de líneas (Chart.js)
- Clasifica el tráfico por protocolo (TCP, UDP, ICMP, HTTP, DNS, etc.)
- Detecta dispositivos conectados por IP y MAC (ARP + análisis pasivo)
- Genera alertas automáticas (ancho de banda alto, posible ICMP flood, nuevos dispositivos)
- Actualiza todo en tiempo real via WebSockets (Flask-SocketIO)

## Capas TCP/IP involucradas

| Capa | Funcionalidad |
|------|---------------|
| Acceso a Red | Captura de tramas Ethernet, detección MAC, ARP |
| Internet | Extracción de IPs, identificación ICMP |
| Transporte | Análisis de puertos TCP/UDP |
| Aplicación | Inferencia de HTTP, DNS, DHCP, SSH, FTP |

---

## Instalación

### Requisitos previos
- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Linux: libpcap instalado (`sudo apt install libpcap-dev`)
- Windows: Npcap instalado (https://npcap.com/)

### Pasos

1. **Descomprime** el archivo ZIP en una carpeta.

2. **Instala las dependencias:**
   ```bash
   cd netmonitor
   pip install -r requirements.txt
   ```

3. **Ejecuta la aplicación** (requiere permisos de administrador para capturar paquetes):

   **Linux / Mac:**
   ```bash
   sudo python app.py
   ```

   **Windows** (abrir CMD como Administrador):
   ```cmd
   python app.py
   ```

4. **Abre el dashboard** en tu navegador:
   ```
   http://localhost:5000
   ```

---

## Configuración

En `app.py` puedes ajustar estas variables al inicio del archivo:

| Variable | Descripción | Default |
|----------|-------------|---------|
| `INTERFACE` | Interfaz de red a capturar (`None` = automática) | `None` |
| `NETWORK` | Rango de red para detección | `192.168.1.0/24` |
| `UPDATE_INTERVAL` | Segundos entre actualizaciones | `1` |
| `BANDWIDTH_ALERT_MBPS` | Umbral de alerta de ancho de banda | `50` |
| `ICMP_ALERT_THRESHOLD` | Paquetes ICMP/min para alerta | `100` |

---

## Estructura del proyecto

```
netmonitor/
├── app.py              # Backend: Flask + Scapy + SocketIO
├── templates/
│   └── index.html      # Dashboard: Chart.js + WebSockets
├── requirements.txt    # Dependencias Python
└── README.md           # Este archivo
```

## Tecnologías

- **Python 3** — Lenguaje principal
- **Scapy** — Captura y disección de paquetes
- **Flask** — Framework web
- **Flask-SocketIO** — WebSockets para tiempo real
- **Chart.js** — Gráficos interactivos
- **Socket.IO** — Cliente WebSocket en el navegador
