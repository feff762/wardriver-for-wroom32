import network
import bluetooth
import socket
import time
import gc
import uselect

# --- Configuration ---
AP_SSID = "UPTIME"
WEB_KEY = "8472"          # Access at: http://192.168.4
SERVER_PORT = 180
MAX_CLIENTS = 1
BLE_SCAN_MS = 2000

# History caps to protect ESP32-WROOM-32 RAM (~320KB total)
MAX_WIFI_HISTORY = 100
MAX_BLE_HISTORY = 100

try:
    server.close()
except Exception:
    pass

# --- Persistent State (Survives across refreshes) ---
# seen_wifi[bssid] = [ssid, channel, best_rssi, auth_str, seen_count, is_active]
seen_wifi = {}

# seen_ble[mac] = [name, best_rssi, addr_type, seen_count, is_active]
seen_ble = {}

# Initialize Wi-Fi Station (Scanner)
sta = network.WLAN(network.STA_IF)
sta.active(True)

# Initialize Open & Visible Wi-Fi Access Point
ap = network.WLAN(network.AP_IF)
ap.active(True)
ap.config(
    essid=AP_SSID,
    authmode=network.AUTH_OPEN,
    hidden=False,
    max_clients=MAX_CLIENTS
)

# Initialize BLE
ble = bluetooth.BLE()
ble.active(True)

def escape_html(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def decode_ble_name(adv_data):
    i = 0
    length = len(adv_data)
    while i + 1 < length:
        field_len = adv_data[i]
        if field_len == 0 or i + field_len >= length:
            break
        ad_type = adv_data[i + 1]
        if ad_type in (0x08, 0x09):
            try:
                return bytes(adv_data[i + 2 : i + 1 + field_len]).decode("utf-8", "ignore")
            except Exception:
                return ""
        i += field_len + 1
    return ""

def ble_irq(event, data):
    if event == 5:  # _IRQ_SCAN_RESULT
        addr_type, addr, adv_type, rssi, adv_data = data
        mac = ":".join("{:02X}".format(b) for b in addr)
        name = decode_ble_name(adv_data)

        if mac in seen_ble:
            entry = seen_ble[mac]
            # Keep strongest RSSI seen, or update if currently active
            if rssi > entry[1] or not entry[4]:
                entry[1] = rssi
            if name and not entry[0]:
                entry[0] = name
            if not entry[4]:
                entry[3] += 1
                entry[4] = True
        elif len(seen_ble) < MAX_BLE_HISTORY:
            seen_ble[mac] = [
                name,
                rssi,
                "Random" if addr_type else "Public",
                1,
                True
            ]

ble.irq(ble_irq)

def auth_to_str(authmode):
    modes = {
        0: "OPEN", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK",
        4: "WPA/WPA2-PSK", 5: "WPA2-ENT", 6: "WPA3-PSK", 7: "WPA2/WPA3-PSK"
    }
    return modes.get(authmode, "UNKNOWN")

def run_scans():
    # Mark all previously seen devices as inactive before scanning
    for mac in seen_wifi:
        seen_wifi[mac][5] = False
    for mac in seen_ble:
        seen_ble[mac][4] = False

    # 1. Wi-Fi Scan
    try:
        networks = sta.scan()
    except Exception:
        networks = []

    for net in networks:
        raw_ssid = net[0].decode("utf-8", "ignore")
        bssid = ":".join("{:02X}".format(b) for b in net[1])
        ch = net[2]
        rssi = net[3]
        auth = auth_to_str(net[4])

        if bssid in seen_wifi:
            entry = seen_wifi[bssid]
            if raw_ssid and not entry[0]:
                entry[0] = raw_ssid
            entry[1] = ch
            if rssi > entry[2] or not entry[5]:
                entry[2] = rssi
            entry[3] = auth
            entry[4] += 1
            entry[5] = True
        elif len(seen_wifi) < MAX_WIFI_HISTORY:
            seen_wifi[bssid] = [raw_ssid, ch, rssi, auth, 1, True]

    del networks
    gc.collect()

    # 2. BLE Scan
    try:
        ble.gap_scan(BLE_SCAN_MS, 30000, 30000, False)
        time.sleep_ms(BLE_SCAN_MS + 150)
        ble.gap_scan(None)
    except Exception:
        pass
    gc.collect()

def serve_dashboard(conn, do_scan=True):
    if do_scan:
        run_scans()

    conn.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n")
    head = (
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ajaxx Scanner</title><style>"
        "body{font-family:monospace;background:#111;color:#0f0;padding:12px;}"
        "h3{color:#0ff;margin-top:20px;}"
        "table{width:100%;border-collapse:collapse;margin-top:6px;}"
        "th,td{border:1px solid #333;padding:6px;text-align:left;font-size:13px;}"
        "th{background:#222;}.btn{display:inline-block;padding:8px 12px;background:#0f0;color:#000;"
        "text-decoration:none;font-weight:bold;margin-right:8px;margin-bottom:6px;}"
        ".btn-warn{background:#f55;color:#fff;}"
        ".act{color:#0f0;font-weight:bold;}.old{color:#888;}"
        "</style></head><body>"
        "<h2>ESP32-WROOM-32 Scanner</h2>"
        "<p>Free RAM: " + str(gc.mem_free()) + " B</p>"
        "<a class='btn' href='/?key=" + WEB_KEY + "'>Scan &amp; Refresh</a>"
        "<a class='btn' href='/csv?key=" + WEB_KEY + "'>Download All CSV</a>"
        "<a class='btn btn-warn' href='/clear?key=" + WEB_KEY + "'>Clear History</a>"
        "<h3>Wi-Fi Access Points (" + str(len(seen_wifi)) + " seen)</h3>"
        "<table><tr><th>Status</th><th>SSID</th><th>MAC</th><th>CH</th><th>Peak RSSI</th><th>Security</th><th>Hits</th></tr>"
    )
    conn.send(head.encode())

    # Sort active networks first, then by strongest RSSI
    sorted_wifi = sorted(seen_wifi.items(), key=lambda x: (x[1][5], x[1][2]), reverse=True)
    for bssid, info in sorted_wifi:
        ssid = escape_html(info[0]) if info[0] else "<i>[Hidden]</i>"
        status = "<span class='act'>ACTIVE</span>" if info[5] else "<span class='old'>SEEN</span>"
        row = "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} dBm</td><td>{}</td><td>{}</td></tr>".format(
            status, ssid, bssid, info[1], info[2], info[3], info[4]
        )
        conn.send(row.encode())

    conn.send(b"</table><h3>Bluetooth Low Energy Devices (" + str(len(seen_ble)).encode() + b" seen)</h3>")
    conn.send(b"<table><tr><th>Status</th><th>Device Name</th><th>MAC</th><th>Addr Type</th><th>Peak RSSI</th><th>Hits</th></tr>")

    sorted_ble = sorted(seen_ble.items(), key=lambda x: (x[1][4], x[1][1]), reverse=True)
    for mac, info in sorted_ble:
        d_name = escape_html(info[0]) if info[0] else "<i>[Unnamed Beacon]</i>"
        status = "<span class='act'>ACTIVE</span>" if info[4] else "<span class='old'>SEEN</span>"
        row = "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} dBm</td><td>{}</td></tr>".format(
            status, d_name, mac, info[2], info[1], info[3]
        )
        conn.send(row.encode())

    conn.send(b"</table></body></html>")
    gc.collect()

def serve_csv(conn):
    conn.send(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/csv\r\n"
        b"Content-Disposition: attachment; filename=\"wardrive_dual.csv\"\r\n"
        b"Connection: close\r\n\r\n"
    )
    conn.send(b"WigleWifi-1.4,appRelease=1.0,model=ESP32-WROOM-32,release=MicroPython,device=WROOM32,display=Web,board=ESP32,brand=Espressif\n")
    conn.send(b"MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n")

    for bssid, info in seen_wifi.items():
        ssid = info[0].replace('"', '')
        auth = "[" + info[3] + "][ESS]"
        line = '{},"{}",{},1970-01-01 00:00:00,{},{},0.000000,0.000000,0,10,WIFI\n'.format(
            bssid, ssid, auth, info[1], info[2]
        )
        conn.send(line.encode())

    for mac, info in seen_ble.items():
        d_name = info[0].replace('"', '')
        line = '{},"{}",[BLE],1970-01-01 00:00:00,0,{},0.000000,0.000000,0,10,BLE\n'.format(
            mac, d_name, info[1]
        )
        conn.send(line.encode())
    gc.collect()

# --- Start Web Server ---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", SERVER_PORT))
server.listen(1)

ap_ip = ap.ifconfig()[0]
print("Scanner active at http://{}:{}/?key={}".format(ap_ip, SERVER_PORT, WEB_KEY))

while True:
    try:
        conn, addr = server.accept()
        conn.settimeout(3.0)
        request = conn.recv(512).decode("utf-8", "ignore")

        if "wpad.dat" in request or ".pac" in request:
            pac = b'HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nConnection: close\r\n\r\nfunction FindProxyForURL(url, host) { return "DIRECT"; }'
            conn.send(pac)
        elif ("key=" + WEB_KEY) not in request:
            conn.send(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n403 Forbidden")
        elif "GET /csv" in request:
            serve_csv(conn)
        elif "GET /clear" in request:
            seen_wifi.clear()
            seen_ble.clear()
            gc.collect()
            serve_dashboard(conn, do_scan=False)
        else:
            serve_dashboard(conn, do_scan=True)

        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
    gc.collect()
