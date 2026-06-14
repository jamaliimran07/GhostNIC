#!/usr/bin/env python3
import os, re, json, time, random, argparse, subprocess, urllib.request
from pathlib import Path
from datetime import datetime

STATE_FILE = Path("/var/tmp/ghostnic_state.json")
TRAIL_FILE = Path("/var/tmp/ghosttrail.log")
BASELINE_FILE = Path("/var/tmp/ghostbaseline.json")
REPORT_FILE = Path("ghostnic_report.html")

BANNER = r"""
   ________               __  _   _   ________
  / ____/ /_  ____  _____/ /_(_) / | / /  _/ __ \
 / / __/ __ \/ __ \/ ___/ __/ / /  |/ // // / / /
/ /_/ / / / / /_/ (__  ) /_/ / / /|  // // /_/ /
\____/_/ /_/\____/____/\__/_/ /_/ |_/___/_____/

        GhostNIC v1.1 
        Network Identity, VPN Detection & Report Toolkit
        Created by: Imran Sarwer
"""

def run(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)

def root_check():
    if os.geteuid() != 0:
        print("[!] Run with sudo: sudo python3 ghostnic.py")
        exit(1)

def interfaces():
    out = run("ip -o link show | awk -F': ' '{print $2}'").stdout.strip()
    return [i for i in out.splitlines() if i != "lo"]

def get_mac(iface):
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip()
    except:
        return "Unknown"

def get_ip(iface):
    out = run(f"ip -4 addr show {iface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'").stdout.strip()
    return out if out else "No IPv4"

def get_public_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode()
    except:
        return "No internet / Cannot detect"

def get_dns():
    try:
        data = Path("/etc/resolv.conf").read_text()
        dns = re.findall(r"nameserver\s+(.+)", data)
        return ", ".join(dns) if dns else "No DNS"
    except:
        return "Unknown"

def get_gateway():
    out = run("ip route | awk '/default/ {print $3}' | head -n 1").stdout.strip()
    return out if out else "No Gateway"

def load_json(path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            return {}
    return {}

def save_json(path, data):
    path.write_text(json.dumps(data, indent=4))

def save_original(iface):
    state = load_json(STATE_FILE)
    if iface not in state:
        state[iface] = {
            "original_mac": get_mac(iface),
            "first_private_ip": get_ip(iface),
            "first_public_ip": get_public_ip(),
            "first_dns": get_dns(),
            "first_gateway": get_gateway(),
            "created_at": str(datetime.now())
        }
        save_json(STATE_FILE, state)

def original_mac(iface):
    return load_json(STATE_FILE).get(iface, {}).get("original_mac", "Not saved")

def first_private_ip(iface):
    return load_json(STATE_FILE).get(iface, {}).get("first_private_ip", "Not saved")

def first_public_ip(iface):
    return load_json(STATE_FILE).get(iface, {}).get("first_public_ip", "Not saved")

def random_mac():
    first = random.choice(["02", "06", "0A", "0E"])
    rest = [f"{random.randint(0,255):02x}" for _ in range(5)]
    return ":".join([first] + rest)

def detect_vpn():
    links = run("ip -o link show | awk -F': ' '{print $2}'").stdout.strip().splitlines()

    for i in links:
        if i.startswith("wg"):
            return {"status": "Connected", "type": "WireGuard", "interface": i, "ip": get_ip(i)}
        if i.startswith("tun"):
            return {"status": "Connected", "type": "OpenVPN/TUN", "interface": i, "ip": get_ip(i)}
        if i.startswith("ppp"):
            return {"status": "Connected", "type": "PPP VPN", "interface": i, "ip": get_ip(i)}
        if i.startswith("tap"):
            return {"status": "Connected", "type": "TAP VPN", "interface": i, "ip": get_ip(i)}

    return {"status": "Not Connected", "type": "None", "interface": "-", "ip": "-"}

def ghosttrail(iface, action):
    vpn = detect_vpn()
    line = (
        f"[{datetime.now()}] {action} | "
        f"IFACE={iface} | MAC={get_mac(iface)} | PRIVATE_IP={get_ip(iface)} | "
        f"PUBLIC_IP={get_public_ip()} | DNS={get_dns()} | GATEWAY={get_gateway()} | "
        f"VPN={vpn['status']} {vpn['type']} {vpn['interface']} {vpn['ip']}\n"
    )
    TRAIL_FILE.open("a").write(line)

def show_trail():
    print("\n========== GhostTrail Logs ==========")
    print(TRAIL_FILE.read_text() if TRAIL_FILE.exists() else "No logs found.")
    print("=====================================\n")

def change_mac(iface):
    save_original(iface)
    new = random_mac()

    print(f"[*] Changing MAC to: {new}")
    run(f"ip link set {iface} down")
    result = run(f"ip link set dev {iface} address {new}")
    run(f"ip link set {iface} up")

    if result.returncode == 0:
        print(f"[+] MAC changed successfully: {get_mac(iface)}")
        ghosttrail(iface, "MAC_CHANGED")
    else:
        print("[!] MAC change failed.")
        print(result.stderr)

def renew_ip(iface):
    print("[*] Renewing private IP using DHCP...")
    run(f"dhclient -r {iface}")
    run(f"dhclient {iface}")
    print(f"[+] Current private IP: {get_ip(iface)}")
    ghosttrail(iface, "IP_RENEWED")

def flush_dns():
    run("resolvectl flush-caches")
    run("systemd-resolve --flush-caches")
    print("[+] DNS cache flush attempted.")

def create_baseline(iface):
    save_original(iface)
    vpn = detect_vpn()

    data = {
        "interface": iface,
        "mac": get_mac(iface),
        "private_ip": get_ip(iface),
        "public_ip": get_public_ip(),
        "dns": get_dns(),
        "gateway": get_gateway(),
        "vpn_status": vpn["status"],
        "vpn_type": vpn["type"],
        "vpn_interface": vpn["interface"],
        "vpn_ip": vpn["ip"],
        "created_at": str(datetime.now())
    }

    save_json(BASELINE_FILE, data)
    ghosttrail(iface, "BASELINE_CREATED")
    print("[+] GhostBaseline created.")

def compare_baseline(iface):
    if not BASELINE_FILE.exists():
        print("[!] No baseline found. Create GhostBaseline first.")
        return []

    base = load_json(BASELINE_FILE)
    vpn = detect_vpn()

    current = {
        "interface": iface,
        "mac": get_mac(iface),
        "private_ip": get_ip(iface),
        "public_ip": get_public_ip(),
        "dns": get_dns(),
        "gateway": get_gateway(),
        "vpn_status": vpn["status"],
        "vpn_type": vpn["type"],
        "vpn_interface": vpn["interface"],
        "vpn_ip": vpn["ip"]
    }

    changes = []

    for key, old in base.items():
        if key == "created_at":
            continue

        new = current.get(key)

        if new is not None and str(old) != str(new):
            changes.append((key, old, new))

    print("\n========== GhostBaseline Compare ==========")

    if not changes:
        print("[+] No deviation detected.")
    else:
        for key, old, new in changes:
            print(f"[!] {key}: {old} -> {new}")

    print("===========================================\n")
    return changes

def ghost_ai_advisor(iface):
    save_original(iface)
    vpn = detect_vpn()

    current_public = get_public_ip()
    original_public = first_public_ip(iface)

    print("\n========== GhostAI Advisor ==========")
    print(f"Original MAC        : {original_mac(iface)}")
    print(f"Current MAC         : {get_mac(iface)}")
    print(f"Original Private IP : {first_private_ip(iface)}")
    print(f"Current Private IP  : {get_ip(iface)}")
    print(f"Original Public IP  : {original_public}")
    print(f"Current Public IP   : {current_public}")
    print(f"DNS Servers         : {get_dns()}")
    print(f"Gateway             : {get_gateway()}")
    print(f"VPN Status          : {vpn['status']}")
    print(f"VPN Type            : {vpn['type']}")
    print(f"VPN Interface       : {vpn['interface']}")
    print(f"VPN IP              : {vpn['ip']}")

    if get_mac(iface) != original_mac(iface):
        print("[AI] MAC spoofing is active.")
    else:
        print("[AI] Original MAC is active.")

    if get_ip(iface) != first_private_ip(iface):
        print("[AI] Private IP has changed.")
    else:
        print("[AI] Private IP is still the same.")

    if vpn["status"] == "Connected":
        print("[AI] VPN tunnel detected.")
    else:
        print("[AI] No VPN tunnel detected.")

    if current_public != original_public:
        print("[AI] Public IP has changed externally.")
        print("[AI] GhostNIC did not modify public IP.")
        print("[AI] Possible causes: ISP renewal, router reconnect, VPN, or mobile hotspot change.")
    else:
        print("[AI] Public IP is still the same.")

    print("[AI] Note: GhostNIC v1.1 does not force-change public IP.")
    print("=====================================\n")

def ghost_mode(iface):
    print("\n========== GhostMode One-Click ==========")
    change_mac(iface)
    renew_ip(iface)
    flush_dns()
    ghost_ai_advisor(iface)
    ghosttrail(iface, "GHOSTMODE_DONE")
    print("=========================================\n")

def rotate_once(iface):
    print("\n========== Ghost Rotate Once ==========")
    change_mac(iface)
    renew_ip(iface)
    flush_dns()
    ghost_ai_advisor(iface)
    ghosttrail(iface, "ROTATE_ONCE_DONE")
    print("=======================================\n")

def auto_ghost_rotate(iface, interval, count):
    print("\n========== Auto Ghost Rotate ==========")
    print(f"Interface : {iface}")
    print(f"Interval  : {interval} seconds")
    print(f"Count     : {'Unlimited' if count == 0 else count}")
    print("Press CTRL + C to stop.")
    print("=======================================\n")

    i = 0

    try:
        while True:
            i += 1
            print(f"\n========== Auto Rotation #{i} ==========")
            rotate_once(iface)

            if count != 0 and i >= count:
                print("[+] Auto Ghost Rotate completed.")
                break

            print(f"[*] Waiting {interval} seconds...")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[!] Auto rotation stopped.")

def ghostwatch(iface, interval):
    last = {
        "mac": get_mac(iface),
        "private_ip": get_ip(iface),
        "public_ip": get_public_ip(),
        "dns": get_dns(),
        "gateway": get_gateway(),
        "vpn": detect_vpn()
    }

    print("\n========== GhostWatch Started ==========")
    print(f"Interface: {iface}")
    print(f"Interval : {interval} seconds")
    print("Press CTRL + C to stop.")
    print("========================================\n")

    try:
        while True:
            time.sleep(interval)

            cur = {
                "mac": get_mac(iface),
                "private_ip": get_ip(iface),
                "public_ip": get_public_ip(),
                "dns": get_dns(),
                "gateway": get_gateway(),
                "vpn": detect_vpn()
            }

            alerts = []

            for k in ["mac", "private_ip", "public_ip", "dns", "gateway"]:
                if last[k] != cur[k]:
                    alerts.append(f"{k}: {last[k]} -> {cur[k]}")

            if last["vpn"]["status"] != cur["vpn"]["status"]:
                alerts.append(f"VPN Status: {last['vpn']['status']} -> {cur['vpn']['status']}")

            if alerts:
                print(f"\n[GhostWatch Alert] {datetime.now()}")

                for a in alerts:
                    print(f"[!] {a}")

                ghosttrail(iface, "GHOSTWATCH_ALERT")
                last = cur
            else:
                print(f"[+] {datetime.now()} No change detected.")

    except KeyboardInterrupt:
        print("\n[!] GhostWatch stopped.")

def reset(iface):
    omac = original_mac(iface)

    if omac == "Not saved":
        print("[!] Original MAC not saved.")
        return

    print(f"[*] Restoring original MAC: {omac}")

    run(f"ip link set {iface} down")
    result = run(f"ip link set dev {iface} address {omac}")
    run(f"ip link set {iface} up")

    if result.returncode == 0:
        print("[+] Original MAC restored.")
    else:
        print("[!] Reset failed.")
        print(result.stderr)

    renew_ip(iface)
    flush_dns()
    ghosttrail(iface, "RESET_DONE")
    ghost_ai_advisor(iface)

def status(iface):
    save_original(iface)
    vpn = detect_vpn()

    print("\n========== GhostNIC Status ==========")
    print(f"Interface           : {iface}")
    print(f"Original MAC        : {original_mac(iface)}")
    print(f"Current MAC         : {get_mac(iface)}")
    print(f"MAC Changed         : {'YES' if get_mac(iface) != original_mac(iface) else 'NO'}")
    print(f"Original Private IP : {first_private_ip(iface)}")
    print(f"Current Private IP  : {get_ip(iface)}")
    print(f"Private IP Changed  : {'YES' if get_ip(iface) != first_private_ip(iface) else 'NO'}")
    print(f"Original Public IP  : {first_public_ip(iface)}")
    print(f"Current Public IP   : {get_public_ip()}")
    print(f"Public IP Changed   : {'YES' if get_public_ip() != first_public_ip(iface) else 'NO'}")
    print(f"DNS Servers         : {get_dns()}")
    print(f"Gateway             : {get_gateway()}")
    print(f"VPN Status          : {vpn['status']}")
    print(f"VPN Type            : {vpn['type']}")
    print(f"VPN Interface       : {vpn['interface']}")
    print(f"VPN IP              : {vpn['ip']}")
    print("=====================================\n")

def help_center():
    print("""
==================== GhostNIC Help Center ====================

1. Show Status
   Shows current network identity:
   MAC address, private IP, public IP, DNS, gateway and VPN status.

2. GhostAI Advisor
   Gives smart analysis:
   tells if MAC changed, private IP changed, VPN is active, or public IP changed externally.

3. GhostMode One-Click
   One-click identity refresh:
   changes MAC, renews private IP, flushes DNS, runs GhostAI and saves logs.

4. Change MAC Once
   Generates a random locally-administered MAC address and applies it to selected interface.

5. Renew Private IP Once
   Uses DHCP to request a new local/private IP address.
   Note: DHCP may give the same IP again.

6. Ghost Rotate Once
   Runs:
   MAC change + private IP renew + DNS flush + GhostAI + GhostTrail log.

7. Auto Ghost Rotate
   Automatically repeats Ghost Rotate after a selected time interval.
   Example: every 60 seconds, 5 times.

8. VPN Detector
   Detects active VPN tunnel interfaces like:
   wg0, tun0, tap0, ppp0.

9. Reset Original MAC + Renew IP
   Restores your original MAC address and renews private IP.

10. Show GhostTrail Logs
   Shows history of actions:
   MAC changes, IP renews, resets, reports, GhostMode actions, etc.

11. Create GhostBaseline
   Saves current network identity as a baseline.
   Useful before testing.

12. Compare GhostBaseline
   Compares current identity with saved baseline.
   Shows what changed.

13. Start GhostWatch
   Live monitoring mode.
   Alerts when MAC, private IP, public IP, DNS, gateway or VPN status changes.

14. Generate HTML Report
   Creates a professional HTML report:
   original/current MAC, private IP, public IP, VPN status, baseline deviations and logs.

15. Flush DNS
   Clears DNS cache if supported by your system.

16. Exit
   Closes GhostNIC.

Important Notes:
- GhostNIC v1.1 does not force-change public IP.
- Public IP changes usually happen because of ISP renewal, router reconnect, mobile hotspot or VPN.
- Use only on your own system or authorized lab network.

==============================================================
""")

def generate_report(iface):
    save_original(iface)
    vpn = detect_vpn()
    changes = compare_baseline(iface) if BASELINE_FILE.exists() else []

    logs = TRAIL_FILE.read_text() if TRAIL_FILE.exists() else "No logs found."
    logs = logs.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = ""

    if changes:
        for k, o, n in changes:
            rows += f"<tr><td>{k}</td><td>{o}</td><td>{n}</td><td><span class='warn'>Changed</span></td></tr>"
    else:
        rows = "<tr><td colspan='4'>No baseline deviations found.</td></tr>"

    mac_changed = get_mac(iface) != original_mac(iface)
    private_changed = get_ip(iface) != first_private_ip(iface)
    public_changed = get_public_ip() != first_public_ip(iface)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>GhostNIC Report</title>
<style>
body {{
    margin: 0;
    font-family: Arial, sans-serif;
    background: #050816;
    color: #e5e7eb;
}}
.header {{
    padding: 30px;
    background: linear-gradient(135deg, #111827, #0f766e);
}}
.container {{
    padding: 25px;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
}}
.card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 14px;
    padding: 20px;
}}
.card h2 {{
    color: #5eead4;
    margin-top: 0;
    font-size: 18px;
}}
.value {{
    font-size: 19px;
    font-weight: bold;
    word-break: break-all;
}}
.ok {{
    background: #064e3b;
    color: #a7f3d0;
    padding: 7px 12px;
    border-radius: 20px;
    font-weight: bold;
}}
.bad {{
    background: #7f1d1d;
    color: #fecaca;
    padding: 7px 12px;
    border-radius: 20px;
    font-weight: bold;
}}
.warn {{
    background: #78350f;
    color: #fde68a;
    padding: 6px 10px;
    border-radius: 20px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
    background: #111827;
}}
th, td {{
    padding: 12px;
    border-bottom: 1px solid #1f2937;
    text-align: left;
}}
th {{
    background: #0f766e;
}}
pre {{
    background: #020617;
    padding: 18px;
    border-radius: 14px;
    overflow: auto;
    color: #d1fae5;
}}
.footer {{
    text-align: center;
    padding: 20px;
    color: #9ca3af;
}}
</style>
</head>
<body>

<div class="header">
    <h1>GhostNIC v1.1 Stable Report</h1>
    <p>Network Identity, VPN Detection, Baseline and GhostTrail Report</p>
    <p>Created by: Imran Sarwer | Generated: {datetime.now()}</p>
</div>

<div class="container">

<div class="grid">
    <div class="card"><h2>Interface</h2><div class="value">{iface}</div></div>
    <div class="card"><h2>Original MAC</h2><div class="value">{original_mac(iface)}</div></div>
    <div class="card"><h2>Current MAC</h2><div class="value">{get_mac(iface)}</div></div>

    <div class="card"><h2>Original Private IP</h2><div class="value">{first_private_ip(iface)}</div></div>
    <div class="card"><h2>Current Private IP</h2><div class="value">{get_ip(iface)}</div></div>
    <div class="card"><h2>Private IP Status</h2><div class="value"><span class="{'warn' if private_changed else 'ok'}">{'CHANGED' if private_changed else 'NO CHANGE'}</span></div></div>

    <div class="card"><h2>Original Public IP</h2><div class="value">{first_public_ip(iface)}</div></div>
    <div class="card"><h2>Current Public IP</h2><div class="value">{get_public_ip()}</div></div>
    <div class="card"><h2>Public IP Status</h2><div class="value"><span class="{'warn' if public_changed else 'ok'}">{'CHANGED EXTERNALLY' if public_changed else 'NO CHANGE'}</span></div></div>

    <div class="card"><h2>MAC Status</h2><div class="value"><span class="{'warn' if mac_changed else 'ok'}">{'CHANGED' if mac_changed else 'ORIGINAL'}</span></div></div>
    <div class="card"><h2>VPN Status</h2><div class="value"><span class="{'ok' if vpn['status']=='Connected' else 'bad'}">{vpn['status']}</span></div></div>
    <div class="card"><h2>VPN Type</h2><div class="value">{vpn['type']}</div></div>

    <div class="card"><h2>VPN Interface</h2><div class="value">{vpn['interface']}</div></div>
    <div class="card"><h2>VPN IP</h2><div class="value">{vpn['ip']}</div></div>
    <div class="card"><h2>DNS / Gateway</h2><div class="value">DNS: {get_dns()}<br>GW: {get_gateway()}</div></div>
</div>

<h2>GhostAI Summary</h2>
<div class="card">
    <p><b>Original Private IP:</b> {first_private_ip(iface)}</p>
    <p><b>Current Private IP:</b> {get_ip(iface)}</p>
    <p><b>Original Public IP:</b> {first_public_ip(iface)}</p>
    <p><b>Current Public IP:</b> {get_public_ip()}</p>
    <p><b>MAC:</b> {"Changed/Spoofed" if mac_changed else "Original active"}</p>
    <p><b>Private IP:</b> {"Changed" if private_changed else "Same as first recorded"}</p>
    <p><b>Public IP:</b> {"Changed externally. GhostNIC did not modify public IP." if public_changed else "Same as first recorded"}</p>
    <p><b>VPN:</b> {vpn['status']} - {vpn['type']} - {vpn['interface']}</p>
</div>

<h2>GhostBaseline Deviations</h2>
<table>
<tr><th>Field</th><th>Baseline</th><th>Current</th><th>Status</th></tr>
{rows}
</table>

<h2>GhostTrail Logs</h2>
<pre>{logs}</pre>

</div>

<div class="footer">GhostNIC v1.1 | Created by: Imran Sarwer</div>

</body>
</html>
"""

    REPORT_FILE.write_text(html)
    ghosttrail(iface, "HTML_REPORT_GENERATED")
    print(f"[+] Report generated: {REPORT_FILE.resolve()}")

def menu():
    print(BANNER)
    ifaces = interfaces()

    if not ifaces:
        print("[!] No network interface found.")
        return

    for n, iface in enumerate(ifaces, 1):
        print(f"{n}. {iface} | MAC={get_mac(iface)} | IP={get_ip(iface)}")

    try:
        iface = ifaces[int(input("\nSelect interface number: ")) - 1]
    except:
        print("[!] Invalid selection.")
        return

    while True:
        print(f"\nSelected Interface: {iface}")
        print("1. Show Status")
        print("2. GhostAI Advisor")
        print("3. GhostMode One-Click")
        print("4. Change MAC Once")
        print("5. Renew Private IP Once")
        print("6. Ghost Rotate Once")
        print("7. Auto Ghost Rotate")
        print("8. VPN Detector")
        print("9. Reset Original MAC + Renew IP")
        print("10. Show GhostTrail Logs")
        print("11. Create GhostBaseline")
        print("12. Compare GhostBaseline")
        print("13. Start GhostWatch")
        print("14. Generate HTML Report")
        print("15. Flush DNS")
        print("16. Help Center")
        print("17. Exit")

        op = input("\nChoose option: ").strip()

        if op == "1":
            status(iface)
        elif op == "2":
            ghost_ai_advisor(iface)
        elif op == "3":
            ghost_mode(iface)
        elif op == "4":
            change_mac(iface)
        elif op == "5":
            renew_ip(iface)
        elif op == "6":
            rotate_once(iface)
        elif op == "7":
            sec = int(input("Interval seconds: "))
            cnt = int(input("Count, 0 unlimited: "))
            auto_ghost_rotate(iface, sec, cnt)
        elif op == "8":
            print(detect_vpn())
        elif op == "9":
            reset(iface)
        elif op == "10":
            show_trail()
        elif op == "11":
            create_baseline(iface)
        elif op == "12":
            compare_baseline(iface)
        elif op == "13":
            sec = int(input("Monitor interval seconds: "))
            ghostwatch(iface, sec)
        elif op == "14":
            generate_report(iface)
        elif op == "15":
            flush_dns()
        elif op == "16":
            help_center()
        elif op == "17":
            print("[+] Exiting GhostNIC.")
            break
        else:
            print("[!] Invalid option.")

def main():
    root_check()

    parser = argparse.ArgumentParser(description="GhostNIC v1.1 Stable")
    parser.add_argument("-i", "--interface")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--ai", action="store_true")
    parser.add_argument("--ghostmode", action="store_true")
    parser.add_argument("--mac", action="store_true")
    parser.add_argument("--ip", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--auto", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--vpn", action="store_true")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--trail", action="store_true")
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--help-center", action="store_true")

    args = parser.parse_args()

    if not args.interface and not args.help_center:
        menu()
        return

    if args.help_center:
        help_center()
        return

    iface = args.interface

    if args.status:
        status(iface)
    elif args.ai:
        ghost_ai_advisor(iface)
    elif args.ghostmode:
        ghost_mode(iface)
    elif args.mac:
        change_mac(iface)
    elif args.ip:
        renew_ip(iface)
    elif args.once:
        rotate_once(iface)
    elif args.auto:
        auto_ghost_rotate(iface, args.interval, args.count)
    elif args.vpn:
        print(detect_vpn())
    elif args.reset:
        reset(iface)
    elif args.trail:
        show_trail()
    elif args.baseline:
        create_baseline(iface)
    elif args.compare:
        compare_baseline(iface)
    elif args.watch:
        ghostwatch(iface, args.interval)
    elif args.report:
        generate_report(iface)
    else:
        status(iface)

if __name__ == "__main__":
    main()
