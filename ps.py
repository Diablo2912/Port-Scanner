import socket
import threading
from queue import Queue
import requests
import binascii

# -------- Geo helpers --------
def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return None

def get_user_country(ip_address):
    try:
        r = requests.get(f"https://ipwho.is/{ip_address}", timeout=5)
        data = r.json()
        if data.get("success"):
            return data.get("country_code", "Unknown")
        return "Unknown"
    except Exception as e:
        print("GeoIP Error:", e)
        return "Unknown"

# -------- Payload helpers --------
def parse_payload(payload_str: str, mode: str) -> bytes:
    if not payload_str:
        return b""
    if mode == "hex":
        cleaned = payload_str.replace(" ", "").replace("0x", "")
        return binascii.unhexlify(cleaned)
    return payload_str.encode("utf-8", "ignore")

def default_payload_for_port(port: int) -> bytes:
    if port == 80:
        return b"HEAD / HTTP/1.0\r\n\r\n"
    if port in (443, 8443, 22, 21, 25, 110, 143):
        return b"\r\n"
    return b"\r\n"

# -------- TCP probe --------
def is_port_open(host, port, timeout=1.0, send_packet=False, payload=b"", expect_reply=True, recv_bytes=256):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except (socket.timeout, socket.error):
            return False, None

        if not send_packet:
            return True, None

        try:
            if payload:
                sock.sendall(payload)
            else:
                sock.sendall(b"\r\n")

            if expect_reply:
                sock.settimeout(min(timeout, 1.0))
                data = sock.recv(recv_bytes)
                return True, data
            else:
                return True, None
        except Exception:
            return True, None

# -------- Core Scan Function --------
def scan_target(ip_addr):
    hostname = socket.gethostname()
    country = get_user_country(ip_addr)
    print(f"\nHostname: {hostname}\nIP Address: {ip_addr}\nCountry: {country}\n")

    # Choose ports
    port_choice = input("Scan port range 1-1024 [1] or a specific port [2]: ").strip()
    ports = []
    if port_choice == "1":
        ports = list(range(1, 1025))
    elif port_choice == "2":
        try:
            ports = [int(input("Port: ").strip())]
        except ValueError:
            print("Invalid port.")
            return
    else:
        print("Invalid option.")
        return

    # Threaded scan
    queue = Queue()
    open_ports = []
    results_lock = threading.Lock()

    for p in ports:
        queue.put(p)

    def worker():
        while True:
            try:
                port = queue.get_nowait()
            except Exception:
                break

            pl = default_payload_for_port(port) if (send_pkt and payload is None) else (payload or b"")

            is_open, reply = is_port_open(
                ip_addr, port,
                timeout=timeout,
                send_packet=send_opt,
                payload=pl,
                expect_reply=expect_reply,
                recv_bytes=recv_bytes
            )

            if is_open:
                with results_lock:
                    open_ports.append((port, reply))
                msg = f"Port {port} is open!"
                if reply:
                    hex_preview = reply[:32].hex()
                    text_preview = reply[:64].decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
                    msg += f"  [reply hex: {hex_preview}]  [text: {text_preview}]"
                print(msg)

            queue.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(100)]
    for t in threads:
        t.start()
    queue.join()

    # Summary
    open_ports.sort(key=lambda x: x[0])
    print("\n--- Scan Summary ---")
    if not open_ports:
        print("No open ports found.")
    else:
        for port, reply in open_ports:
            line = f"- {port}"
            if reply:
                preview = reply[:40].decode("utf-8", errors="replace").splitlines()[0]
                line += f" → reply: {preview!r}"
            print(line)
    print("----------------------\n")

def send_pkt():
    print("\n--- Send Custom Packet to a Port ---")
    target_ip = input("Target IP: ").strip()
    try:
        port = int(input("Target port: ").strip())
    except ValueError:
        print("Invalid port.")
        return

    # Packet send config
    send_opt = input("Send a packet after connect? [Y/N]: ").strip().lower() == "y"
    payload = b""
    expect_reply = True
    recv_bytes = 256
    timeout = 1.0

    if not send_opt:
        print("Packet send cancelled.")
        return

    mode = input("Payload mode: text [1] | hex [2] | default-per-port [3]: ").strip()
    if mode == "1":
        payload_text = input("Enter text payload: ")
        payload = parse_payload(payload_text, "text")
    elif mode == "2":
        payload_hex = input("Enter hex payload: ")
        try:
            payload = parse_payload(payload_hex, "hex")
        except binascii.Error:
            print("Invalid hex. Using empty payload.")
            payload = b""
    elif mode == "3":
        payload = default_payload_for_port(port)
    else:
        print("Unknown payload mode. Cancelled.")
        return

    try:
        timeout = float(input("Timeout (sec, default 1.0): ").strip() or "1.0")
    except ValueError:
        timeout = 1.0

    expect_reply = input("Attempt to read a reply? [Y/n]: ").strip().lower() != "n"
    try:
        recv_bytes = int(input("Max bytes to read (default 256): ").strip() or "256")
    except ValueError:
        recv_bytes = 256

    is_open, reply = is_port_open(
        host=target_ip,
        port=port,
        timeout=timeout,
        send_packet=True,
        payload=payload,
        expect_reply=expect_reply,
        recv_bytes=recv_bytes
    )

    if is_open:
        print(f"\n✅ Port {port} on {target_ip} is open.")
        if reply:
            hex_preview = reply[:32].hex()
            text_preview = reply[:64].decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
            print(f"→ Reply hex: {hex_preview}")
            print(f"→ Text: {text_preview}")
        else:
            print("→ No reply received.")
    else:
        print(f"\n❌ Port {port} on {target_ip} is closed or filtered.")

def reverse_dns(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No PTR record found"
    except Exception as e:
        return f"Error: {e}"

def reverse_dns_menu():
    ip = input("Enter IP address for reverse DNS: ").strip()
    result = reverse_dns(ip)
    print(f"\nHostname for {ip}: {result}\n")

# -------- Menu Loop --------
def main_menu():
    print("⚠️  Only scan systems you own or are authorised to test.\n")

    while True:
        print("=== TCP Port Scanner ===")
        print("[1] Scan your own public IP")
        print("[2] Scan a target IP")
        print("[3] Send packet to target port")
        print("[4] Reverse DNS lookup")
        print("[5] Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            ip = get_public_ip()
            if not ip:
                print("Could not retrieve your public IP.\n")
                continue
            scan_target(ip)

        elif choice == "2":
            ip = input("Enter target IP address: ").strip()
            scan_target(ip)

        elif choice == "3":
            send_pkt()

        elif choice == "4":
            reverse_dns_menu()

        elif choice == "5":
            break

        else:
            print("Invalid selection. Try again.\n")

if __name__ == "__main__":
    main_menu()
