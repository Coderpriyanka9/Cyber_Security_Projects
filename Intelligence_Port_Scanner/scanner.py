import socket
import threading
from datetime import datetime

# Common ports and services
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}

high_risk_ports = [21, 23]
print_lock = threading.Lock()

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            service = services.get(port, "Unknown")
            risk = "High" if port in high_risk_ports else "Medium"

            banner = ""
            try:
                s.send(b"Hello\r\n")
                banner = s.recv(1024).decode().strip()
            except:
                banner = "No Banner"

            with print_lock:
                print(f"[OPEN] Port {port} | Service: {service} | Risk: {risk}")
                print(f"        Banner: {banner}")

        s.close()

    except:
        pass

def main():
    target = input("Enter Target IP or Domain: ")
    print(f"\nScanning Target: {target}")
    print(f"Scan Started at: {datetime.now()}\n")

    for port in range(1, 1025):
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()

if __name__ == "__main__":
    main()
