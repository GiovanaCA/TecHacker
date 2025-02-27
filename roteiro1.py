import socket
import errno
import tkinter as tk
from tkinter import ttk

# Tabela de Well-Known Ports
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP", 
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 636: "LDAPS", 989: "FTPS", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis"
}

def scan_tcp(host_ip, ports):
    results = {}
    try:
        host_ip = socket.gethostbyname(host_ip) # Escaneamento de um host ou ip
    except socket.gaierror:
        return {"error": f"Invalid Host/IP: {host_ip}"}

    for port in ports: # Detecção do estado das portas
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host_ip, port))
            if result == 0:
                results[port] = "Open"
            elif result in (errno.ECONNREFUSED, 111, 10061):
                results[port] = "Closed"
            else:
                results[port] = "Filtered"
    return results

def parse_ports(start_port, end_port): # Permite inserir o range de portas
    ports = set()
    ports.update(range(start_port, end_port + 1))
    return sorted(ports)

def start_scan():
    host_ip = entry_host.get()
    start_port = int(entry_start_port.get())
    end_port = int(entry_end_port.get())
    try:
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        results_box.insert(tk.END, "Please enter valid port numbers (0-65535).\n")
        return

    results_box.delete(1.0, tk.END)
    results_box.insert(tk.END, f"Scanning TCP ports {start_port} - {end_port} on {host_ip}\n")
    
    ports = parse_ports(start_port, end_port)  
    results = scan_tcp(host_ip, ports)

    if "error" in results:
        results_box.insert(tk.END, results["error"] + "\n")
        return

    results_box.insert(tk.END, "\nScan Results:\n")
    results_box.insert(tk.END, "=" * 50 + "\n")
    results_box.insert(tk.END, f"{'Port':<10}{'Status':<15}{'Service':<15}\n")
    results_box.insert(tk.END, "=" * 50 + "\n")
    
    for port, status in results.items():
        # Relacionando as portas Well-Known Ports e seus serviços
        service = KNOWN_SERVICES.get(port, "Unknown")
        results_box.insert(tk.END, f"{port:<10}{status:<15}{service:<15}\n")

    results_box.insert(tk.END, "Scanning finished\n")

# Interface gráfica user-friendly.
root = tk.Tk()
root.title("Port Scanner")
root.geometry("500x400")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Host/IP:").grid(row=0, column=0, sticky=tk.W, pady=10)
entry_host = ttk.Entry(frame, width=30)
entry_host.grid(row=0, column=1)

ttk.Label(frame, text="Start Port:").grid(row=1, column=0, sticky=tk.W, pady=10)
entry_start_port = ttk.Entry(frame, width=10)
entry_start_port.grid(row=1, column=1, sticky=tk.W)
entry_start_port.insert(0, "0")

ttk.Label(frame, text="End Port:").grid(row=2, column=0, sticky=tk.W, pady=10)
entry_end_port = ttk.Entry(frame, width=10)
entry_end_port.grid(row=2, column=1, sticky=tk.W)
entry_end_port.insert(0, "65535")

scan_button = ttk.Button(frame, text="Start Scan", command=start_scan)
scan_button.grid(row=3, column=0, columnspan=2, pady=10)

results_box = tk.Text(frame, height=15, width=60)
results_box.grid(row=4, column=0, columnspan=2)

root.mainloop()