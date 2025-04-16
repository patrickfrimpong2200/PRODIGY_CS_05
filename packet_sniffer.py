import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto

        print(f"[+] IP Packet | From: {src_ip} -> To: {dst_ip} | Protocol: {proto}")

        # Check if it's TCP
        if packet.haslayer(scapy.TCP):
            print("[-] TCP Packet Detected")
            if packet.haslayer(scapy.Raw):
                try:
                    raw_data = packet[scapy.Raw].load
                    decoded_data = raw_data.decode('utf-8', 'ignore')
                    print(f"    TCP Payload: {decoded_data}")
                except Exception as e:
                    print(f"    [!] Couldn't decode TCP payload: {e}")

        # Check if it's UDP
        elif packet.haslayer(scapy.UDP):
            print("[-] UDP Packet Detected")
            if packet.haslayer(scapy.Raw):
                try:
                    raw_data = packet[scapy.Raw].load
                    decoded_data = raw_data.decode('utf-8', 'ignore')
                    print(f"    UDP Payload: {decoded_data}")
                except Exception as e:
                    print(f"    [!] Couldn't decode UDP payload: {e}")

def start_sniffing():
    print("[*] Starting packet sniffing... Press Ctrl+C to stop.")
    scapy.sniff(store=False, prn=packet_callback)

# Kick things off
start_sniffing()
