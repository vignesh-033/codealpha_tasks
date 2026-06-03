from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import threading
import queue

packet_queue = queue.Queue(maxsize=1000)

def format_packet(pkt):
    try:
        ip_layer = pkt.getlayer(IP)
        proto = "OTHER"
        sport, dport = "-", "-"
        payload = ""

        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load[:50]
            payload = raw_data.decode(errors="ignore").replace("\n", " ")

        return f"[{datetime.now().strftime('%H:%M:%S')}] {ip_layer.src}:{sport} -> {ip_layer.dst}:{dport} | {proto} | {payload}"

    except Exception:
        return None


def packet_producer(pkt):
    if pkt.haslayer(IP):
        try:
            packet_queue.put_nowait(pkt)
        except queue.Full:
            pass


def packet_consumer():
    while True:
        pkt = packet_queue.get()
        formatted = format_packet(pkt)
        if formatted:
            print(formatted)
        packet_queue.task_done()


def start_sniffer(interface=None, packet_limit=0):
    consumer_thread = threading.Thread(target=packet_consumer, daemon=True)
    consumer_thread.start()

    sniff(
        iface=interface,
        prn=packet_producer,
        store=False,
        count=packet_limit
    )


if __name__ == "__main__":
    print("⚡ High Performance Network Sniffer Started...")
    print("Press CTRL+C to stop\n")

    try:
        start_sniffer(interface=None)
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")