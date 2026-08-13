import socket

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP

from . import formatting


def resolve_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unresolved"


ROW_WIDTHS = [16, 10, 16, 10, 22]


def print_row(cells):
    print("  " + "".join(str(cell).ljust(width) for cell, width in zip(cells, ROW_WIDTHS)))


def process_packet(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport
    destination_host = resolve_hostname(destination_ip)

    print_row([source_ip, source_port, destination_ip, destination_port, destination_host])


def run():
    formatting.page_title("LIVE IP AND TCP PACKET SNIFFER", "Captures and displays live TCP traffic.")

    interface = str(conf.iface)

    formatting.section("Capture Information")
    formatting.key_values([("Network interface", interface), ("Packet filter", "IP and TCP"), ("Storage mode", "Disabled")])
    formatting.section_end()

    formatting.message("Packet capture may require administrator or root privileges.", "warning")
    formatting.message("Press Ctrl+C to stop the packet capture.", "warning")

    formatting.section("Live Packet Results")
    print_row(["SOURCE IP", "SRC PORT", "DEST IP", "DST PORT", "DEST HOST"])

    try:
        sniff(iface=interface, filter="ip and tcp", prn=process_packet, store=False)
    except PermissionError:
        formatting.message("Administrator or root privileges are required for packet capture.", "danger")
    except OSError as error:
        formatting.message(f"Unable to start packet capture: {error}", "danger")
    except KeyboardInterrupt:
        formatting.message("Packet capture stopped by the user.", "success")

    formatting.section_end()
