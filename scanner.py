
import ipaddress
import socket

from scapy.all import ARP, Ether, srp, conf
import psutil
import ipaddress
import socket



def get_network_info():
    """
    Mengambil informasi interface jaringan aktif.
    """

    try:
        # Mengambil interface dari default route
        _, interface, _ = conf.route.route("0.0.0.0")

        # Mengambil alamat IP dan netmask menggunakan psutil
        interfaces = psutil.net_if_addrs()

        ip_address = None
        netmask = None

        for address in interfaces.get(interface, []):
            if address.family == socket.AF_INET:
                ip_address = address.address
                netmask = address.netmask
                break

        if not ip_address or not netmask:
            raise RuntimeError(
                "IP Address atau netmask tidak ditemukan."
            )

        network = ipaddress.ip_network(
            f"{ip_address}/{netmask}",
            strict=False
        )

        if network.num_addresses > 1024:
            raise ValueError(
                "Subnet terlalu besar. Maksimal 1024 alamat."
            )

        return {
            "interface": str(interface),
            "ip_address": ip_address,
            "netmask": netmask,
            "network": str(network)
        }

    except Exception as error:
        raise RuntimeError(
            f"Gagal mendapatkan informasi jaringan: {error}"
        )



def get_hostname(ip_address):
    """Mencoba mendapatkan hostname berdasarkan IP."""

    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def scan_network():
    """Melakukan pemindaian perangkat pada jaringan lokal."""

    network_info = get_network_info()
    network = network_info["network"]
    interface = network_info["interface"]

    # Membuat ARP Request
    arp_request = ARP(pdst=network)

    # Membuat Ethernet Broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    # Mengirim paket dan menerima ARP Reply
    answered, unanswered = srp(
        packet,
        timeout=3,
        retry=1,
        iface=interface,
        verbose=False
    )

    devices = []

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc

        devices.append({
            "ip_address": ip,
            "mac_address": mac.upper(),
            "hostname": get_hostname(ip),
            "status": "Online"
        })

    devices.sort(
        key=lambda device: ipaddress.ip_address(
            device["ip_address"]
        )
    )

    return {
        "network": network,
        "interface": interface,
        "total_devices": len(devices),
        "devices": devices
    }
