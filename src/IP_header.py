import os
import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# Get the script's directory dynamically
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the path to the "Recordings" folder
PCAP_DIR = os.path.join(BASE_DIR, "Recordings")

# Ensure the "Recordings" directory exists
os.makedirs(PCAP_DIR, exist_ok=True)


def extract_packet_data(pcap_file, ssl_keylog):
    """
    Extracts network packet data from a given `.pcapng` file using PyShark.
    It analyzes IP source-destination pairs, TTL values, protocol types, checksum errors, and QoS values.

    Parameters:
    - pcap_file (str): Path to the `.pcapng` file to be analyzed.
    - ssl_keylog (str): Path to the SSL key log file for decryption.

    Returns:
    - data (dict): A dictionary containing:
        - 'ip_pairs' (Counter): Frequency of source-destination IP pairs.
        - 'ttl_values' (list): Collected Time-To-Live (TTL) values.
        - 'protocols' (list): List of detected protocols.
        - 'checksum_errors' (int): Count of packets with checksum errors.
        - 'qos_values' (list): List of Differentiated Services Code Point (DSCP) values (QoS).
    """
    cap = pyshark.FileCapture(
        pcap_file,
        use_json=True,
        override_prefs={"tls.keylog_file": ssl_keylog}
    )

    data = {
        "ip_pairs": Counter(),
        "ttl_values": [],
        "protocols": [],
        "checksum_errors": 0,
        "qos_values": []
    }

    try:
        for packet in cap:
            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                ttl = int(packet.ip.ttl)
                protocol = int(packet.ip.proto)
                checksum = int(packet.ip.checksum, 16)
                qos = int(packet.ip.dsfield, 16)  # Differentiated Services Field

                data["ip_pairs"][(src_ip, dst_ip)] += 1
                data["ttl_values"].append(ttl)
                data["protocols"].append(protocol)
                data["qos_values"].append(qos)

                if checksum == 0:  # Checksum error
                    data["checksum_errors"] += 1

            except AttributeError:
                continue
    finally:
        cap.close()

    return data


def plot_ttl_distribution(ttl_values, app_name):
    """
    Generates and displays a histogram showing the distribution of TTL values for a specific application.

    Parameters:
    - ttl_values (list): A list of TTL values extracted from packets.
    - app_name (str): The name of the application associated with the dataset.

    Returns:
    - None (Displays a histogram plot of TTL values).
    """
    if not ttl_values:
        print(f"No TTL data for {app_name}.")
        return

    plt.figure(figsize=(10, 5))
    plt.hist(ttl_values, bins=range(0, 256, 5), color='blue', alpha=0.7, edgecolor='black')
    plt.xlabel("TTL Value")
    plt.ylabel("Packet Count")
    plt.title(f"TTL Distribution for {app_name}")
    plt.grid()
    plt.show()


def plot_protocol_distribution(protocols, app_name):
    if not protocols:
        print(f"No protocol data for {app_name}.")
        return

    protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
    protocol_counts = Counter(protocols)
    labels = [protocol_names.get(proto, f"Other ({proto})") for proto in protocol_counts.keys()]
    sizes = protocol_counts.values()

    plt.figure(figsize=(7, 7))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title(f"Protocol Breakdown for {app_name}")
    plt.show()


def plot_checksum_errors(checksum_errors, total_packets, app_name):
    """
    Generates and displays a pie chart representing the proportion of packets with checksum errors versus valid packets.

    Parameters:
    - checksum_errors (int): The number of packets with checksum errors.
    - total_packets (int): Total number of packets processed.
    - app_name (str): The name of the application associated with the dataset.

    Returns:
    - None (Displays a pie chart of checksum errors).
    """
    if total_packets == 0:
        print(f"No packets processed for {app_name}, skipping checksum errors plot.")
        return

    labels = ['Errors', 'Valid']
    sizes = [checksum_errors, total_packets - checksum_errors]

    plt.figure(figsize=(7, 7))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['orange', 'blue'])
    plt.title(f"Checksum Errors for {app_name}")
    plt.show()


def plot_qos_distribution(qos_values, app_name):
    """
    Generates and displays a bar chart showing the distribution of Quality of Service (QoS) values (DSCP values) in the captured traffic.

    Parameters:
    - qos_values (list): List of QoS (DSCP) values extracted from packets.
    - app_name (str): The name of the application associated with the dataset.

    Returns:
    - None (Displays a bar chart of QoS values).
    """
    if not qos_values:
        print(f"No QoS data for {app_name}.")
        return

    qos_counts = Counter(qos_values)
    labels, values = zip(*qos_counts.items())

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color='purple', alpha=0.7)
    plt.xlabel("QoS (DSCP) Value")
    plt.ylabel("Packet Count")
    plt.title(f"QoS (DSCP) Distribution for {app_name}")
    plt.grid()
    plt.show()


def plot_ip_pair_frequency(ip_pairs, app_name):
    """
    Generates and displays a bar chart of the top 10 most frequent source-destination IP address pairs in the captured network traffic.

    Parameters:
    - ip_pairs (Counter): A Counter object mapping IP pairs to their frequency.
    - app_name (str): The name of the application associated with the dataset.

    Returns:
    - None (Displays a bar chart showing the most frequent IP pairs).
    """
    if not ip_pairs:
        print(f"No IP pair data for {app_name}.")
        return

    ip_labels, counts = zip(*ip_pairs.most_common(10))  # Show top 10 IP pairs
    ip_labels = [f"{src} → {dst}" for src, dst in ip_labels]

    plt.figure(figsize=(12, 6))
    plt.bar(ip_labels, counts, color='green', alpha=0.7)
    plt.xticks(rotation=45, ha="right")
    plt.xlabel("Source → Destination IP")
    plt.ylabel("Packet Count")
    plt.title(f"Top IP Source-Destination Pairs for {app_name}")
    plt.grid()
    plt.show()


if __name__ == "__main__":
    """
    Processes multiple `.pcapng` files corresponding to different applications, extracting relevant network data and generating visualizations.

    Steps:
    1. Defines paths to `.pcapng` files for Zoom, YouTube, Spotify, Firefox, and Edge.
    2. Iterates over each `.pcapng` file, extracting network data.
    3. Calls respective plotting functions to visualize TTL distribution, protocol distribution, checksum errors, QoS distribution, and IP pair frequency.
    4. Skips analysis for files that do not exist in the `Recordings` folder.

    Returns:
    - None (Executes analysis and displays visualizations).
    """
    ssl_keylog = os.path.join(BASE_DIR, "sslkeylog.txt")
    pcap_files = [
        os.path.join(PCAP_DIR, "Zoom_Decrypted_Filtered.pcapng"),
        os.path.join(PCAP_DIR, "Youtube_Decrypted_Filtered.pcapng"),
        os.path.join(PCAP_DIR, "Spotify_Decrypted_Filtered.pcapng"),
        os.path.join(PCAP_DIR, "FireFox_Decrypted_Filtered.pcapng"),
        os.path.join(PCAP_DIR, "MicrosoftEdge_Decrypted_Filtered.pcapng")
    ]
    app_names = ["Zoom", "YouTube", "Spotify", "Firefox", "Edge"]

    for pcap_file, app_name in zip(pcap_files, app_names):
        if os.path.exists(pcap_file):
            data = extract_packet_data(pcap_file, ssl_keylog)
            total_packets = sum(data["ip_pairs"].values())

            plot_ttl_distribution(data["ttl_values"], app_name)
            plot_protocol_distribution(data["protocols"], app_name)
            plot_checksum_errors(data["checksum_errors"], total_packets, app_name)
            plot_qos_distribution(data["qos_values"], app_name)
            plot_ip_pair_frequency(data["ip_pairs"], app_name)
        else:
            print(f"Warning: {pcap_file} not found in Recordings folder. Skipping...")
