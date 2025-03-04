import os
import pyshark
import matplotlib.pyplot as plt
import numpy as np

# Get the script's directory dynamically
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECORDINGS_DIR = os.path.join(BASE_DIR, "Recordings")  # Path to Recordings folder
SSL_KEYLOG_FILE = os.path.join(BASE_DIR, "sslkeylog.txt")  # SSL Key Log File in base dir

# Ensure the Recordings directory exists
if not os.path.exists(RECORDINGS_DIR):
    print(f"Error: 'Recordings' folder not found at {RECORDINGS_DIR}.")
    exit()

# Function to extract packet sizes and timestamps from a .pcap or .pcapng file
def extract_packet_data(pcap_file, ssl_keylog):
    """
    Extracts packet sizes and timestamps from a given .pcapng file.

    Args:
        pcap_file (str): Path to the .pcapng file.
        ssl_keylog (str): Path to the SSL key log file for decryption.

    Returns:
        tuple: Two lists:
            - timestamps (list of float): List of packet timestamps.
            - packet_sizes (list of int): Corresponding packet sizes.
    """
    cap = pyshark.FileCapture(
        pcap_file,
        use_json=True,
        override_prefs={"tls.keylog_file": ssl_keylog}  # Use SSL Key Log File for Decryption
    )
    packet_sizes = []
    timestamps = []

    try:
        for packet in cap:
            try:
                packet_sizes.append(int(packet.length))  # Get packet size
                timestamps.append(float(packet.sniff_time.timestamp()))  # Keep raw timestamps
            except AttributeError:
                continue
    finally:
        cap.close()  # Ensures PyShark closes properly

    return timestamps, packet_sizes


# Function to group packets into 200ms intervals
def group_packets_by_interval(timestamps, packet_sizes, interval=0.2):
    """
    Groups packets into time intervals and sums their sizes.

    Args:
        timestamps (list of float): List of packet timestamps.
        packet_sizes (list of int): List of packet sizes.
        interval (float, optional): Time interval in seconds (default is 0.2s).

    Returns:
        tuple: Two lists:
            - bins[:-1] (list of float): Start times of each interval.
            - binned_sizes (list of float): Total packet sizes in each interval.
    """
    start_time = min(timestamps)
    relative_times = [t - start_time for t in timestamps]

    bins = np.arange(0, max(relative_times) + interval, interval)
    binned_sizes = np.zeros(len(bins) - 1)

    for i, t in enumerate(relative_times):
        bin_index = np.searchsorted(bins, t) - 1
        if 0 <= bin_index < len(binned_sizes):
            binned_sizes[bin_index] += packet_sizes[i]  # Sum up packet sizes in the interval

    return bins[:-1], binned_sizes


# Function to plot packet sizes over time for a single application
def plot_packet_size_over_time_single(timestamps, packet_sizes, app_name):
    """
    Plots packet sizes over time for a single application.

    Args:
        timestamps (list of float): Packet timestamps.
        packet_sizes (list of int): Corresponding packet sizes.
        app_name (str): Name of the application.
    """
    times, sizes = group_packets_by_interval(timestamps, packet_sizes, interval=0.2)

    plt.figure(figsize=(10, 6))
    plt.plot(times, sizes, color='blue', linestyle='-', alpha=0.6, linewidth=1.2)
    plt.scatter(times, sizes, color='red', alpha=0.5, s=10, label="Packets")

    plt.xlabel("Time (seconds from start)")
    plt.ylabel("Packet Size (Bytes per 200ms)")
    plt.title(f"Packet Size Over Time for {app_name} (200ms Interval)")
    plt.legend()
    plt.grid()
    plt.show()  # Only show the plot (no saving)

    print(f"Displayed plot for: {app_name}")


def compare_packet_sizes_over_time(pcap_files, app_names, ssl_keylog):
    """
    Compares packet sizes over time for multiple applications.

    Args:
        pcap_files (list of str): List of paths to .pcapng files.
        app_names (list of str): List of application names.
        ssl_keylog (str): Path to the SSL key log file for decryption.
    """
    plt.figure(figsize=(12, 6))

    for pcap_file, app_name in zip(pcap_files, app_names):
        timestamps, packet_sizes = extract_packet_data(pcap_file, ssl_keylog)
        times, sizes = group_packets_by_interval(timestamps, packet_sizes, interval=0.2)

        plt.plot(times, sizes, linestyle='-', linewidth=1.2, alpha=0.7, label=app_name)

    plt.xlabel("Time (seconds from start)")
    plt.ylabel("Packet Size (Bytes per 200ms)")
    plt.title("Comparison of Packet Sizes Over Time (200ms Interval)")
    plt.legend()
    plt.grid()
    plt.show()  # Only show the plot (no saving)

    print("Displayed comparison plot for all applications")


if __name__ == "__main__":
    # Check if the SSL keylog file exists
    if not os.path.exists(SSL_KEYLOG_FILE):
        print(f"Warning: SSL Key Log file '{SSL_KEYLOG_FILE}' not found. Decryption may not work.")

    # Define PCAP file paths (inside "Recordings" folder)
    pcap_files = [
        os.path.join(RECORDINGS_DIR, "Zoom_Decrypted_Filtered.pcapng"),
        os.path.join(RECORDINGS_DIR, "Youtube_Decrypted_Filtered.pcapng"),
        os.path.join(RECORDINGS_DIR, "Spotify_Decrypted_Filtered.pcapng"),
        os.path.join(RECORDINGS_DIR, "FireFox_Decrypted_Filtered.pcapng"),
        os.path.join(RECORDINGS_DIR, "MicrosoftEdge_Decrypted_Filtered.pcapng")
    ]

    app_names = ["Zoom", "YouTube", "Spotify", "Firefox", "Edge"]

    # Process each application separately first
    for pcap_file, app_name in zip(pcap_files, app_names):
        if os.path.exists(pcap_file):  # Check if file exists before processing
            timestamps, packet_sizes = extract_packet_data(pcap_file, SSL_KEYLOG_FILE)
            plot_packet_size_over_time_single(timestamps, packet_sizes, app_name)
        else:
            print(f"Warning: {pcap_file} not found. Skipping...")

    # Compare all applications together
    compare_packet_sizes_over_time(pcap_files, app_names, SSL_KEYLOG_FILE)
