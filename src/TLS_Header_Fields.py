import os
import pyshark
import matplotlib.pyplot as plt
import numpy as np
import math

# Define the folder paths
PCAP_FOLDER = os.path.abspath(os.path.dirname(__file__))  # Current script directory
RECORDINGS_FOLDER = os.path.join(PCAP_FOLDER, "Recordings")  # Subfolder containing PCAPs

# Path to SSL Key Log File (Update if needed)
SSL_KEYLOG_FILE = os.path.join(PCAP_FOLDER, "sslkeylog.txt")

# Dictionary with filenames (inside "Recordings" folder now)
APPLICATIONS = {
    "Zoom": "Zoom_Decrypted_Filtered.pcapng",
    "YouTube": "Youtube_Decrypted_Filtered.pcapng",
    "Spotify": "Spotify_Decrypted_Filtered.pcapng",
    "Firefox": "FireFox_Decrypted_Filtered.pcapng",
    "Microsoft Edge": "MicrosoftEdge_Decrypted_Filtered.pcapng",
}

def get_existing_pcaps():
    """
    Returns a dictionary of applications with available `.pcapng` files inside the 'Recordings/' directory.

    Returns:
    - dict: A dictionary mapping application names to valid `.pcapng` file paths.
    """
    return {
        app: os.path.join(RECORDINGS_FOLDER, filename)
        for app, filename in APPLICATIONS.items()
        if os.path.exists(os.path.join(RECORDINGS_FOLDER, filename))
    }

def extract_tls_traffic(pcap_file):
    """
    Extracts total TLS traffic (in bytes) from a given `.pcapng` file using PyShark.

    Parameters:
    - pcap_file (str): Path to the `.pcapng` file to be analyzed.

    Returns:
    - int: Total traffic in bytes for the specified application.
    """
    try:
        cap = pyshark.FileCapture(
            pcap_file,
            override_prefs={
                "ssl.keylog_file": SSL_KEYLOG_FILE,
                "tls.keylog_file": SSL_KEYLOG_FILE
            },
            display_filter="tls",
            use_json=True,
            keep_packets=False
        )
        cap.load_packets(timeout=10)

        total_traffic = sum(int(packet.length) for packet in cap if hasattr(packet, 'tls'))
        cap.close()
        return total_traffic

    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        return 0  # Return zero on failure

if __name__ == "__main__":
    """
    Extracts and visualizes total TLS traffic per application based on available `.pcapng` files.

    Steps:
    1. Checks for available `.pcapng` files in the `Recordings` folder.
    2. Extracts TLS traffic data for each valid application.
    3. Filters out applications with zero traffic.
    4. Converts traffic from bytes to megabytes (MB).
    5. Generates a bar chart comparing total TLS traffic per application.

    Returns:
    - None (Displays visualization of extracted TLS traffic data).
    """
    app_traffic_data = {
        app: extract_tls_traffic(pcap)
        for app, pcap in get_existing_pcaps().items()
    }

    # Remove applications with zero traffic
    app_traffic_data = {
        app: traffic for app, traffic in app_traffic_data.items() if traffic > 0
    }

    # Sort applications by traffic in descending order
    app_traffic_data = dict(sorted(app_traffic_data.items(), key=lambda x: x[1], reverse=True))

    # Convert traffic from Bytes to MB (no rounding)
    app_traffic_data_mb = {
        app: traffic / (1024 * 1024) for app, traffic in app_traffic_data.items()
    }

    # Define distinct colors for each application
    colors = ["blue", "green", "red", "purple", "orange"]

    # Plot the data
    plt.figure(figsize=(10, 5))
    bars = plt.bar(
        app_traffic_data_mb.keys(),
        app_traffic_data_mb.values(),
        color=colors[:len(app_traffic_data_mb)],
        alpha=0.85
    )

    # Add text labels on top of the bars (exact values)
    for bar in bars:
        yval = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width()/2,
            yval,
            f"{yval:.2f} MB",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color="black"
        )

    plt.xlabel("Application", fontsize=12)
    plt.ylabel("Total Traffic (MB)", fontsize=12)
    plt.title("Total TLS Traffic per Application (MB)", fontsize=14)
    plt.xticks(rotation=15)

    # Adjust y-axis to only show integer ticks
    max_val = math.ceil(max(app_traffic_data_mb.values(), default=1))  # Round up to nearest integer
    plt.yticks(range(0, max_val + 1, max(1, max_val // 10)))  # Set interval dynamically

    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.show()
