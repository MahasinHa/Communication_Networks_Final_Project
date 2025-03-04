import os
import pyshark
import pandas as pd
import matplotlib.pyplot as plt

# Get the current script directory dynamically
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define relative paths
project_dir = script_dir  # Use the script's directory as the project root
pcap_dir = os.path.join(project_dir, "Recordings")  # Folder where .pcapng files are stored
ssl_key_log_file = os.path.join(project_dir, "sslkeylog.txt")  # SSL key log file
csv_path = os.path.join(project_dir, "tcp_headers.csv")  # CSV output file

# Ensure the "Recordings" directory exists
os.makedirs(pcap_dir, exist_ok=True)

# Define application-specific .pcapng files
pcap_files = {
    "Web Browsing (Edge)": os.path.join(pcap_dir, "MicrosoftEdge_Decrypted_Filtered.pcapng"),
    "Web Browsing (Firefox)": os.path.join(pcap_dir, "FireFox_Decrypted_Filtered.pcapng"),
    "Video Streaming (YouTube)": os.path.join(pcap_dir, "Youtube_Decrypted_Filtered.pcapng"),
    "Audio Streaming (Spotify)": os.path.join(pcap_dir, "Spotify_Decrypted_Filtered.pcapng"),
    "Video Conferencing (Zoom)": os.path.join(pcap_dir, "Zoom_Decrypted_Filtered.pcapng")
}

# Function to extract TCP header fields
def extract_tcp_headers(file_path, label):
    print(f"Processing TCP packets from {label} ({file_path})...")

    # Check if the file exists before processing
    if not os.path.exists(file_path):
        print(f"Warning: File {file_path} not found. Skipping {label}.")
        return pd.DataFrame()

    cap = pyshark.FileCapture(file_path, override_prefs={'ssl.keylog_file': ssl_key_log_file})
    data = []

    for pkt in cap:
        try:
            if 'TCP' in pkt:
                timestamp = float(pkt.sniff_time.timestamp())
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                seq_num = int(pkt.tcp.seq)
                ack_num = int(pkt.tcp.ack)
                window_size = int(pkt.tcp.window_size_value)
                tcp_flags = pkt.tcp.flags  # TCP flags (e.g., SYN, ACK, FIN, RST)
                payload_size = int(pkt.length) - int(pkt.tcp.hdr_len)

                data.append([timestamp, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, tcp_flags, window_size, payload_size, label])

        except AttributeError:
            continue  # Skip packets without complete TCP headers

    cap.close()
    return pd.DataFrame(data, columns=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port",
                                       "Sequence Number", "Ack Number", "TCP Flags", "Window Size", "Payload Size",
                                       "Application"])

# Process all files
df_list = [extract_tcp_headers(file, label) for label, file in pcap_files.items()]
df = pd.concat(df_list, ignore_index=True)

# Save to CSV
df.to_csv(csv_path, index=False)
print(f"TCP headers extracted and saved to {csv_path}")

# ✅ Check if the DataFrame is empty before processing further
if df.empty:
    print("No packets were extracted. Please check if the .pcapng files exist in the 'Recordings' folder.")
    exit()

# Convert timestamp to a readable format
df["Timestamp"] = pd.to_datetime(df["Timestamp"], unit="s")

# Function to generate **separate**, **easy-to-read** graphs for each application
def plot_application_traffic(df):
    for app in df["Application"].unique():
        subset = df[df["Application"] == app]

        # TCP Window Size Over Time
        plt.figure(figsize=(10, 5))
        plt.plot(subset["Timestamp"], subset["Window Size"], marker="o", linestyle="-", alpha=0.7, color="blue", label="Window Size")
        plt.xlabel("Time", fontsize=12)
        plt.ylabel("TCP Window Size", fontsize=12)
        plt.title(f"{app} - TCP Window Size Over Time", fontsize=14, fontweight="bold")
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.legend(fontsize=12)
        plt.xticks(rotation=30)
        plt.show()

        # TCP Flags Distribution
        plt.figure(figsize=(8, 5))
        subset["TCP Flags"].value_counts().plot(kind="bar", color="skyblue", edgecolor="black")
        plt.xlabel("TCP Flags", fontsize=12)
        plt.ylabel("Count", fontsize=12)
        plt.title(f"{app} - TCP Flags Distribution", fontsize=14, fontweight="bold")
        plt.grid(axis="y", linestyle="--", alpha=0.5)
        plt.xticks(rotation=0, fontsize=12)
        plt.yticks(fontsize=12)
        plt.show()

        # Payload Size Distribution
        plt.figure(figsize=(10, 5))
        plt.hist(subset["Payload Size"], bins=30, alpha=0.7, color="green", edgecolor="black")
        plt.xlabel("Payload Size (Bytes)", fontsize=12)
        plt.ylabel("Frequency", fontsize=12)
        plt.title(f"{app} - TCP Payload Size Distribution", fontsize=14, fontweight="bold")
        plt.grid(axis="y", linestyle="--", alpha=0.5)
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.show()

# Generate **separate plots** for each application
plot_application_traffic(df)
