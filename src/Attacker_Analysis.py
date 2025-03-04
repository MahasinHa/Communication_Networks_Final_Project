import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import os

# ✅ Step 1: Define the PCAP File Path Automatically
recordings_dir = os.path.join(os.getcwd(), "Recordings")  # Path to the "Recordings" folder
pcap_file = os.path.join(recordings_dir, "All_Decrypted.pcapng")  # Automatically use "All_Decrypted.pcapng"

# Check if the file exists
if not os.path.exists(pcap_file):
    print(f"❌ File not found: {pcap_file}")
    exit()

print(f"✅ Using PCAP file: {pcap_file}")

# ✅ Step 2: Read the PCAP File Safely
try:
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    print("✅ PCAP file loaded successfully!")
except Exception as e:
    print(f"❌ Error loading PCAP file: {e}")
    exit()

# ✅ Step 3: Extract Relevant Traffic Data
packets_data = []
for pkt in cap:
    try:
        transport_layer = pkt.transport_layer if hasattr(pkt, 'transport_layer') and pkt.transport_layer else None

        packet_info = {
            "timestamp": float(pkt.sniff_time.timestamp()),
            "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else "Unknown",
            "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else "Unknown",
            "src_port": pkt[transport_layer].srcport if transport_layer and hasattr(pkt, transport_layer) else None,
            "dst_port": pkt[transport_layer].dstport if transport_layer and hasattr(pkt, transport_layer) else None,
            "packet_size": int(pkt.length),
        }
        packets_data.append(packet_info)
    except AttributeError:
        continue  # Skip packets without required attributes
    except Exception as e:
        print(f"⚠️ Error processing packet: {e}")

# ✅ Step 4: Convert to DataFrame
if not packets_data:
    print("❌ No valid packets found in the PCAP file.")
    exit()

df = pd.DataFrame(packets_data)

# ✅ Step 5: Save Processed Data as CSV (Optional)
output_csv = os.path.join(os.getcwd(), "traffic_analysis.csv")

# ✅ Step 6: Generate Refined Histogram (Only Show, Do Not Save)
num_bins = min(100, max(10, len(df["packet_size"].unique()) // 10))
plt.figure(figsize=(10, 5))
plt.hist(df["packet_size"], bins=num_bins, alpha=0.7, color="blue", edgecolor="black")
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Count")
plt.title("Refined Packet Size Distribution")
plt.grid()
plt.xlim(0, min(df["packet_size"].max(), 16000))  # Limiting max packet size to 16,000 for better visualization
plt.show()  # Displaying the plot instead of saving it

print("✅ Displayed histogram for packet size distribution.")

# ✅ Step 7: Generate Attacker View Scatter Plot (Only Show, Do Not Save)
plt.figure(figsize=(12, 6))
plt.scatter(df["timestamp"], df["packet_size"], alpha=0.5, s=10, color="orange", label="Packet Size")
plt.xlabel("Time")
plt.ylabel("Packet Size (Bytes)")
plt.title("Traffic Pattern Over Time (Potential Attack Scenario)")
plt.legend()
plt.grid()
plt.xticks(rotation=45)
plt.ylim(0, min(df["packet_size"].max(), 16000))  # Limiting Y-axis to filter out extreme packet sizes
plt.show()  # Displaying the plot instead of saving it

print("✅ Displayed scatter plot for attacker view.")

# ✅ Step 8: Print Summary Statistics
print("\n📊 Summary Statistics:")
print(df["packet_size"].describe())
