# **Communication System Final Project**

## **Overview**
This project analyzes the traffic characteristics of different applications, such as web browsing, video streaming, audio streaming, and video conferencing. We focus on extracting and comparing traffic properties from recorded `.pcap` files using Wireshark and Python. The project investigates key traffic parameters including:

- **IP header fields**
- **TCP header fields**
- **TLS header fields**
- **Packet sizes**

By studying these properties, we can gain insights into how different applications behave in the network, how they affect performance, and how encrypted traffic can still reveal user activity patterns.

## **Project Goals**
- Capture and analyze network traffic from different applications.
- Extract TCP,IP, TLS header fields and Packet Sizes to understand traffic behavior.
- Generate **Plots** comparing the traffic patterns of different applications.
- Investigate the feasibility of **identifying applications from encrypted traffic.**

## **Project Structure**
```
📂 Project Root
 ├── 📂 src/            # Source code for parsing and analyzing `.pcap` files
 ├── 📂 res/            # Result files (figures, visualizations, and analysis reports)
 ├── 📄 report.pdf      # Final project report
 ├── 📄 README.md       # This file
```

## **Installation and Setup**

### **2. Install Dependencies**
Ensure Python is installed, then run:
```bash
pip install pyshark pandas matplotlib
```
### **3. If the code didn't work**
If the code gave an error and not showing the plots, please put this command in the terminal:
```bash
sudo apt install python3-tk -y
```
### **4. Running the Code**
To process the `.pcap` files and generate plots, execute:
```bash
python src/Packet_Size.py
or
python src/IP_header.py
or
python src/TLS_Header_Fields.py
or
python src/TCP_Header_Fields.py
```
You should run each one individually based on what plots you want to see.

### **4. Viewing the Results**
- The generated figures and plots will be saved in the `/res/` directory.
- The `.pcap` files are **not included** in the repository due to size constraints. Instead, a cloud storage link is provided in `report.pdf`.

## **Traffic Capture Methodology**
1. Used **Wireshark** to record network traffic while using different applications.
2. Ensured minimal background noise (e.g., turned off automatic updates and notifications).
3. Recorded traffic for the following applications **one at a time:**
   - **Web Browsing 1**: Edge
   - **Web Browsing 2**: Firefox
   - **Audio Streaming**: Spotify (only audio, no video)
   - **Video Streaming**: YouTube
   - **Video Conferencing**: Zoom
4. Extracted relevant traffic features and filtered the pcaps and plotted comparisons.
5. We decrypted the code using the SSLKEYLOG and in our code we used the sslkeylog.log file to decrypt the packets before doing the plots.

## **Findings**
- **Spotify downloads audio in chunks rather than streaming continuously.**
- **Edge allows more data flow at once compared to Firefox.**
- **Zoom traffic consists of many small packets to maintain real time communication.**
- **YouTube’s captured data showed large packets.**
- **Even when encrypted, traffic patterns can help identify which applications were used.**

## **Contributors**
- **Mahasin Hamood** (212933907)
- **Omri Bessan** (206607905)
- **Leon Pasternak** (314789348)
- **Adham Hamoudy** (214225187)

## **Acknowledgments**
- Special thanks to Amit Dvir for guidance.
- AI tools like ChatGPT were used for structuring code and documentation.

---

