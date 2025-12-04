🛡️ Cyber Sentinel 

Cyber Sentinel is a high-fidelity network traffic simulation and analysis tool featuring a cyberpunk-inspired interface. It visualizes simulated packet data in real-time, monitors protocol distribution, and acts as a dashboard for threat detection.

⚡ Features

Live Traffic Simulation: Generates realistic synthetic network traffic (TCP, UDP, HTTP, etc.) between internal and external IP addresses.

Real-Time Visualization:

Traffic Volume: Live line chart showing packets per second (PPS).

Protocol Distribution: Dynamic donut chart breaking down traffic by type.

Threat Detection: Automated logic to flag high-traffic events or specific protocol activities.

Data Persistence: Export captured packet logs to CSV format for external analysis.

Immersive UI: Built with CustomTkinter for a modern, dark-mode, terminal-like aesthetic.

🛠️ Tech Stack

Language: Python 3.x

GUI Framework: CustomTkinter

Data Visualization: Matplotlib (embedded via FigureCanvasTkAgg)

Concurrency: Python threading module for non-blocking simulation

🚀 Installation & Setup

Install Dependencies:
You need customtkinter for the UI and matplotlib for the graphs.

pip install customtkinter matplotlib


Run the System:

python cyber_sentinel.py


📖 Usage Guide

▶ INITIATE SCAN: Starts the background thread that simulates network traffic. The graphs and log will begin to update immediately.

⏹ TERMINATE: Stops the simulation thread.

💾 EXPORT LOGS: Saves the current session's packet data to a timestamped CSV file (e.g., LOG_123456.csv) in the local directory.

🧠 Simulation Logic

The application uses a dedicated thread to simulate network "sniffing." It randomly generates packets with varying attributes (Source IP, Destination IP, Protocol, Size) and updates the UI every second. This simulates the behavior of a real Intrusion Detection System (IDS) dashboard without requiring actual network interface permissions.

📄 License

This project is open-source and available under the MIT License.
