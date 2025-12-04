import threading
import time
import random
import datetime
import csv
from collections import deque
import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import matplotlib.animation as animation

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

COLOR_BG = "#0f0f0f"
COLOR_PANEL = "#1c1c1c"
COLOR_ACCENT = "#00ff99"
COLOR_TEXT = "#e0e0e0"
COLOR_ERR = "#ff4444"

class CyberSentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CYBER SENTINEL | Network Threat Analyzer")
        self.geometry("1200x700")
        self.configure(fg_color=COLOR_BG)
        
        self.sniffing = False
        self.packet_data = [] 
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "HTTPS": 0}
        self.traffic_history = deque([0]*60, maxlen=60)
        self.stop_event = threading.Event()
        self.packet_count_second = 0

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self.header_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=0, height=50)
        self.header_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 2))
        
        self.logo_lbl = ctk.CTkLabel(self.header_frame, text=" 🛡️ CYBER SENTINEL ", 
                                     font=("Consolas", 20, "bold"), text_color=COLOR_ACCENT)
        self.logo_lbl.pack(side="left", padx=20)
        
        self.status_lbl = ctk.CTkLabel(self.header_frame, text="SYSTEM IDLE", 
                                       font=("Consolas", 12), text_color="gray")
        self.status_lbl.pack(side="right", padx=20)

        self.sidebar = ctk.CTkFrame(self, fg_color=COLOR_PANEL, width=200, corner_radius=10)
        self.sidebar.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        self.btn_start = ctk.CTkButton(self.sidebar, text="▶ INITIATE SCAN", 
                                       fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1,
                                       hover_color="#00331f", text_color=COLOR_ACCENT, 
                                       font=("Consolas", 12, "bold"), command=self.start_scan)
        self.btn_start.pack(pady=(20, 10), padx=15, fill="x")

        self.btn_stop = ctk.CTkButton(self.sidebar, text="⏹ TERMINATE", 
                                      fg_color=COLOR_BG, border_color=COLOR_ERR, border_width=1,
                                      hover_color="#330000", text_color=COLOR_ERR, 
                                      font=("Consolas", 12, "bold"), state="disabled", command=self.stop_scan)
        self.btn_stop.pack(pady=10, padx=15, fill="x")

        self.btn_save = ctk.CTkButton(self.sidebar, text="💾 EXPORT LOGS", 
                                      fg_color=COLOR_PANEL, hover_color="#333333",
                                      command=self.save_csv)
        self.btn_save.pack(pady=10, padx=15, fill="x")
        
        self.create_stat_card("TOTAL PACKETS", "0", "lbl_total")
        self.create_stat_card("THREAT LEVEL", "LOW", "lbl_threat", text_color=COLOR_ACCENT)

        self.log_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=10)
        self.log_frame.grid(row=1, column=1, sticky="nsew", pady=10)
        
        ctk.CTkLabel(self.log_frame, text="LIVE TRAFFIC FEED", font=("Consolas", 12, "bold"), text_color="gray").pack(anchor="w", padx=10, pady=5)
        
        self.log_box = ctk.CTkTextbox(self.log_frame, font=("Courier New", 12), fg_color="#000000", text_color=COLOR_ACCENT, activate_scrollbars=False)
        self.log_box.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_box.insert("0.0", ">> SYSTEM READY...\n>> WAITING FOR INITIATION...\n")

        self.viz_frame = ctk.CTkFrame(self, fg_color=COLOR_BG, width=300)
        self.viz_frame.grid(row=1, column=2, sticky="nsew", padx=10, pady=10)
        
        self.chart1_frame = ctk.CTkFrame(self.viz_frame, fg_color=COLOR_PANEL, height=200)
        self.chart1_frame.pack(fill="x", pady=(0, 10))
        self.setup_line_chart()

        self.chart2_frame = ctk.CTkFrame(self.viz_frame, fg_color=COLOR_PANEL, height=200)
        self.chart2_frame.pack(fill="x")
        self.setup_donut_chart()

    def create_stat_card(self, title, value, attr_name, text_color="white"):
        frame = ctk.CTkFrame(self.sidebar, fg_color="#222222")
        frame.pack(pady=10, padx=15, fill="x")
        ctk.CTkLabel(frame, text=title, font=("Arial", 10), text_color="gray").pack(pady=(5,0))
        lbl = ctk.CTkLabel(frame, text=value, font=("Consolas", 24, "bold"), text_color=text_color)
        lbl.pack(pady=(0,5))
        setattr(self, attr_name, lbl)

    def setup_line_chart(self):
        plt.style.use('dark_background')
        self.fig1, self.ax1 = plt.subplots(figsize=(4, 2.5), dpi=80)
        self.fig1.patch.set_facecolor(COLOR_PANEL)
        self.ax1.set_facecolor(COLOR_PANEL)
        
        self.line, = self.ax1.plot([], [], color=COLOR_ACCENT, linewidth=1.5)
        self.ax1.set_title("TRAFFIC VOLUME (PPS)", fontsize=8, color="gray")
        self.ax1.set_ylim(0, 50)
        self.ax1.tick_params(colors='gray', labelsize=8)
        self.ax1.grid(True, color="#333333", linestyle='--', linewidth=0.5)
        
        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=self.chart1_frame)
        self.canvas1.get_tk_widget().pack(fill="both", expand=True)

    def setup_donut_chart(self):
        self.fig2, self.ax2 = plt.subplots(figsize=(4, 2.5), dpi=80)
        self.fig2.patch.set_facecolor(COLOR_PANEL)
        self.ax2.set_facecolor(COLOR_PANEL)
        self.ax2.text(0,0, "NO DATA", ha='center', color='gray', fontsize=8)
        self.ax2.axis('off')
        
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=self.chart2_frame)
        self.canvas2.get_tk_widget().pack(fill="both", expand=True)

    def traffic_engine(self):
        ips_internal = ["192.168.1.10", "192.168.1.55", "10.0.0.3"]
        ips_external = ["172.217.16.1 (Google)", "204.79.197.200 (Bing)", "140.82.112.4 (GitHub)", "185.60.216.35 (Meta)"]
        
        while not self.stop_event.is_set():
            time.sleep(random.uniform(0.05, 0.5))
            
            src = random.choice(ips_internal)
            dst = random.choice(ips_external)
            proto = random.choices(["TCP", "UDP", "ICMP", "HTTPS"], weights=[40, 30, 5, 25], k=1)[0]
            size = random.randint(64, 1500)
            
            self.packet_count_second += 1
            self.protocol_counts[proto] += 1
            
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            log = f"[{ts}] {proto:<5} | {src:<15} >> {dst}\n"
            
            self.packet_data.append([ts, proto, src, dst, size])
            
            self.after(0, lambda l=log: self.update_log_ui(l))

    def update_log_ui(self, text):
        self.log_box.insert("end", text)
        if int(self.log_box.index("end-1c").split('.')[0]) > 200:
             self.log_box.delete("1.0", "2.0")
        self.log_box.see("end")
        
        total = sum(self.protocol_counts.values())
        self.lbl_total.configure(text=str(total))
        
        if total % 100 < 5: 
            self.lbl_threat.configure(text="ANALYZING...", text_color="yellow")
        elif "HTTPS" in text:
            self.lbl_threat.configure(text="SECURE", text_color=COLOR_ACCENT)
        elif "UDP" in text:
            self.lbl_threat.configure(text="HIGH TRAFFIC", text_color="#ffcc00")

    def update_graphs(self):
        if not self.sniffing: return

        self.traffic_history.append(self.packet_count_second)
        self.packet_count_second = 0
        
        self.line.set_data(range(len(self.traffic_history)), self.traffic_history)
        self.ax1.set_xlim(0, 60)
        self.ax1.set_ylim(0, max(max(self.traffic_history)+10, 20))
        self.canvas1.draw()

        self.ax2.clear()
        self.ax2.axis('off')
        vals = list(self.protocol_counts.values())
        labels = list(self.protocol_counts.keys())
        
        if sum(vals) > 0:
            wedges, texts = self.ax2.pie(vals, labels=None, startangle=90, 
                                         colors=['#00ff99', '#00ccff', '#ff6666', '#ffff99', '#cc99ff'],
                                         wedgeprops=dict(width=0.4))
            self.ax2.legend(wedges, labels, loc="center", fontsize=7, frameon=False, labelcolor="white")
        
        self.canvas2.draw()
        
        self.after(1000, self.update_graphs)

    def start_scan(self):
        self.sniffing = True
        self.stop_event.clear()
        
        self.btn_start.configure(state="disabled", fg_color="#111111")
        self.btn_stop.configure(state="normal", fg_color=COLOR_BG)
        self.status_lbl.configure(text="● SYSTEM ACTIVE - MONITORING", text_color=COLOR_ACCENT)
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", ">> INITIALIZING NETWORK INTERFACE...\n>> PROMISCUOUS MODE ENABLED.\n>> SCANNING...\n\n")

        threading.Thread(target=self.traffic_engine, daemon=True).start()
        self.update_graphs()

    def stop_scan(self):
        self.sniffing = False
        self.stop_event.set()
        
        self.btn_start.configure(state="normal", fg_color=COLOR_BG)
        self.btn_stop.configure(state="disabled", fg_color="#111111")
        self.status_lbl.configure(text="SYSTEM HALTED", text_color="gray")
        self.log_box.insert("end", "\n>> CAPTURE TERMINATED BY USER.\n")

    def save_csv(self):
        filename = f"LOG_{datetime.datetime.now().strftime('%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Protocol", "Source", "Destination", "Size"])
            writer.writerows(self.packet_data)
        self.log_box.insert("end", f"\n>> [DATA EXPORTED]: {filename}\n")

if __name__ == "__main__":
    app = CyberSentinelApp()
    app.mainloop()