import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import random
from datetime import datetime

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer Simulator")
        self.root.geometry("900x600")
        self.root.configure(bg="#f9d6e8")
        
        # Initialize variables
        self.packet_count = 0
        self.is_capturing = False
        self.after_id = None
        
        # Sample protocol and IP data
        self.protocols = ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP']
        self.sources = ['192.168.1.{}'.format(i) for i in range(1, 20)]
        self.destinations = ['10.0.0.{}'.format(i) for i in range(1, 20)] + \
                          ['google.com', 'facebook.com', 'youtube.com']
        
        # Set up styles for the UI
        self.configure_styles()
        
        # Create the main UI components
        self.create_widgets()
        
        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def configure_styles(self):
        # Set styles for the application
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Background colors
        self.style.configure('TFrame', background='#f9d6e8')
        self.style.configure('TLabel', background='#f9d6e8', foreground='black')
        
        # Button styles
        self.style.configure('TButton', background='#ff85a2', foreground='black')
        self.style.map('TButton',
                      background=[('active', '#ff9eb7'), ('disabled', '#d3d3d3')])
        
        # Treeview styles for packet display
        self.style.configure('Treeview', 
                           background='white', 
                           fieldbackground='white',
                           foreground='black')
        self.style.map('Treeview', 
                      background=[('selected', '#ff85a2')],
                      foreground=[('selected', 'black')])

    def create_widgets(self):
        # Create and arrange all the UI components
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control panel for buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(control_frame, text="Clear", command=self.clear_packets)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Create the packet display treeview
        self.create_packet_tree(main_frame)
        
        # Create the area to show packet details
        self.create_details_area(main_frame)
        
        # Status bar to show current status
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(10, 0))

    def create_packet_tree(self, parent):
        # Create the treeview to display captured packets
        columns = ('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length')
        self.tree = ttk.Treeview(parent, columns=columns, show='headings', selectmode='browse')
        
        # Set up column headings
        for col in columns:
            self.tree.heading(col, text=col, anchor=tk.CENTER)
            self.tree.column(col, width=100, anchor=tk.CENTER)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add a scrollbar for the treeview
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind selection event to show packet details
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)

    def create_details_area(self, parent):
        # Create the area to display details of the selected packet
        details_frame = ttk.Frame(parent)
        details_frame.pack(fill=tk.BOTH, expand=False, pady=(10, 0))
        
        ttk.Label(details_frame, text="Packet Details:").pack(anchor=tk.W)
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame, 
            height=8, 
            wrap=tk.WORD,
            font=('Consolas', 10)
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)

    def start_capture(self):
        # Start simulating packet capture
        self.is_capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Capturing packets...")
        self.simulate_packets()

    def stop_capture(self):
        # Stop the packet capture simulation
        self.is_capturing = False
        if self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Capture stopped")

    def clear_packets(self):
        # Clear all captured packets from the display
        if self.is_capturing:
            self.stop_capture()
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.status_var.set("Packet list cleared")

    def simulate_packets(self):
        # Simulate incoming network packets
        if not self.is_capturing:
            return
            
        # Generate random packet data
        protocol = random.choice(self.protocols)
        source = random.choice(self.sources)
        dest = random.choice(self.destinations)
        length = random.randint(64, 1500)
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Add packet data to the treeview
        self.packet_count += 1
        self.tree.insert('', tk.END, values=(
            self.packet_count, 
            timestamp, 
            source, 
            dest, 
            protocol, 
            length
        ))
        
        # Auto-scroll to the bottom of the treeview
        self.tree.yview_moveto(1)
        
        # Update status message
        self.status_var.set(f"Captured {self.packet_count} packets")
        
        # Schedule the next packet simulation
        delay = random.uniform(0.1, 1.5)
        self.after_id = self.root.after(int(delay * 1000), self.simulate_packets)

    def show_packet_details(self, event=None):
        # Show details for the selected packet
        selected_item = self.tree.selection()
        if not selected_item:
            return
            
        item = self.tree.item(selected_item)
        packet_data = item['values']
        
        details = f"""Packet #{packet_data[0]} Details:
-----------------------------
Timestamp: {packet_data[1]}
Source: {packet_data[2]}
Destination: {packet_data[3]}
Protocol: {packet_data[4]}
Length: {packet_data[5]} bytes

Simulated Payload:
"""
        
        # Generate payload based on protocol
        if packet_data[4] == 'HTTP':
            details += self.generate_http_payload()
        elif packet_data[4] == 'DNS':
            details += self.generate_dns_payload()
        else:
            details += self.generate_generic_payload()
            
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)

    def generate_http_payload(self):
        # Create a simulated HTTP payload
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        paths = ['/', '/index.html', '/api/data', '/images/logo.png']
        versions = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2']
        
        payload = f"{random.choice(methods)} {random.choice(paths)} {random.choice(versions)}\n"
        payload += f"Host: {random.choice(self.destinations)}\n"
        payload += "User -Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n"
        payload += "Accept: text/html,application/xhtml+xml\n"
        payload += "Connection: keep-alive\n\n"
        
        if random.random() > 0.7:  # 30% chance of including a request body
            payload += "{\"data\": \"sample request body\"}"
            
        return payload
        
    def generate_dns_payload(self):
        # Create a simulated DNS payload
        queries = ['www.example.com', 'mail.google.com', 'api.facebook.com', 'cdn.twitter.com']
        types = ['A', 'AAAA', 'MX', 'CNAME']
        
        payload = f"DNS Query for {random.choice(queries)}\n"
        payload += f"Type: {random.choice(types)}\n"
        payload += f"ID: 0x{random.randint(0x1000, 0xFFFF):04X}\n"
        payload += "Flags: Standard query\n"
        
        return payload
        
    def generate_generic_payload(self):
        # Create a simulated hex dump payload
        payload = "Hex Dump:\n"
        for _ in range(8):
            hex_line = ' '.join(f"{random.randint(0, 255):02X}" for _ in range(8))
            ascii_line = ''.join(chr(random.randint(32, 126)) for _ in range(8))
            payload += f"{hex_line}  {ascii_line}\n"
            
        return payload

    def show_error(self, title, message):
        # Show an error message
        messagebox.showerror(title, message)
        self.status_var.set(f"Error: {title}")

    def on_close(self):
        # Handle the window close event
        if self.is_capturing:
            self.stop_capture()
        self.root.destroy()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PacketSnifferApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
