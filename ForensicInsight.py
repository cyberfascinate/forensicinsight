import os
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# Set the output directory
output_dir = "C:/ForensicReports"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

report_timestamp = None  # Global timestamp for matching HTML report

# Create the main GUI window
root = tk.Tk()
root.title("Forensic Insight")
root.geometry("400x350")
root.configure(bg="#1f1f1f")

# Status label
status_label = tk.Label(root, text="Status: Ready", font=("Helvetica", 12), bg="#1f1f1f", fg="white")
status_label.pack(pady=10)

# Progress bar
progress_bar = ttk.Progressbar(root, length=300, mode="indeterminate")
progress_bar.pack(pady=10)

# Collect forensic data and write plaintext report
def collect_forensic_data():
    global report_timestamp
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    progress_bar.start()
    try:
        timeline_file = os.path.join(output_dir, f"Combined_Timeline_{report_timestamp}.txt")
        with open(timeline_file, 'w', encoding='utf-8') as f:
            f.write(f"Forensic Insight Report\nGenerated on: {now}\n\n")

            f.write("=== SYSTEM LOG ===\n")
            f.write(subprocess.getoutput("wevtutil qe System /rd:true /c:10 /f:text") + "\n\n")

            f.write("=== APPLICATION LOG ===\n")
            f.write(subprocess.getoutput("wevtutil qe Application /rd:true /c:10 /f:text") + "\n\n")

            try:
                f.write("=== SECURITY LOG ===\n")
                f.write(subprocess.getoutput("wevtutil qe Security /rd:true /c:10 /f:text") + "\n\n")
            except Exception:
                f.write("Error reading Security log.\n\n")

            recent_folder = os.path.expandvars("%USERPROFILE%\\Recent")
            f.write("=== RECENTLY USED FILES ===\n")
            f.write(subprocess.getoutput(f'dir /b /o:d /a:-d "{recent_folder}\\*"') + "\n\n")

            f.write("=== RECENT PROGRAMS (UserAssist) ===\n")
            f.write(subprocess.getoutput('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" /s | findstr /i "Count"') + "\n\n")

            f.write("=== NETWORK CONNECTIONS ===\n")
            f.write(subprocess.getoutput("netstat -ano"))

        status_label.config(text="Status: Forensic Analysis Completed")
        messagebox.showinfo("Forensic Analysis", "Forensic analysis completed. Report saved.")
    except Exception as e:
        status_label.config(text="Status: Error during analysis")
        messagebox.showerror("Error", f"An error occurred: {e}")
    finally:
        progress_bar.stop()

# Generate and open HTML report
def open_report():
    global report_timestamp
    if not report_timestamp:
        messagebox.showerror("Error", "No report has been generated yet.")
        return

    report_file = os.path.join(output_dir, f"Forensic_Report_{report_timestamp}.html")
    analysis_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        hostname = subprocess.getoutput("hostname")
        windows_version = subprocess.getoutput("ver")

        sec_logs = subprocess.getoutput("wevtutil qe Security /c:20 /rd:true /f:text")
        app_logs = subprocess.getoutput("wevtutil qe Application /c:20 /rd:true /f:text")
        sys_logs = subprocess.getoutput("wevtutil qe System /c:20 /rd:true /f:text")

        netstat_output = subprocess.getoutput("netstat -an")
        tcp_lines = [line for line in netstat_output.splitlines() if "TCP" in line]
        udp_lines = [line for line in netstat_output.splitlines() if "UDP" in line]
        listening_lines = [line for line in netstat_output.splitlines() if "LISTENING" in line]

        tcp_output = '\n'.join(tcp_lines)
        udp_output = '\n'.join(udp_lines)
        listening_output = '\n'.join(listening_lines)

        sec_entries = sec_logs.count("Event ID")
        app_entries = app_logs.count("Event ID")
        sys_entries = sys_logs.count("Event ID")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report</title>
<style>
    body {{
        background-color: #0e1628;
        font-family: Arial, sans-serif;
        color: #ffffff;
        padding: 20px;
    }}
    h1 {{
        color: #ffffff;
    }}
    .badge {{
        background-color: #2ecc71;
        color: white;
        padding: 5px 10px;
        border-radius: 8px;
        float: right;
    }}
    .card {{
        background-color: #1c2b3a;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }}
    .title {{
        font-size: 18px;
        font-weight: bold;
        margin-bottom: 10px;
    }}
    pre {{
        background-color: #0e1b2d;
        padding: 10px;
        border-radius: 8px;
        overflow-x: auto;
        max-height: 300px;
        white-space: pre-wrap;
    }}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>Forensic Insight Report</h1>

    <div class="card">
        <div class="title">System Information</div>
        <p><strong>Hostname:</strong> {hostname}</p>
        <p><strong>Windows Version:</strong> {windows_version}</p>
        <p><strong>Analysis Time:</strong> {analysis_time}</p>
    </div>

    <div class="card">
        <div class="title">Event Log Summary</div>
        <p>Security Logs: {sec_entries}</p>
        <p>Application Logs: {app_entries}</p>
        <p>System Logs: {sys_entries}</p>
        <p>TCP Connections: {len(tcp_lines)}</p>
        <p>UDP Connections: {len(udp_lines)}</p>
        <p>Listening Ports: {len(listening_lines)}</p>
    </div>

    <div class="card">
        <div class="title">Summary Chart</div>
        <canvas id="logChart" width="400" height="200"></canvas>
    </div>

    <div class="card">
        <div class="title">Security Logs</div>
        <pre>{sec_logs}</pre>
    </div>

    <div class="card">
        <div class="title">Application Logs</div>
        <pre>{app_logs}</pre>
    </div>

    <div class="card">
        <div class="title">System Logs</div>
        <pre>{sys_logs}</pre>
    </div>

    <div class="card">
        <div class="title">TCP Connections</div>
        <pre>{tcp_output}</pre>
    </div>

    <div class="card">
        <div class="title">UDP Connections</div>
        <pre>{udp_output}</pre>
    </div>

    <div class="card">
        <div class="title">Listening Ports</div>
        <pre>{listening_output}</pre>
    </div>

    <script>
    const ctx = document.getElementById('logChart').getContext('2d');
    const chart = new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: ['Security Logs', 'Application Logs', 'System Logs', 'TCP', 'UDP', 'Listening'],
            datasets: [{{
                label: 'Forensic Data Overview',
                data: [{sec_entries}, {app_entries}, {sys_entries}, {len(tcp_lines)}, {len(udp_lines)}, {len(listening_lines)}],
                backgroundColor: ['#e74c3c', '#3498db', '#f1c40f', '#2ecc71', '#9b59b6', '#e67e22']
            }}]
        }},
        options: {{
            responsive: true,
            scales: {{
                y: {{
                    beginAtZero: true
                }}
            }}
        }}
    }});
    </script>

</body>
</html>
""")
        os.startfile(report_file)
    except Exception as e:
        messagebox.showerror("Error", f"Error generating HTML report: {e}")

# Buttons
start_button = tk.Button(root, text="Start Forensic Analysis", font=("Helvetica", 12), command=collect_forensic_data, bg="#2ecc71", fg="white")
start_button.pack(pady=20)

open_report_button = tk.Button(root, text="Open HTML Report", font=("Helvetica", 12), command=open_report, bg="#3498db", fg="white")
open_report_button.pack(pady=10)

# Run GUI loop
root.mainloop()
