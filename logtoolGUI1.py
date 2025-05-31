import tkinter as tk
from tkinter import messagebox
import csv
import os
import subprocess
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import requests
import time
import re

# --- Backend Log Analysis Functions (from log_tool1.py, with original names) ---

# Telegram bot settings
bot_token = "7228914341:AAHuoMlfSyeDDyjCDZihQnsPElAWdnULhSM"
chat_id = "2137091905"

def send_telegram_alerts(alerts):
    message = "\n".join(alerts)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print("[OK] Telegram alert sent.")
        else:
            print(f"[ERROR] Failed to send Telegram alert: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[ERROR] Telegram exception: {e}")

def extract_events():
    """
    Extracts authentication events from /var/log/auth.log on Linux Mint/Ubuntu.
    Parses failed and successful login attempts (SSH, sudo).
    """
    auth_log_file = "/var/log/auth.log" # Common authentication log path in Linux Mint

    if not os.path.exists(auth_log_file):
        messagebox.showerror("Error", f"Authentication log file not found at {auth_log_file}.\n"
                                      "Ensure you are on Linux Mint/Ubuntu and have read permissions.")
        return

    failed_logins_data = []
    successful_logins_data = []

    # Regex patterns for extracting usernames from auth.log lines
    failed_ssh_regex = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
    accepted_ssh_regex = re.compile(r"Accepted password for (\S+) from (\S+) port")
    sudo_auth_regex = re.compile(r"sudo: (\S+) : TTY=")
    
    try:
        with open(auth_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                timestamp_match = re.match(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
                timestamp = timestamp_match.group(1) if timestamp_match else "Unknown Time"
                source = "auth.log"

                failed_match = failed_ssh_regex.search(line)
                if failed_match:
                    username = failed_match.group(1)
                    ip_address = failed_match.group(2)
                    failed_logins_data.append([timestamp, "4625", source, username, ip_address, line.strip()])
                    continue

                accepted_match = accepted_ssh_regex.search(line)
                if accepted_match:
                    username = accepted_match.group(1)
                    ip_address = accepted_match.group(2)
                    successful_logins_data.append([timestamp, "4624", source, username, ip_address, line.strip()])
                    continue

                sudo_match = sudo_auth_regex.search(line)
                if sudo_match and "authentication failure" not in line.lower():
                    username = sudo_match.group(1)
                    successful_logins_data.append([timestamp, "4624", source, username, "localhost", line.strip()])
                    continue

        with open('failed_logins.csv', 'w', newline='', encoding='utf-8') as failed:
            writer = csv.writer(failed)
            writer.writerow(["TimeGenerated", "EventID", "Source", "AccountName", "IPAddress", "RawMessage"])
            writer.writerows(failed_logins_data)

        with open('successful_logins.csv', 'w', newline='', encoding='utf-8') as success:
            writer = csv.writer(success)
            writer.writerow(["TimeGenerated", "EventID", "Source", "AccountName", "IPAddress", "RawMessage"])
            writer.writerows(successful_logins_data)

        messagebox.showinfo("Success", "Extraction complete. Data saved to failed_logins.csv and successful_logins.csv.")
    except PermissionError:
        messagebox.showerror("Permission Denied", f"Permission denied to read {auth_log_file}.\nPlease run the script with sudo.")
    except Exception as e:
        messagebox.showerror("Error", f"Error during extraction: {e}")

def analyze_logins():
    """
    Analyzes failed login attempts from the generated CSV file
    and sends alerts for potential brute-force attacks.
    """
    if not os.path.exists("failed_logins.csv"):
        messagebox.showerror("Error", "Required CSV file 'failed_logins.csv' not found. Please run 'Extract Logs' first.")
        return

    failed_logins = defaultdict(int)
    alerts = []

    try:
        with open('failed_logins.csv', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                username = row.get("AccountName", "unknown")
                ip_address = row.get("IPAddress", "unknown")
                
                if username and username.strip().lower() not in ("", "-", "nouser"):
                    failed_logins[f"User: {username} from IP: {ip_address}"] += 1

        print("[INFO] Brute-force attack detection report")
        has_alerts = False
        for user_ip, count in failed_logins.items():
            if count >= 6: # Brute-force detection threshold
                alert = f"[ALERT] {user_ip} has {count} failed login attempts. Potential brute-force attack!"
                print(alert)
                alerts.append(alert)
                has_alerts = True

        if alerts:
            with open("alerts.txt", "w", encoding="utf-8") as f:
                for alert in alerts:
                    f.write(alert + "\n")
            send_telegram_alerts(alerts)
            messagebox.showinfo("Alerts Generated", "Alerts saved to alerts.txt and sent via Telegram.")
        elif not has_alerts:
            messagebox.showinfo("Analysis Complete", "No suspicious activity detected based on failed login threshold.")
    except Exception as e:
        messagebox.showerror("Error", f"Error analyzing logins: {e}")

def visualize_logins():
    """
    Visualizes failed and successful login attempts per user.
    """
    if not os.path.exists("failed_logins.csv") or not os.path.exists("successful_logins.csv"):
        messagebox.showerror("Error", "CSV files not found. Please run 'Extract Logs' first.")
        return

    failed_users_counts = defaultdict(int)
    success_users_counts = defaultdict(int)

    try:
        with open('failed_logins.csv', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                username = row.get("AccountName")
                if username:
                    failed_users_counts[username] += 1

        with open('successful_logins.csv', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                username = row.get("AccountName")
                if username:
                    success_users_counts[username] += 1

        all_users = sorted(list(set(failed_users_counts.keys()).union(set(success_users_counts.keys()))))
        
        if not all_users:
            messagebox.showinfo("Info", "No user data found for visualization.")
            return

        failed_values = [failed_users_counts[u] for u in all_users]
        success_values = [success_users_counts[u] for u in all_users]

        x = range(len(all_users))
        plt.figure(figsize=(12, 7))
        
        bar_width = 0.35
        # Colors for the chart remain red/green for visual clarity of failed/successful
        plt.bar([i - bar_width/2 for i in x], failed_values, width=bar_width, label='Failed Logins', color='#dc3545', align='center')
        plt.bar([i + bar_width/2 for i in x], success_values, width=bar_width, label='Successful Logins', color='#28a745', align='center')
        
        plt.xticks(x, all_users, rotation=45, ha='right')
        plt.xlabel('Users', fontsize=12)
        plt.ylabel('Login Attempts', fontsize=12)
        plt.title('Login Attempts Per User', fontsize=14)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig('login_chart.png')
        messagebox.showinfo("Visualization Complete", "Login chart saved to login_chart.png")
        # plt.show() # Uncomment to display the plot immediately
    except Exception as e:
        messagebox.showerror("Error", f"Error during visualization: {e}")

def analyze_web_logs():
    """
    Analyzes common Linux web server logs (Apache/Nginx) for suspicious activity.
    """
    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/error.log",
        # Add other common Linux Mint/Ubuntu web log paths if needed
    ]
    
    found_logs = [p for p in log_paths if os.path.exists(p)]

    if not found_logs:
        messagebox.showerror("Error", "No common web server log files (Apache/Nginx) found.\n"
                                      "Ensure web server is installed and logs exist, or specify custom paths.")
        return

    alerts = []
    ip_request_counter = Counter()
    status_code_counter = Counter()
    not_found_errors = defaultdict(int)
    error_messages = []

    print(f"[INFO] Analyzing web logs from: {', '.join(found_logs)}")

    try:
        for file_path in found_logs:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    
                    parts = line.split()
                    
                    if "access.log" in file_path:
                        if len(parts) >= 10:
                            ip = parts[0]
                            status_code = parts[len(parts) - 2]
                            
                            ip_request_counter[ip] += 1
                            status_code_counter[status_code] += 1
                            
                            if status_code == "404":
                                not_found_errors[ip] += 1
                    elif "error.log" in file_path:
                        if "error" in line.lower() or "failed" in line.lower() or "denied" in line.lower():
                            error_messages.append(line.strip())

        for ip, count in ip_request_counter.items():
            if count > 500:
                alert = f"[ALERT] High request volume from IP {ip}: {count} requests."
                print(alert)
                alerts.append(alert)

        for ip, count in not_found_errors.items():
            if count > 20:
                alert = f"[ALERT] IP {ip} caused {count} 404 (Not Found) errors. Potential scanning or directory brute-force."
                print(alert)
                alerts.append(alert)

        if "403" in status_code_counter and status_code_counter["403"] > 50:
            alert = f"[WARNING] High number of 403 (Forbidden) errors: {status_code_counter['403']}. Check access control or malicious attempts."
            print(alert)
            alerts.append(alert)

        if error_messages:
            top_errors = "\n".join(error_messages[:5])
            alert = f"[WARNING] {len(error_messages)} web server error messages detected. Top errors:\n{top_errors}"
            print(alert)
            alerts.append(alert)

        if alerts:
            with open("web_alerts.txt", "w", encoding="utf-8") as f:
                for alert in alerts:
                    f.write(alert + "\n")
            send_telegram_alerts(alerts)
            messagebox.showinfo("Web Alerts Generated", "Web analysis alerts saved and sent.")
        else:
            messagebox.showinfo("Web Analysis Complete", "No significant suspicious web activity detected.")
    except PermissionError:
        messagebox.showerror("Permission Denied", "Permission denied to read web log files.\nPlease run the script with sudo.")
    except Exception as e:
        messagebox.showerror("Error", f"Error during web log analysis: {e}")

# The block_ip_timed function is omitted as it requires sudo and can block the GUI.

# --- GUI Definition (from code3GUI.py, with original names and new color scheme) ---

def create_gui():
    root = tk.Tk()
    root.title("Designing a System for Detecting Suspicious Network Activities")
    root.geometry("500x550")
    root.configure(bg="#f0f0f0") # Very light gray background (close to white)

    # --- Header ---
    header = tk.Label(
        root,
        text="Cyber Security Log Analyzer",
        font=("Arial", 18, "bold"),
        bg="#f0f0f0",
        fg="#333333"  # Dark gray text
    )
    header.pack(pady=30)

    # --- Button Frame ---
    button_frame = tk.Frame(root, bg="#f0f0f0")
    button_frame.pack(pady=20)

    # --- Functions to be linked to buttons (using original names) ---
    def on_extract_logs():
        print("Extract Logs button clicked!")
        extract_events() # Call the function by its original name

    def on_analyze_logins():
        print("Analyze Logins button clicked!")
        analyze_logins() # Call the function by its original name

    def on_visualize_data():
        print("Visualize Data button clicked!")
        visualize_logins() # Call the function by its original name

    def on_analyze_iis_logs(): # Original button name, but calls generic web log analysis
        print("Analyze IIS Logs button clicked!")
        analyze_web_logs() # Call the function by its original name

    # --- Buttons and their commands ---
    # Button styling with white, black, and gray colors
    button_style = {
        "width": 30,
        "height": 2,
        "bg": "#ffffff",        # White background
        "fg": "#000000",        # Black text
        "activebackground": "#cccccc", # Light gray when pressed
        "relief": "raised",     # Raised design for a tactile feel
        "bd": 2,                # Slightly thicker border
        "font": ("Arial", 11, "bold"),
        "cursor": "hand2"
    }

    buttons_config = [
        {"text": "Extract Logs", "command": on_extract_logs},
        {"text": "Analyze Logins", "command": on_analyze_logins},
        {"text": "Visualize Data", "command": on_visualize_data},
        {"text": "Analyze IIS Logs", "command": on_analyze_iis_logs}
    ]

    for config in buttons_config:
        btn = tk.Button(button_frame, text=config["text"], command=config["command"], **button_style)
        btn.pack(pady=10)

    # --- Footer/Instructions ---
    footer = tk.Label(
        root,
        #text="Ensure necessary permissions (sudo) for log access.",
        font=("Arial", 10, "italic"),
        bg="#f0f0f0",
        fg="#666666" # Medium gray
    )
    footer.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
