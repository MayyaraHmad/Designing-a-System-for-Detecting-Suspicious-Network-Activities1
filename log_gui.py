# log_gui.py - واجهة رسومية لتشغيل log_tool.exe

import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import os

def run_command(mode):
    try:
        result = subprocess.run(
            ['log_tool.exe', '--mode', mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.getcwd()
        )
        output = result.stdout + "\n" + result.stderr
        output_box.delete('1.0', tk.END)
        output_box.insert(tk.END, output)

        if result.returncode == 0:
            messagebox.showinfo("Success", f"{mode.upper()} completed successfully.")
        else:
            messagebox.showwarning("Warning", f"{mode.upper()} finished with warnings or errors.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# إعداد نافذة GUI
root = tk.Tk()
root.title("LogSentinel - Cybersecurity Tool")
root.geometry("650x550")

# عنوان
tk.Label(root, text="Cybersecurity Log Analyzer GUI", font=("Arial", 16, "bold")).pack(pady=10)

# أزرار التحكم
frame = tk.Frame(root)
frame.pack(pady=10)

buttons = [
    ("Extract Logs", "extract"),
    ("Analyze Logins", "analyze"),
    ("Visualize Data", "visualize"),
    ("Analyze IIS Logs", "iis-analyze")
]

for idx, (label, mode) in enumerate(buttons):
    tk.Button(frame, text=label, width=20, command=lambda m=mode: run_command(m)).grid(row=idx//2, column=idx%2, padx=10, pady=5)

# صندوق المخرجات
tk.Label(root, text="Output:").pack()
output_box = scrolledtext.ScrolledText(root, width=75, height=20)
output_box.pack(padx=10, pady=10)

root.mainloop()
