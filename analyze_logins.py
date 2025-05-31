# analyze_logins.py - تحليل سلوك محاولات الدخول مع تنبيه Telegram

import csv
from collections import defaultdict
import requests

# إعدادات Telegram
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
            print(f"[ERROR] Failed to send Telegram alert: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Telegram error: {e}")

# تحميل المحاولات الفاشلة
failed_logins = defaultdict(int)

with open('failed_logins.csv', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        message = str(row["Message"])
        for item in message.split(","):
            if "Account Name:" in item:
                username = item.strip().split(":")[-1].strip()
                if username and username != "-" and username.upper() != "NOUSER":
                    failed_logins[username] += 1

# تحميل المحاولات الناجحة
successful_logins = []

with open('successful_logins.csv', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        message = str(row["Message"])
        for item in message.split(","):
            if "Account Name:" in item:
                username = item.strip().split(":")[-1].strip()
                if username and username != "-" and username.upper() != "NOUSER":
                    successful_logins.append(username)

# تحليل السلوك
print("\n[INFO] Login Behavior Analysis Report")
print("======================================")

alerts = []

for user, fail_count in failed_logins.items():
    if user in successful_logins and fail_count >= 3:
        msg = f"[ALERT] User '{user}' had {fail_count} failed attempts, then succeeded."
        print(msg)
        alerts.append(msg)

for user, fail_count in failed_logins.items():
    if fail_count >= 6:
        msg = f"[WARNING] User '{user}' has {fail_count} failed login attempts. Possible brute-force."
        print(msg)
        alerts.append(msg)

if alerts:
    with open("alerts.txt", "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(alert + "\n")
    send_telegram_alerts(alerts)
else:
    print("[OK] No suspicious activity detected.")

# طباعة عدد المحاولات لكل مستخدم
print("\n[INFO] Summary of Failed Logins:")
for user, count in failed_logins.items():
    print(f" - {user}: {count} failed attempts")
