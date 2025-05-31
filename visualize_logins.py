# visualize_logins.py - رسم بياني لمحاولات الدخول مع تتبع البيانات (باستخدام الفهرس الثابت)

import csv
from collections import defaultdict
import matplotlib.pyplot as plt
import ast

failed_users = defaultdict(int)
success_users = defaultdict(int)

print("\n[DEBUG] Loading failed_logins.csv...")
with open('failed_logins.csv', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        try:
            message = ast.literal_eval(row["Message"])
            username = message[5].strip()
            print("[DEBUG] Failed Username:", username)
            if username and username != "-" and username.upper() != "NOUSER":
                failed_users[username] += 1
        except:
            continue

print("\n[DEBUG] Loading successful_logins.csv...")
with open('successful_logins.csv', newline='', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        try:
            message = ast.literal_eval(row["Message"])
            username = message[5].strip()
            print("[DEBUG] Success Username:", username)
            if username and username != "-" and username.upper() != "NOUSER":
                success_users[username] += 1
        except:
            continue

# دمج المستخدمين وإنشاء المخطط
all_users = set(failed_users.keys()).union(set(success_users.keys()))
users = list(all_users)
failed_counts = [failed_users[u] for u in users]
success_counts = [success_users[u] for u in users]

print("\n[DEBUG] Users:", users)
print("[DEBUG] Failed Counts:", failed_counts)
print("[DEBUG] Success Counts:", success_counts)

if not users:
    print("[INFO] No login attempts found in the logs. Check your CSV files.")
else:
    x = range(len(users))
    plt.figure(figsize=(10, 6))
    plt.bar(x, failed_counts, width=0.4, label='Failed Logins', color='red', align='center')
    plt.bar(x, success_counts, width=0.4, label='Successful Logins', color='green', align='edge')
    plt.xticks(x, users, rotation=45)
    plt.xlabel('Users')
    plt.ylabel('Login Attempts')
    plt.title('Login Attempts per User')
    plt.legend()
    plt.tight_layout()
    plt.savefig('login_chart.png')
    plt.show()

    print("[INFO] Chart saved as login_chart.png and displayed.")
