# log_tool.py - أداة تحليل تسجيلات الدخول، التنبيهات، والرصد مع دعم الحظر المؤقت للمهاجمين (نسخة لينكس)

import argparse
import csv
import os
import subprocess
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import requests
import time
import re # لتحليل سطور السجل باستخدام التعبيرات النمطية

# إعدادات Telegram bot
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
    تستخرج أحداث المصادقة من /var/log/auth.log على Linux Mint.
    تحلل محاولات تسجيل الدخول الفاشلة (SSH, sudo) والناجحة (SSH, sudo).
    """
    auth_log_file = "/var/log/auth.log"
    
    if not os.path.exists(auth_log_file):
        print(f"[ERROR] ملف سجل المصادقة غير موجود في {auth_log_file}. "
              "تأكد من أنك تعمل على Linux Mint/Ubuntu ولديك أذونات القراءة.")
        return

    failed_logins_data = []
    successful_logins_data = []

    # تعابير نمطية لاستخراج أسماء المستخدمين من سطور auth.log
    # لـ SSH الفاشل: "Failed password for (invalid user)? (\S+) from (\S+) port"
    # لـ SSH المقبول: "Accepted password for (\S+) from (\S+) port"
    # لـ sudo: "sudo: (\S+) : TTY=..."
    failed_ssh_regex = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
    accepted_ssh_regex = re.compile(r"Accepted password for (\S+) from (\S+) port")
    sudo_auth_regex = re.compile(r"sudo: (\S+) : TTY=")
    
    try:
        with open(auth_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                timestamp_match = re.match(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
                timestamp = timestamp_match.group(1) if timestamp_match else "Unknown Time"
                source = "auth.log" # أو يمكن تحليل اسم المضيف (hostname)

                # تسجيلات الدخول الفاشلة (تعادل EventID 4625 في Windows)
                failed_match = failed_ssh_regex.search(line)
                if failed_match:
                    username = failed_match.group(1)
                    ip_address = failed_match.group(2)
                    failed_logins_data.append([timestamp, "4625", source, username, ip_address, line.strip()])
                    continue # معالجة السطر التالي

                # تسجيلات الدخول الناجحة (تعادل EventID 4624 في Windows)
                accepted_match = accepted_ssh_regex.search(line)
                if accepted_match:
                    username = accepted_match.group(1)
                    ip_address = accepted_match.group(2)
                    successful_logins_data.append([timestamp, "4624", source, username, ip_address, line.strip()])
                    continue

                # مصادقة Sudo (أيضًا شكل من أشكال تسجيل الدخول الناجح)
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

        print("[OK] تم الانتهاء من الاستخراج. تم حفظ البيانات في failed_logins.csv و successful_logins.csv.")
    except PermissionError:
        print(f"[ERROR] تم رفض الإذن لقراءة {auth_log_file}. يرجى تشغيل السكربت باستخدام sudo.")
    except Exception as e:
        print(f"[ERROR] خطأ أثناء الاستخراج: {e}")

def analyze_logins():
    """
    يحلل محاولات تسجيل الدخول الفاشلة من ملف CSV الذي تم إنشاؤه
    ويرسل تنبيهات لاحتمال هجمات القوة الغاشمة (brute-force).
    """
    if not os.path.exists("failed_logins.csv"):
        print("[ERROR] ملف CSV المطلوب 'failed_logins.csv' غير موجود. قم بتشغيل --mode extract أولاً.")
        return

    failed_logins = defaultdict(int)
    alerts = []

    try:
        with open('failed_logins.csv', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # نفترض أن عمودي 'AccountName' و 'IPAddress' تم تعبئتهما بشكل صحيح بواسطة extract_events
                username = row.get("AccountName", "unknown")
                ip_address = row.get("IPAddress", "unknown")
                
                if username and username.strip().lower() not in ("", "-", "nouser"):
                    failed_logins[f"المستخدم: {username} من IP: {ip_address}"] += 1

        print("[INFO] تقرير اكتشاف هجمات القوة الغاشمة (Brute-force)")
        has_alerts = False
        for user_ip, count in failed_logins.items():
            if count >= 6: # عتبة اكتشاف هجمات القوة الغاشمة
                alert = f"[تنبيه] {user_ip} لديه {count} محاولة تسجيل دخول فاشلة. احتمال هجوم قوة غاشمة!"
                print(alert)
                alerts.append(alert)
                has_alerts = True

        if alerts:
            with open("alerts.txt", "w", encoding="utf-8") as f:
                for alert in alerts:
                    f.write(alert + "\n")
            send_telegram_alerts(alerts)
            print("[OK] تم حفظ التنبيهات في alerts.txt وإرسالها عبر Telegram.")
        elif not has_alerts:
            print("[OK] لم يتم اكتشاف أي نشاط مشبوه بناءً على عتبة تسجيل الدخول الفاشل.")
    except Exception as e:
        print(f"[ERROR] خطأ أثناء تحليل تسجيلات الدخول: {e}")

def visualize_logins():
    """
    يعرض تصوراً بصرياً لمحاولات تسجيل الدخول الفاشلة والناجحة لكل مستخدم.
    """
    if not os.path.exists("failed_logins.csv") or not os.path.exists("successful_logins.csv"):
        print("[ERROR] ملفات CSV غير موجودة. قم بتشغيل --mode extract أولاً.")
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
        
        # التأكد من عدم وجود قوائم مستخدمين فارغة للرسم
        if not all_users:
            print("[معلومات] لم يتم العثور على بيانات المستخدم للتصور.")
            return

        failed_values = [failed_users_counts[u] for u in all_users]
        success_values = [success_users_counts[u] for u in all_users]

        x = range(len(all_users))
        plt.figure(figsize=(12, 7)) # حجم أكبر قليلاً للرسم لسهولة القراءة
        
        bar_width = 0.35 # عرض الأشرطة
        plt.bar([i - bar_width/2 for i in x], failed_values, width=bar_width, label='تسجيلات دخول فاشلة', color='#dc3545', align='center') # أحمر
        plt.bar([i + bar_width/2 for i in x], success_values, width=bar_width, label='تسجيلات دخول ناجحة', color='#28a745', align='center') # أخضر
        
        plt.xticks(x, all_users, rotation=45, ha='right') # تدوير ومحاذاة لأسماء المستخدمين الطويلة
        plt.xlabel('المستخدمون', fontsize=12)
        plt.ylabel('محاولات تسجيل الدخول', fontsize=12)
        plt.title('محاولات تسجيل الدخول لكل مستخدم', fontsize=14)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig('login_chart.png')
        print("[OK] تم حفظ مخطط تسجيل الدخول في login_chart.png")
        # plt.show() # إلغاء التعليق إذا أردت عرض المخطط فوراً
    except Exception as e:
        print(f"[ERROR] خطأ أثناء التصور: {e}")

def analyze_web_logs():
    """
    يحلل سجلات خادم الويب الشائعة في Linux (Apache/Nginx) بحثًا عن نشاط مشبوه.
    """
    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/error.log",
        # أضف مسارات أخرى شائعة إذا لزم الأمر، على سبيل المثال، /var/log/httpd/access_log لأنظمة RHEL
    ]
    
    found_logs = [p for p in log_paths if os.path.exists(p)]

    if not found_logs:
        print("[ERROR] لم يتم العثور على ملفات سجل خادم ويب شائعة (Apache/Nginx). "
              "تأكد من تثبيت خادم الويب ووجود السجلات، أو حدد مسارات مخصصة.")
        return

    alerts = []
    ip_request_counter = Counter()
    status_code_counter = Counter()
    not_found_errors = defaultdict(int) # عدد محدد لأخطاء 404 لكل IP
    error_messages = []

    print(f"[INFO] يتم تحليل سجلات الويب من: {', '.join(found_logs)}")

    try:
        for file_path in found_logs:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # تخطي سطور التعليق في سجلات Apache/Nginx
                    if line.startswith("#"):
                        continue
                    
                    parts = line.split()
                    
                    if "access.log" in file_path:
                        # تنسيق سجل الوصول الشائع لـ Apache/Nginx: IP - - [تاريخ وقت] "الأسلوب /المسار HTTP/1.1" الحالة البايتات "المُحيل" "وكيل المستخدم"
                        if len(parts) >= 10: # الحد الأدنى للأجزاء لـ IP والحالة
                            ip = parts[0]
                            status_code = parts[len(parts) - 2] # عادة ما يكون الجزء الثاني من النهاية للحالة
                            
                            ip_request_counter[ip] += 1
                            status_code_counter[status_code] += 1
                            
                            if status_code == "404":
                                not_found_errors[ip] += 1
                    elif "error.log" in file_path:
                        # تحليل بسيط لسجل الأخطاء: البحث عن "error", "failed", "denied"
                        if "error" in line.lower() or "failed" in line.lower() or "denied" in line.lower():
                            error_messages.append(line.strip())

        # اكتشاف الشذوذ والتنبيه
        for ip, count in ip_request_counter.items():
            if count > 500: # حجم طلبات مرتفع
                alert = f"[تنبيه] حجم طلبات مرتفع من IP {ip}: {count} طلب."
                print(alert)
                alerts.append(alert)
                # فكر في الحظر فقط إذا كان هجومًا شديدًا
                # block_ip_timed(ip, 300) # حظر فقط إذا كان تهديدًا حقيقيًا

        for ip, count in not_found_errors.items():
            if count > 20: # عدد كبير من أخطاء 404 من IP واحد
                alert = f"[تنبيه] IP {ip} تسبب في {count} خطأ 404 (لم يتم العثور عليه). احتمال مسح أو هجوم قوة غاشمة على الدلائل."
                print(alert)
                alerts.append(alert)
                block_ip_timed(ip, 300) # حظر مؤقت للمهاجمين العدوانيين

        if "403" in status_code_counter and status_code_counter["403"] > 50:
            alert = f"[تحذير] عدد كبير من أخطاء 403 (ممنوع): {status_code_counter['403']}. تحقق من التحكم في الوصول أو المحاولات الخبيثة."
            print(alert)
            alerts.append(alert)

        if error_messages:
            top_errors = "\n".join(error_messages[:5]) # عرض أحدث 5 أخطاء
            alert = f"[تحذير] تم الكشف عن {len(error_messages)} رسالة خطأ لخادم الويب. أهم الأخطاء:\n{top_errors}"
            print(alert)
            alerts.append(alert)

        if alerts:
            with open("web_alerts.txt", "w", encoding="utf-8") as f:
                for alert in alerts:
                    f.write(alert + "\n")
            send_telegram_alerts(alerts)
            print("[OK] تم حفظ تنبيهات تحليل الويب وإرسالها.")
        else:
            print("[OK] لم يتم اكتشاف أي نشاط ويب مشبوه كبير.")
    except PermissionError:
        print(f"[ERROR] تم رفض الإذن لقراءة ملفات سجل الويب. يرجى تشغيل السكربت باستخدام sudo.")
    except Exception as e:
        print(f"[ERROR] خطأ أثناء تحليل سجلات الويب: {e}")

def block_ip_timed(ip, duration_seconds):
    """
    يحظر عنوان IP مؤقتًا باستخدام UFW (Uncomplicated Firewall) على Linux.
    يتطلب صلاحيات sudo.
    """
    print(f"[تحذير] محاولة حظر IP {ip} لمدة {duration_seconds // 60} دقيقة باستخدام UFW.")
    print("يتطلب هذا الإجراء صلاحيات sudo. قد يتم مطالبتك بكلمة المرور.")
    
    try:
        # إضافة قاعدة لحظر حركة المرور الواردة من IP
        # نقوم بالإدراج في الموضع 1 للتأكد من معالجتها مبكرًا
        cmd_add = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]
        subprocess.run(cmd_add, check=True, capture_output=True)
        print(f"[OK] تم حظر IP {ip} بنجاح.")
        
        # تشغيل عملية/مؤشر ترابط جديد لإلغاء الحظر بعد التأخير لتجنب حظر تدفق السكربت الرئيسي
        # في سيناريو حقيقي، قد تحتاج إلى مهمة خلفية منفصلة أو وظيفة cron
        # لإلغاء الحظر لجعل هذا أكثر قوة. للتبسيط، سنستخدم time.sleep.
        def unblock_after_delay():
            time.sleep(duration_seconds)
            try:
                cmd_remove = ["sudo", "ufw", "delete", "deny", "from", ip, "to", "any"]
                subprocess.run(cmd_remove, check=True, capture_output=True)
                print(f"[OK] تم إلغاء حظر IP {ip} بعد {duration_seconds // 60} دقيقة.")
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] فشل إلغاء حظر IP {ip}: {e.stderr.decode().strip()}")
            except Exception as e:
                print(f"[ERROR] خطأ أثناء إلغاء حظر IP {ip}: {e}")

        # ملاحظة: هذا سيقوم بحظر المؤشر الترابطي الحالي. إذا كنت تريد سلوكًا غير حظر حقيقي
        # في سياق واجهة المستخدم الرسومية، فستقوم بإنشاء QThread أو ما شابه ذلك.
        # لسكربت مستقل، طبيعة sleep التي تسبب الحظر مقبولة.
        unblock_after_delay() 

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] فشل حظر IP {ip}. الخطأ: {e.stderr.decode().strip()}")
        print("الرجاء التأكد من تثبيت UFW وتمكينه (`sudo ufw enable`) وأن لديك صلاحيات sudo.")
    except Exception as e:
        print(f"[ERROR] خطأ في حظر IP: {e}")

# تشغيل الأداة حسب الوضع
parser = argparse.ArgumentParser(description="أداة تحليل سجلات الأمن السيبراني (إصدار Linux)")
parser.add_argument('--mode', choices=['extract', 'analyze', 'visualize', 'web-analyze'], required=True,
                    help="اختر الوضع: 'extract' (سجلات المصادقة), 'analyze' (تسجيلات الدخول الفاشلة), "
                         "'visualize' (مخططات تسجيل الدخول), 'web-analyze' (سجلات Apache/Nginx).")
args = parser.parse_args()

if __name__ == "__main__":
    # التحقق مما إذا كان يتم التشغيل كـ root للعمليات التي تتطلب ذلك
    if args.mode in ['extract', 'web-analyze'] and os.geteuid() != 0:
        print("[تحذير] تشغيل وضع 'extract' أو 'web-analyze' بدون صلاحيات root قد يؤدي إلى أخطاء رفض الإذن لملفات السجل.")
        print("فكر في التشغيل باستخدام `sudo python3 log_tool.py --mode <mode>` للوصول الكامل.")
    if args.mode == 'web-analyze' and os.geteuid() != 0:
        print("[تحذير] حظر عناوين IP في وضع 'web-analyze' يتطلب صلاحيات root.")
        print("الرجاء التشغيل باستخدام `sudo python3 log_tool.py --mode web-analyze` لتمكين حظر IP.")

    if args.mode == 'extract':
        extract_events()
    elif args.mode == 'analyze':
        analyze_logins()
    elif args.mode == 'visualize':
        visualize_logins()
    elif args.mode == 'web-analyze':
        analyze_web_logs()
