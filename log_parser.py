# log_parser.py - استخراج السجلات من Windows Event Log

import win32evtlog
import csv

server = 'localhost'
log_type = 'Security'

# فتح السجلات
handle = win32evtlog.OpenEventLog(server, log_type)
events = win32evtlog.ReadEventLog(
    handle,
    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
    0
)

# استخراج السجلات الفاشلة (4625)
with open('failed_logins.csv', 'w', newline='', encoding='utf-8') as failed:
    writer = csv.writer(failed)
    writer.writerow(["TimeGenerated", "EventID", "Source", "Message"])
    for event in events:
        if event.EventID == 4625:
            writer.writerow([event.TimeGenerated, event.EventID, event.SourceName, event.StringInserts])

print("[INFO] Failed login attempts saved to failed_logins.csv")

# إعادة فتح السجل لاستخراج السجلات الناجحة
handle = win32evtlog.OpenEventLog(server, log_type)
events = win32evtlog.ReadEventLog(
    handle,
    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
    0
)

with open('successful_logins.csv', 'w', newline='', encoding='utf-8') as success:
    writer = csv.writer(success)
    writer.writerow(["TimeGenerated", "EventID", "Source", "Message"])
    for event in events:
        if event.EventID == 4624:
            writer.writerow([event.TimeGenerated, event.EventID, event.SourceName, event.StringInserts])

print("[INFO] Successful login attempts saved to successful_logins.csv")
