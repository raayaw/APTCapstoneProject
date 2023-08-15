from zapv2 import ZAPv2
import time
import subprocess
from subprocess import Popen


zap_command = "/usr/share/zaproxy/zap.sh -config api.key=test"
subprocess.Popen(['gnome-terminal','-e',zap_command])
print("If a window opens saying 'Do you want to persist the ZAP Session?', please select 'No, I do not want to persist this session at this moment in time' and press start")
input("Press enter to continue once ZAP finishes booting up...")
time.sleep(5)
apikey = 'test'
zap = ZAPv2(apikey=apikey)

target = input('Enter the URL to attack (eg. http://example/.com): ')    
print('Accessing target:', target)
zap.urlopen(target)

# Spider the target URL
print('Spidering target URL...')
zap.spider.scan(target)

# Wait for the spidering to complete
while int(zap.spider.status()) < 100:
    print('Spider progress:', zap.spider.status(), '%')
    time.sleep(2)

# Start the active scan
print('Starting active scan...')
zap.ascan.scan(target)

# Wait for the active scan to complete
while int(zap.ascan.status()) < 100:
    print('Active scan progress:', zap.ascan.status(), '%')
    time.sleep(5)

# Generate the report
report_name = input("What name would you like to save the report as? ")
print('Generating report...')
time.sleep(10)
report_html = zap.core.htmlreport()

# Save the report to a file
with open(report_name + ".html", 'w') as f:
    f.write(report_html)

print("Report saved as {}.html".format(report_name))
time.sleep(5)


