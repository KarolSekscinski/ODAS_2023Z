import re
REGEX = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
files = ['auth.log.4', 'auth.log.3', 'auth.log.2', 'auth.log.1', 'auth.log']

ips = []
for file in files:
    with open(f"auth/var/log/{file}") as f:
        lines = f.readlines()
        for line in lines:
            if "Failed password for root" in line:
                ip = re.search(REGEX, line).group()
                if ip not in ips:
                    ips.append(ip)

with open("ips.txt", "a") as f:
    for ip in ips:
        f.write(f"{ip}\n")

