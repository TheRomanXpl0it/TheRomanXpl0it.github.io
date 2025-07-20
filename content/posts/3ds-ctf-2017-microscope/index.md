---
title: 3DS CTF 2017 - Microscope
date: '2017-12-20'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- 3ds2017
tags:
- misc
- steganography
- gif
- qr
authors:
- dp1
---

The input gif had 108900 frames, all either yellow or green. By mapping each one to a single white or black pixel of an image, we can get to a qr code.
The tricky part here was that the frame data was identical for each one of them, while the thing to change was the first entry in the color palette, effectively modifying the color without touching the actual pixel data.

```python
#!/usr/bin/python2

import os
from PIL import Image

def extractFrames(inGif, outFolder):
	outdata = []
	frame = Image.open(inGif)
	nframes = 0
	while frame:
		if frame.getpalette()[0] < 128:
			outdata += [(0,0,0)]
		else:
			outdata += [(255,255,255)]

		nframes += 1
		try:
			frame.seek(nframes)
		except EOFError:
			break
	return outdata


if __name__ == "__main__":
	c = extractFrames('gif.gif', 'output')
	img = Image.new('RGB', (330, 330))
	img.putdata(c)
	img.save('qr.png', 'PNG')

```

The output of this script is the following image, which when read reveals the flag:

<img class="img-responsive" src="/3dsctf2017/qr.png" alt="QR code image containing flag for 3DS Capture the Flag 2017 'Microscope' challenge" width="330" height="330">

```bash
3DS{s0_y0u_kn0w_yur_g1fs}
```
