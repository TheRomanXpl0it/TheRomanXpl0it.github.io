---
title: 3DS CTF 2017 - String Obfuscator
date: '2017-12-21'
lastmod: '2023-07-03T19:19:24+02:00'
categories:
- writeup
- 3ds2017
tags:
- misc
- reverse
- excel
authors:
- dp1
---

The input file had no extension, so the first thing to do was figure out how to read it. I opened it in n++ and saw it began with the zip header, so it got decompressed. On the inside, the files were actually the structure of an `.xlsm` file, so rather than working on the directory I changed the extension of the input and opened it in excel. I had to enable macros for the challenge to work properly, and this is what I saw at first:

<img class="img-responsive" src="/3dsctf2017/excel.png" alt="Screenshot of Microsoft Excel window showing obfuscated formula" width="603" height="234.433">

By clicking on the icon in the top left, a dialog would pop up and ask for a string to be encrypted:

<img class="img-responsive" src="/3dsctf2017/dialog.png" alt="Screenshot of dialog box showing input field and 'Encrypt' button in Microsoft Excel" width="603" height="235.017">

It was at this point that I figured out that the string in the bottom was the output of that encryption algorithm and that I had to find and reverse it. As I enabled macros before, I went to the visual basic editor (that's `Alt+F11`), but was prompted for a password. After trying the obvious passwords with no success, I was stuck for a while. Paraphrasing my teammate, [for a l33t h4xor it's easy, for me it means Google](/ctf_backdoorctf17/funsignals/)

As it turns out, excel passwords are implemented horribly, so by just following a couple steps from [here](http://www.dragmar.com/public/?p=140) I was able to bypass it. I'll list them here for clarity:
1. Change the string 'DPB' to 'DPx' inside the file
2. Close and reopen the file (duh!)
3. Open the vbasic window, tell it it's fine that the password is broken, set a new password

Yup, done already. _VBA passwords are that easy to bypass_.

One note, though: When I tried to modify the string in file `xl/vbaProject.bin` inside the unzipped folder and compress it back, Excel wouldn't accept it. The only thing to work for me was to add the modified file to the original zip, so that compression options would be kept.

So I could finally get my hands on the obfuscation algorithm. There were a couple hundred lines of visual basic, of which only a few were actually important, while the others were conversion algorithms between base64/text/bytes.

```python
Private Sub OK_Click()
    If TextBox1.Value = "" Then: Exit Sub
    Dim x, l, a, test1, test As String
    Dim tam As Integer
    x = TextBox1.Value
    tam = Len(x)
    While tam > 0: a = a & (Asc(Mid(x, 1, 1))): tam = tam - 1: x = Right(x, tam): Wend
    ' a is now the concatenation of the ascii values in the string. Ex: "abcd" -> 979899100
    tam = Len(a)
    While a <> "":
        test1 = Mid(a, 1, 1):
        ' test1 contains the current digit in a
        test = test & (Mid(a, 1, 1) + tam):
        ' test contains each digit in a + len(a). Ex: a = 123, test = 456
        l = l & Chr(Mid(a, 1, 1) + tam):
        ' l is the same as test but with each digit interpreted as ascii
        a = Right(a, Len(a) - 1):
    Wend
    MsgBox Base64EncodeString(l), vbOKOnly, "Obfuscation Successfully": Unload Me
End Sub
```

It's ugly, I know. But I still went and wrote an inverse algorithm in python, which was used to get the flag:

```python
def decrypt(target):
	d = base64.b64decode(target)
	e = ''.join(str((ord(ch) - len(d)) % 256) for ch in d)

	i = 0
	out = ''
	while i < len(e):
		if i < len(e) - 2 and e[i] == '1':
			out += chr(int(e[i:i+3]))
			i += 3
		elif i < len(e) - 1:
			out += chr(int(e[i:i+2]))
			i += 2
		else:
			i += 1
	return out
```

At this point I thought I had it, but it took me a while to actually get to the flag. I couldn't get copy paste to work from excel for some reason, so at first I was manually copying the string over and I couldn't see there were some missing characters that overflowed the textbox. Excel has another layer of protection that can be applied on the whole document, which I had to remove by going to `Revision->Remove sheet protection`. Only now could I get copy paste to work and obtain the full encrypted string:
```
XVleYGBbWVpbXl9cYF9gX1lgWl1aXV1gXV9eXVpdXVxhXGBfYF1bYV1gYVxgYF1hXV9dX2BcYGBfYV1dXV9aXVlhXWBfXGBgWl9dXVtfWl1ZXVldXVlaXQ==
```

By running it through the decryption routine, I got the flag: `3DS{C0NGR47UL4710N5_Y0U_KN0W_7H3_W0RK5H337}`.

Finally!
