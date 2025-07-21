---
title: Dump and analysis of exec only binary in Linux
date: '2017-09-23'
lastmod: '2019-04-07T13:46:27+02:00'
categories:
- articles
tags:
- ECSC
authors:
- malweisse
---

<style>
    .responsive-wrap iframe { max-width: 100%;}
</style>
<div class="responsive-wrap">
    <iframe src="https://docs.google.com/presentation/d/e/2PACX-1vRZu0TswsXPQqjXJc-p2kPs0BKF9-t-GIi0nQGoWdsELq_CzVX-mtj93f8B5M3FwYNR3948srQmBn8O/embed?start=false&loop=false&delayms=3000" frameborder="0" width="960" height="569" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>
</div>

```cpp
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h> //basename

#include <iostream>
#include <string>
#include <fstream>
#include <vector>

using namespace std;

#define BINNAME "noread"


extern "C" int fake_main(int argc, char** argv, char** envp) {

    fstream maps("/proc/self/maps", fstream::in);
    string addrs;
    string nocare;
    string name;

    unsigned long last = (unsigned long)-1;
    vector<string> dumps;
    vector<string> starts;
    vector<string> ends;

    while(maps.good()) {
        maps >> addrs;
        maps >> nocare;
        maps >> nocare;
        maps >> nocare;
        maps >> nocare;
        getline(maps, name);

        if(string(basename((char*)name.c_str())) != BINNAME)
            continue;

        size_t minus = addrs.find("-");
        string start_str = addrs.substr(0, minus);
        string end_str = addrs.substr(minus +1, addrs.size() - minus -1);
        unsigned long start = stol(start_str, 0, 16);
        unsigned long end = stol(end_str, 0, 16);

        if(last == start) {
            dumps.back() += string((char*)start, end - start);
            ends.back() = end_str;
        }
        else {
            dumps.push_back(string((char*)start, end - start));
            starts.push_back(start_str);
            ends.push_back(end_str);
        }
        last = end;
    }

    maps.close();

    for(size_t i = 0; i < dumps.size(); ++i) {
        string outname = BINNAME "-dump-" + starts[i] + "-" + ends[i] + ".bin";
        fstream out(outname, fstream::binary | fstream::out);
        out << dumps[i];
        out.close();

        cout << "dumped: [" << starts[i] << ", " << ends[i] << "]" << endl;
    }

    return 0;
}

//use LD_BIND_NOW LD_PRELOAD

extern "C" int __libc_start_main (int (*main)(int, char**, char**), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {

    auto functor = (int (*)(int (*) (int, char**, char**), int, char**, void (*) (void), void (*) (void), void (*) (void), void (*)))dlsym(RTLD_NEXT, "__libc_start_main");

    return functor(&fake_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

```
