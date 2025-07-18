---
title: Transient Execution Attacks explained to your Grandma
date: '2019-02-22'
lastmod: '2019-04-07T14:29:47+02:00'
categories:
- articles
tags:
- microarch
authors:
- pietroborrello
---

What? Reading kernel memory from user space? What?

I explained, at the 5th meeting of DC11396, how modern processor optimizations such as branch prediction and out-of-order execution may lead to leak of secrets through the CPU’s microarchitectural state. 
Numerous attacks have been proposed, this is an overview of the state of the art of these techniques:

<style>
    .responsive-wrap iframe { max-width: 100%;}
</style>
<div class="responsive-wrap">
    <iframe src="https://docs.google.com/presentation/d/1DylZk40ixblYL1y1xq4rmz1qu_wn1TpRAeiBo3D9DbQ/embed?start=false&loop=false&delayms=3000" frameborder="0" width="960" height="569" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>
</div>
