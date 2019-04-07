---
layout: page
title: About
---

We are the TRX team.

Mainly students of Sapienza, University of Rome and alumni of <a href="https://cyberchallenge.it">CyberChallengeIT</a>.

We often play Capture the Flags, we often fuzz stuffs and we often teach other people about this art.

Many of us play top CTFs (like CCC CTF and DEF CON CTF) with the <a href="https://twitter.com/mhackeroni">mhackeroni</a> italian joint team.

Many of us are involved in the organization of the local DEF CON Group, <a href="https://defcon11396.it">DC11396</a>, with the mission of spreading security awareness, hacking skills and (hopefully) our passion in the local community that we are contributing to build.

Some of us actively teach crypto and binary exploitation at the newbies of CyberChallenge Rome.

Contact us at <a href="mailto:theromanxpl0it@gmail.com">theromanxpl0it@gmail.com</a>

Follow us on [Twitter](https://twitter.com/TheRomanXpl0it)

Join our [Telegram group](https://t.me/TheRomanChat)

<h2>Members</h2>

<div class="members">
    {% for member in site.categories.team reversed %}
    <a href="{{ member.url }}">
        {{ member.title }} {% if member.nick %}({{ member.nick }}){% endif %}<br>
    </a>
    {% endfor %}
</div>

<h2>Formers</h2>

<div class="members">
    {% for member in site.categories.former reversed %}
    <a href="{{ member.url }}">
        {{ member.title }} {% if member.nick %}({{ member.nick }}){% endif %}<br>
    </a>
    {% endfor %}
</div>

