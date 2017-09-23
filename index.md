---
layout: default
---
# Home

## $ cat About
{:id="about"}

CTF Team composed by students of Sapienza University of Rome and alumns of CyberChallenge.IT.

We are just born, stay tuned and look how we become big.

## $ ls CTFs
{:id="ctfs"}

<ul>
{% for ctf in site.categories.ctfs %}
<li><a href="{{ ctf.url }}">{{ ctf.title }}</a></li>
{% endfor %}
</ul>

<!--# $ cat Contact
{:id="contact"}

You can contact out team at the official mail blablabla@pippo.com.-->

## $ cat Team
{:id="team"}

<ul>
{% for member in site.categories.team reversed %}
<li id="{{ member.title }}">{{ member.title }}
<ul>
<li>{{ member.mail }}</li>
<li><a href="https://github.com/{{ member.github }}">https://github.com/{{ member.github }}</a></li>
{% if member.site %}
<li><a href="{{ member.site }}">{{ member.site }}</a></li>
{% endif %}
</ul>
</li>
{% endfor %}
</ul>

## $ ls Articles
{:id="articles"}

<ul>
{% for article in site.categories.articles %}
<li><a href="{{ article.url }}" title="{{ article.description }}">{{ article.title }}</a></li>
{% endfor %}
</ul>

## $ ls Tools
{:id="tools"}

<ul>
{% for tool in site.categories.tools %}
<li><a href="{{ tool.link }}">{{ tool.title }}</a> - {{ tool.description }}</li>
{% endfor %}
</ul>
