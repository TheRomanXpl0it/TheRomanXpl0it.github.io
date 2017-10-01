---
layout: home
---

<h2>$ cat About</h2>
{:id="about"}

CTF Team composed of students of Sapienza, University of Rome and alumns of CyberChallengeIT.

We are just born, stay tuned and look how we become big.

Contact us: <a href="mailto:theromanxpl0it@gmail.com">theromanxpl0it@gmail.com</a>

<h2>$ ls CTFs</h2>
{:id="ctfs"}

<div class="list-group">
    {% for ctf in site.categories.ctfs %}
    <a class="list-group-item" href="{{ ctf.url }}">
        {{ ctf.title }}
    </a>
    {% endfor %}
</div>

<!--#$ cat Contact
{:id="contact"}

You can contact out team at the official mail blablabla@pippo.com.-->

<h2>$ cat Team</h2>
{:id="team"}

<ul class="list-group">
    {% for member in site.categories.team reversed %}
    <li class="list-group-item" id="{{ member.title }}">{{ member.title }}
        <ul class="list-unstyled">
            <li>
                {{ member.mail }}
            </li>
            <li>
                <a href="https://github.com/{{ member.github }}">https://github.com/{{ member.github }}</a>
            </li>
            {% if member.site %}
            <li>
                <a href="{{ member.site }}">{{ member.site }}</a>
            </li>
            {% endif %}
        </ul>
    </li>
    {% endfor %}
</ul>

<h2>$ ls Articles</h2>
{:id="articles"}

<div class="list-group">
    {% for article in site.categories.articles %}
    <a href="{{ article.url }}" class="list-group-item" title="{{ article.description }}">
        {{ article.title }}
    </a>
    {% endfor %}
</div>

<h2>$ ls Tools</h2>
{:id="tools"}

<div class="list-group">
    {% for tool in site.categories.tools %}
    <a class="list-group-item" href="{{ tool.link }}">
        {{ tool.title }} - {{ tool.description }}
    </a>
    {% endfor %}
</div>
