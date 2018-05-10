---
layout: home
---

<h2>$ cat About</h2>
{:id="about"}

CTF Team composed of students of Sapienza, University of Rome and alumni of CyberChallengeIT.

We are just born, stay tuned and look how we become big.

Contact us at <a href="mailto:theromanxpl0it@gmail.com">theromanxpl0it@gmail.com</a>

Follow us on [Twitter](https://twitter.com/TheRomanXpl0it)

Join our [Telegram group](https://t.me/TheRomanChat)

<h2>$ ls -l CTFs</h2>
{:id="ctfs"}

<div class="table-responsive">
    <table class="table table-hover table-dark">
        <thead>
            <tr>
                <th>CTF</th>
                <th>Place</th>
            </tr>
        </thead>
        <tbody>
            {% for ctf in site.categories.ctfs %}
            <tr onclick="window.location='{{ ctf.url }}';">
                <td>{{ ctf.title }}</td>
                <td>{{ ctf.place }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<h2>$ cat Team</h2>
{:id="team"}

<ul class="list-group">
    {% for member in site.categories.team reversed %}
    <a class="list-group-item" href="{{ member.url }}">
        {{ member.title }}
    </a>
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
