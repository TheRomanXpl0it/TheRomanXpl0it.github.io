---
layout: simple
title: Insomni'hack Teaser 2018
categories: ctfs
keywords: "ctf"
place: 61st
---
{{ page.date | date: "%B %-d, %Y" }}


<table class="table">
    <thead>
        <tr>
            <th>Position</th>
            <th>Score</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>{{ page.place }}</td>
            <td>257</td>
        </tr>
    </tbody>
</table>

## Writeups
{:id="writeups"}

<div class="list-group">
    {% for writeup in site.categories.ctf_insomnihackteaser2018 %}
    <a class="list-group-item" href="{{ writeup.url }}" title="{{ writeup.description }}">
        {{ writeup.title }}
    </a>
    {% endfor %}
</div>

View on [CTFTime](https://ctftime.org/event/545)
