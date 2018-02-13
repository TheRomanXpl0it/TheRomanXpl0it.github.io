---
layout: simple
title: nullcom HackIM 2018
categories: ctfs
keywords: "ctf"
place: 70th
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
            <td>700</td>
        </tr>
    </tbody>
</table>

## Writeups
{:id="writeups"}

<div class="list-group">
    {% for writeup in site.categories.ctf_nullcomhackim18 %}
    <a class="list-group-item" href="{{ writeup.url }}" title="{{ writeup.description }}">
        {{ writeup.title }}
    </a>
    {% endfor %}
</div>

View on [CTFTime](https://ctftime.org/event/566)
