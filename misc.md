---
layout: page
title: Misc
---

<h2> Articles </h2>

<div class="posts">
  {% for post in site.categories.articles %}
    <h3 class="post-title">
      <a href="{{ site.baseurl }}{{ post.url | remove_first: '/'}}">
        {{ post.title }}
      </a>
    </h3>
    <span class="post-date">{{ post.date | date_to_string }}</span>
  {% endfor %}
</div>

<h2> Tools </h2>

<div class="tools">
  {% for tool in site.categories.tools %}
    <h3 class="tool-title">
      <a href="{{ tool.link }}">
        {{ tool.title }}
      </a>
    </h3>
    {{ tool.description }}<br>
    <span class="tool-date">{{ tool.date | date_to_string }}</span>
  {% endfor %}
</div>
