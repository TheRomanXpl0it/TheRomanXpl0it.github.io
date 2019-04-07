---
layout: page
title: Misc
---

<h2> Articles </h2>

<div class="articles">
  {% for article in site.categories.articles %}
    <h3 class="article-title">
      <a href="{{ article.baseurl }}{{ article.url | remove_first: '/'}}">
        {{ article.title }}
      </a>
    </h3>
    {{ article.description }}<br>
    <span class="post-date">{{ article.date | date_to_string }}</span>
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
