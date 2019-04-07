---
layout: page
title: Writeups
---

<div class="ctfs">
  {% for ctf in site.categories.ctfs %}
  <div class="ctf">
      <h2 class="ctf-title">
        {{ ctf.title }}
      </h2>
      {{ ctf.content }}
  </div>
  {% endfor %}
</div>
