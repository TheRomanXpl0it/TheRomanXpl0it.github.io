---
# file creation date (not relevant)
date: {{ .Date }}

# username (required)
title: '{{ replace .File.ContentBaseName "-" " " }}'

# real name (optional)
name: "{{ .Name }}"

# join year (required)
join_year: 2024

# join month number (optional)
join_month: # 1

# you can add multiple, but please no custom ones
# please don't use more than 2 roles
roles:
  # - reverse
  # - crypto
  # - forensics
  # - misc
  # - pwn
  # - web
  # - fullpwn
  # - hardware
  # - infra
  # - OG
  # - former

# put the avatar in /static/avatars/
avatar: # "/avatars/{{ urlize .Name }}.jpg"

# optional social links
social:
  mail: ""
  github: ""
  linkedin: ""
  website: ""
---
