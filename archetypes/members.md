---
date: {{ .Date }}

# username
title: '{{ replace .File.ContentBaseName "-" " " }}'
# real name
name: "{{ .Name }}"
# join date (year & month)
joined: {{ .Date }} # change this

roles:
  - pwn
  # - web
  # - reverse
  # - crypto
  # - misc
  # - forensics
  # - hardware
  # - OG

# put the avatar in /static/avatars/
avatar: # "/avatars/{{ urlize .Name }}.jpg"
social:
  mail: ""
  github: ""
  linkedin: ""
  website: ""
---
