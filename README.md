# [theromanxpl0.it](https://theromanxpl0.it/)

## Adding a member

To add yourself to the members page, you can run the helper script:

```bash
./tools/add-member.sh NAME
```

Otherwise you can do it manually like so:

```bash
hugo new members/NAME.md
vim content/members/NAME.md
```

> [!TIP]
> Using the hugo new command listed above will create the template automatically

The content of the members page are as follows:

* `title`: Your username
* `name`: Your full name (optional)
* `join_year`: Year of join (required)
* `join_month`: Month of join (optional)
* `roles`: A list of roles (please don't add custom roles :pray:)
* `avatar`: Path of your avatar image (relative to `/static`). Please add the image as `/static/avatars/X` and put the avatar value as `"/avatars/X"`

Values supported in the `social` table are:
* `mail`
* `github`
* `linkedin`
* `website`

## Writing a post

You can create an empty blog post with header by using hugo:

```bash
hugo new posts/myctf25-chall1/index.md
```

> [!TIP]
> If you need mathjax, you can add `math: true` to the frontmatter.

## Development setup

### Installation

Clone with submodules:
```bash
git clone --recurse-submodules git@github.com:TheRomanXpl0it/TheRomanXpl0it.github.io.git
```

Install hugo modules:
```bash
hugo mod get
hugo mod tidy
```

Install npm packages:
```bash
npm install
```

> [!IMPORTANT]
> To build properly the scss you should install [Dart Sass](https://gohugo.io/functions/css/sass/#dart-sass).

### Run

Then you can run the website with:
```bash
hugo server

```

### With Docker

Build the image and serve:

```bash
docker build -t hugo-dev .

# if you want to quickly serve the current site
docker run -p 1313:1313 --rm hugo-dev:latest hugo serve --bind 0.0.0.0

# if you want to make it better <3
docker run -p 1313:1313 --rm -it -v `pwd`:/code hugo-dev:latest bash

# inside the container you'll have
# /src -> original code
# /code -> the current code in a volume
cd /code
hugo serve --bind 0.0.0.0
```
