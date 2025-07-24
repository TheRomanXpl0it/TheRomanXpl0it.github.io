# [theromanxpl0.it](https://theromanxpl0.it/)

## Add member

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
* `joined`: Approximate date of join (year/month is enough)
* `roles`: A list of roles (please don't add custom roles :pray:)
* `avatar`: Path of your avatar image (relative to `/static`). Please add the image as `/static/avatars/X` and put the avatar value as `"/avatars/X"`

Values supported in the `social` table are:
* `mail`
* `github`
* `linkedin`
* `website`

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
