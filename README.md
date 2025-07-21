# trxdotit

## Get

Clone with submodules

```bash
git clone --recurse-submodules https://github.com/TheRomanXpl0it/trxdotit.git
```

Install hugo modules

```bash
hugo mod get
hugo mod tidy
```

## Run

To build the hugo website do
```bash
hugo build
```

To try out the website while developing do
```bash
hugo server
```

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
