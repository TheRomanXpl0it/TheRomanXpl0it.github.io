FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    ca-certificates \
    golang-go \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Hugo v0.147.7 extended
RUN wget https://github.com/gohugoio/hugo/releases/download/v0.147.7/hugo_extended_0.147.7_linux-amd64.tar.gz && \
    tar -xzf hugo_extended_0.147.7_linux-amd64.tar.gz && \
    mv hugo /usr/local/bin/ && \
    chmod +x /usr/local/bin/hugo && \
    rm hugo_extended_0.147.7_linux-amd64.tar.gz

# Install Dart Sass
RUN curl -LO https://github.com/sass/dart-sass/releases/download/1.69.5/dart-sass-1.69.5-linux-x64.tar.gz && \
    tar -xzf dart-sass-1.69.5-linux-x64.tar.gz && \
    mv dart-sass /usr/local/dart-sass && \
    ln -s /usr/local/dart-sass/sass /usr/local/bin/sass && \
    rm dart-sass-1.69.5-linux-x64.tar.gz

WORKDIR /src

COPY . .

RUN npm install

RUN hugo mod get -u && \
    hugo mod tidy

