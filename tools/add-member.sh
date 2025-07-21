#!/bin/sh

if [ -z "$1" ];
then
	echo "Usage: $0 NAME"
	exit 1
fi

hugo new members/$1.md

$EDITOR content/members/$1.md
