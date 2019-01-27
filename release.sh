#!/bin/bash
set -e

cd "$( dirname "${BASH_SOURCE[0]}" )"

if [ -n "$1" ]; then
    git tag "$1"
    git push --tag
fi

python setup.py sdist bdist_wheel
twine upload dist/*
