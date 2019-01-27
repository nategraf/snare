#!/bin/bash
set -e

cd "$( dirname "${BASH_SOURCE[0]}" )"

if [ -z "$1" ]; then
    echo "usage: release.sh <tag>" && exit 1
fi

git tag "$1"
git push --tag

python setup.py sdist bdist_wheel
twine upload dist/*
