#!/bin/bash
set -e

cd "$( dirname "${BASH_SOURCE[0]}" )"

# If provided a tag, tag the current commit.
if [ -n "$1" ]; then
    git tag "$1"
    git push --tag
fi

if [ -z "$(git tag -l --contains HEAD)" ]; then
    devpi upload --formats sdist,bdist_wheel
else
    python setup.py sdist bdist_wheel
    twine upload --skip-existing $REPO dist/*
fi
