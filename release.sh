#!/bin/bash
set -e

cd "$( dirname "${BASH_SOURCE[0]}" )"

# If provided a tag, tag the current commit.
if [ -n "$1" ]; then
    TAG="$1"
    git tag "$1"
    git push --tag
else
    TAG="$(git tag -l --contains HEAD)"
fi

# If this commit is untagged, upload to our dev repo.
if [ -z "$TAG" ]; then
    TAG="0.0.dev0"
    REPO="-r dev"
fi

# Package and upload the current source.
python setup.py sdist bdist_wheel
twine upload --skip-existing $REPO dist/*$TAG*
