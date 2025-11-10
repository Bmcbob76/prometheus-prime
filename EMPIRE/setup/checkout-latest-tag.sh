#!/bin/bash
# Get git tags matching semver
# remove the -beta -alpha -rc suffixes with grep
tags=$(git tag --list --sort=-version:refname "v*.*.*")

# If prerelease arg is not passed, filter out prerelease tags
if [ "$1" != "pre" ] && [ "$2" != "pre" ]; then
  tags=$(echo "$tags" | grep -v -E "beta|alpha|rc|RC")
fi

# If sponsors arg is passed, only show tags with sponsors
if [[ "$1" == "sponsor"* ]] || [[ "$2" == "sponsor"* ]]; then
  tags=$(echo "$tags" | grep -E "sponsors")
fi

# If kali arg is passed, only show tags with kali
if [ "$1" == "kali" ] || [ "$2" == "kali" ]; then
  tags=$(echo "$tags" | grep -E "kali")
fi

# get latest tag
latest_tag=$(echo "$tags" | head -n 1)

echo "Checkout out latest tag: $latest_tag"
git checkout "$latest_tag"
