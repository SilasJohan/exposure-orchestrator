#!/bin/sh
# Build the docroot at startup. The static files are mounted read-only at
# /seed-docroot; we copy them into the writable nginx root and then materialize
# the exposed fake-secret files. They are created here (not committed under
# their live names) so the repo never stores a file named .env or .git/config,
# which secret scanners and .gitignore would choke on.
set -e

root=/usr/share/nginx/html
rm -rf "$root"
mkdir -p "$root/.git" "$root/files"

cp -r /seed-docroot/. "$root/"

cp /seed/git-config.sample  "$root/.git/config"
cp /seed/dotenv.sample      "$root/.env"
cp /seed/backup.sample      "$root/backup.sql.bak"
cp /seed/config.json.sample "$root/config.json"
cp /seed/htpasswd.sample    "$root/.htpasswd"

echo "lab file-listing demo — nothing sensitive here" > "$root/files/readme.txt"

exec nginx -g 'daemon off;'
