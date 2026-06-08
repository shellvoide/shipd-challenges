#!/bin/sh
set -eu

su -s /bin/sh hss -c 'cd /app && node server.js' &

while :; do
  sleep 3600
done
