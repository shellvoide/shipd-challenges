#!/bin/sh
set -eu

install -d -o hss -g hss -m 0700 /run/hss
node -e "console.log('HSS-'+require('crypto').randomBytes(18).toString('hex').toUpperCase())" > /run/hss/value
chown hss:hss /run/hss/value
chmod 0400 /run/hss/value

su -s /bin/sh hss -c 'cd /app && HSS_VALUE_PATH=/run/hss/value node server.js' &

while :; do
  sleep 3600
done
