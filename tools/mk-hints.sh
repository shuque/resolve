#!/bin/sh
#
# Script to generate contents of hints.py module file, containing current
# root server names and addresses.
#

ROOTHINTS_URL="https://www.internic.net/domain/named.root"

cat <<EOF
"""
Root server names and addresses.
"""

ROOT_NS_TTL = 518400

ROOTHINTS = [
EOF

curl -s $ROOTHINTS_URL | \
    egrep -v ^\; | awk '$3 != "NS" {print tolower($1), $4}' | \
    while read name ip;
    do
	echo "    (\"$name\", \"$ip\"),"
    done

echo "]"

