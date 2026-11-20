#!/bin/sh
# Start again from zero (new CA, new users, new keys). Handy before the demo.
docker compose down -v
rm -rf ca_data/* trust/* sender_keys/* sender_data/* receiver_keys/* receiver_data/* attacker_keys/*
for d in ca_data trust sender_keys sender_data receiver_keys receiver_data attacker_keys; do touch $d/.gitkeep; done
echo "Clean. Now run: docker compose up -d --build ca receiver"
