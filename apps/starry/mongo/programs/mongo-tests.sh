#!/bin/sh
# StarryOS on-target mongo runner. Stage 1 (feasibility): the glibc-dynamic mongod
# starts, initializes the WiredTiger storage engine and binds its listener - i.e. the
# real server runs on StarryOS, not just --version. Later stages drive CRUD/aggregate
# through a client. Prints MONGO_TEST_PASSED only when mongod reaches "Waiting for
# connections"; dumps the server log and fails otherwise.
set -u
export LD_LIBRARY_PATH=/lib:/lib64:/usr/lib
echo "=== mongo on $(uname -m) ==="

echo "--- mongod --version ---"
mongod --version 2>&1 | head -3 || { echo "MONGO_TEST_FAILED (version)"; exit 1; }

DB=/tmp/mdb
rm -rf "$DB"; mkdir -p "$DB"
echo "--- start mongod (dbpath=$DB, 127.0.0.1:27017) ---"
mongod --dbpath "$DB" --bind_ip 127.0.0.1 --port 27017 --nounixsocket \
    --wiredTigerCacheSizeGB 0.25 > /tmp/mongod.log 2>&1 &
MPID=$!

ready=0; i=0
while [ "$i" -lt 90 ]; do
    if grep -q 'Waiting for connections' /tmp/mongod.log 2>/dev/null; then ready=1; break; fi
    kill -0 "$MPID" 2>/dev/null || { echo "mongod exited early"; break; }
    i=$((i + 1)); sleep 1
done

echo "=== mongod.log (tail 25) ==="
tail -25 /tmp/mongod.log 2>/dev/null

kill "$MPID" 2>/dev/null
if [ "$ready" -eq 1 ]; then
    echo "mongod reached: Waiting for connections"
    echo "MONGO_TEST_PASSED"
    exit 0
fi
echo "MONGO_TEST_FAILED (mongod did not become ready)"
exit 1
