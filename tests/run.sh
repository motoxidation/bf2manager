#!/bin/sh
# needs python3. runs the mock server and checks what bf2am sends
cd "$(dirname "$0")/.." || exit 1
make -s || exit 1
python3 tests/mock_server.py 14711 > /tmp/bf2am_mock.log &
pid=$!
sleep 0.5
timeout 6 ./bf2am 127.0.0.1 14711 hunter2 tests/rules.test > /dev/null
kill $pid
fail=0
for c in "admin.kickPlayer 1" "admin.banPlayer 2 Perm" "game.sayAll" "admin.runNextLevel"; do
  grep -q "$c" /tmp/bf2am_mock.log || { echo "missing: $c"; fail=1; }
done
[ $fail = 0 ] && echo ok
exit $fail
