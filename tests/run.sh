#!/bin/sh
# needs python3. runs the mock server and checks what bf2am sends/writes
cd "$(dirname "$0")/.." || exit 1
make -s || exit 1
t=$(mktemp -d)
cat > $t/state.txt <<S
P 0 1 1 20 -30 50 pilot
P 1 1 0 10 10 20 bob
P 2 1 0 10 10 5 carl
P 3 1 0 10 10 80 dave
P 4 2 0 10 10 7 erin
S
cp tests/rules.test $t/rules
printf 'state %s/state.txt\nactions %s/actions.txt\nbalance 2 30\nnfz 0 0 100\n' $t $t >> $t/rules
python3 tests/mock_server.py 14711 > $t/mock.log &
pid=$!
sleep 0.5
timeout 6 ./bf2am 127.0.0.1 14711 hunter2 $t/rules > /dev/null
kill $pid
fail=0
for c in "admin.kickPlayer 1" "admin.banPlayer 2 Perm" "game.sayAll" "admin.runNextLevel"; do
  grep -q "$c" $t/mock.log || { echo "missing cmd: $c"; fail=1; }
done
for a in "swap 2" "kill 0"; do
  grep -q "$a" $t/actions.txt || { echo "missing action: $a"; fail=1; }
done
rm -rf $t
[ $fail = 0 ] && echo ok
exit $fail
