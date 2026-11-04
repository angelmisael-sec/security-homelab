#!/bin/bash
# Week 10: unauthenticated Greenbone (OpenVAS) scan of DC01 + WS01, run on LNX01.
# Creates the target and task once, starts a new run each time it is called (run 1 = before fixes,
# run 2 = after), waits, and saves the report as XML plus a short severity summary in ~/scans/.
# Needs ~/bin/gmp (gvm-cli wrapper) and the Greenbone community containers from ~/greenbone.
set -euo pipefail
GMP=~/bin/gmp
NAME='LAB - DC01 + WS01'
FULL_AND_FAST=daba56c8-73ec-11df-a475-002264764cea
ALL_IANA_TCP=33d0cd82-57c6-11e1-8ed1-406186ea4fc5
OPENVAS=08b69003-5fc2-4037-a479-93b440211c73
mkdir -p ~/scans

id_of() { { grep -oP "<$1 id=\"\K[^\"]+" || true; } | head -1; }   # empty, not an error, when absent

# Target: WS01 drops ping, so treat hosts as alive instead of skipping them
target=$($GMP "<get_targets filter='name=\"$NAME\"'/>" | id_of target)
if [ -z "$target" ]; then
  target=$($GMP "<create_target><name>$NAME</name><hosts>10.10.0.10,10.10.0.30</hosts>
    <port_list id=\"$ALL_IANA_TCP\"/><alive_tests>Consider Alive</alive_tests></create_target>" | grep -oP 'id="\K[^"]+')
fi
task=$($GMP "<get_tasks filter='name=\"$NAME\"'/>" | id_of task)
if [ -z "$task" ]; then
  task=$($GMP "<create_task><name>$NAME</name><config id=\"$FULL_AND_FAST\"/><target id=\"$target\"/>
    <scanner id=\"$OPENVAS\"/></create_task>" | grep -oP 'id="\K[^"]+')
fi
report=$($GMP "<start_task task_id=\"$task\"/>" | grep -oP '<report_id>\K[^<]+')
echo "target $target  task $task  report $report"

while true; do
  st=$($GMP "<get_tasks task_id=\"$task\"/>" | grep -oP '<status>\K[^<]+' | head -1)
  pr=$($GMP "<get_tasks task_id=\"$task\"/>" | grep -oP '<progress>\K-?[0-9]+' | head -1)
  echo "$(date +%T) $st $pr%"
  case "$st" in Done) break ;; Stopped|Interrupted) echo "scan ended: $st"; exit 1 ;; esac
  sleep 120
done

run=$(( $(ls ~/scans/s10-greenbone-run*.xml 2>/dev/null | wc -l) + 1 ))   # shortcut: numbered by files on disk, not by Greenbone
out=~/scans/s10-greenbone-run$run
$GMP "<get_reports report_id=\"$report\" details=\"1\" ignore_pagination=\"1\" filter=\"levels=hml rows=-1 min_qod=70\"/>" > "$out.xml"
# One line per finding: severity, host, port, name (QoD >= 70 is Greenbone's default trust threshold)
tr -d '\n' < "$out.xml" | grep -oP '<result id=.*?</result>' | while read -r r; do
  printf '%s\t%s\t%s\t%s\n' \
    "$(grep -oP '<severity>\K[0-9.]+' <<<"$r" | tail -1)" "$(grep -oP '<host>\K[0-9.]+' <<<"$r" | head -1)" \
    "$(grep -oP '<port>\K[^<]+' <<<"$r" | head -1)" "$(grep -oP '<name>\K[^<]+' <<<"$r" | head -1)"
done | sort -t$'\t' -k1,1nr > "$out.tsv"
echo "saved $out.xml and $out.tsv ($(wc -l < "$out.tsv") findings)"
cat "$out.tsv"
