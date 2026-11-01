#!/bin/bash
# Interop with katzenqt over a client daemon: katzenqt1 and katzenqt-headless join one group and
# read each other. As host, katzenqt1 founds the group and inducts katzenqt; as guest, katzenqt
# founds it and inducts katzenqt1.
#
#   scripts/interop-katzenqt.sh host|guest [DAEMON] [KATZENQT]
set -euo pipefail
role=${1:?host or guest}
daemon=${2:-@katzenpost}
katzenqt=${3:-$HOME/katzenqt}
here=$(cd "$(dirname "$0")/.." && pwd)
kq="$katzenqt/.venv/bin/katzenqt-headless"
case $daemon in
  @*|/*) conn=(--address "$daemon" --network unix) ;;
  *) conn=(--address "$daemon" --network tcp) ;;
esac
work=${WORK:-$HOME/scratch/interop-$role-$$}
mkdir -p "$work"
export XDG_DATA_HOME="$work/xdg" KQT_STATE=interop
(cd "$here/go" && go build -o "$work/katzenqt1" ./cmd/katzenqt1)
mkfifo "$work/in"
"$work/katzenqt1" -daemon "$daemon" -state "$work/go" -name gopher -log "$work/go.log" < "$work/in" > "$work/go.out" &
go=$!
trap 'kill $go 2>/dev/null || true' EXIT
exec 3> "$work/in"
wait_for() {
  until grep -q "$1" "$work/go.out"; do
    kill -0 $go 2>/dev/null || { cat "$work/go.out"; exit 1; }
    sleep 2
  done
}
step() { echo "== $(date +%T) $*"; }
wait_for READY
if [ "$role" = host ]; then
  "$kq" create-conv g katzenqt "${conn[@]}" 2> "$work/create.log"
  echo "create g" >&3
  wait_for "JOINED g"
  step "katzenqt mints a voucher"
  code=$("$kq" voucher-mint g katzenqt "${conn[@]}" 2>&1 | sed -n 's/.*VOUCHER=//p' | tail -1)
  test -n "$code"
  step "katzenqt1 inducts katzenqt"
  echo "invite g $code" >&3
  "$kq" voucher-await g "${conn[@]}"
else
  "$kq" create-conv g katzenqt "${conn[@]}" 2> "$work/create.log"
  echo "join g" >&3
  wait_for "VOUCHER="
  code=$(sed -n 's/^VOUCHER=//p' "$work/go.out" | tail -1)
  step "katzenqt inducts katzenqt1"
  "$kq" voucher-induct g gopher "$code" "${conn[@]}"
  wait_for "JOINED g"
fi
step "each sends"
"$kq" send g "from katzenqt" "${conn[@]}"
echo "send g from katzenqt1" >&3
step "katzenqt reads katzenqt1"
"$kq" read g 1800 "from katzenqt1" "${conn[@]}"
step "katzenqt1 reads katzenqt"
wait_for "LINE g .*: from katzenqt$"
# katzenqt reads on past its own Introduction, so that what it sends says where it was
# introduced, and katzenqt1 can tell whom its acknowledgements name.
step "katzenqt1 sends again, and katzenqt reads up to it"
echo "send g once more" >&3
"$kq" read g 1800 "once more" "${conn[@]}"
step "katzenqt acknowledges, and katzenqt1 sees it"
"$kq" send g "katzenqt read you" "${conn[@]}"
wait_for "LINE g .*: katzenqt read you"
for i in $(seq 1 180); do
  echo "show g" >&3
  sleep 10
  grep -q "me ✓✓: from katzenqt1" "$work/go.out" && break
done
grep -q "me ✓✓: from katzenqt1" "$work/go.out" || { echo "FAIL: no acknowledgement"; exit 1; }
step "ok: katzenqt1 and katzenqt read and acknowledge each other"
