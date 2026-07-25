#!/usr/bin/env bash
# Protocol-coverage matrix driver. Root/WSL2. Reuses lib.sh netns plumbing.
#   sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf|iproute] [--only NAME]
set -u
PROTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROTO_DIR/../lib.sh"
export PYTHONPATH="$PROTO_DIR"

MODE=ebpf; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    *) red "unknown arg: $1"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { red "must run as root (sudo)"; exit 1; }
[ -x "$BIN" ] || { red "release binary not found: $BIN (cargo build -p mymitm --release)"; exit 1; }

WORK="$(mktemp -d /tmp/mymitm-matrix.XXXXXX)"          # transient scratch
RUN_DIR="$(report_run_dir matrix "$MODE")"             # persistent, organized report folder
CERT="$WORK/leaf.pem"; KEY="$WORK/leaf.key"; TOML="$WORK/mymitm.toml"
RESULTS="$WORK/results.tsv"; : > "$RESULTS"
ART="$RUN_DIR/dumps"                                   # per-case dumps land straight in the report folder
info "scratch:       $WORK   mode: $MODE"
info "report folder: $RUN_DIR"

trap 'stop_proxy; topo_down' EXIT
topo_reset
topo_up "$MODE"
gen_cert "$CERT" "$KEY"

emit() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RESULTS"; }

run_simple() {  # run_simple <name>
  local name="$1"
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/$name.ready" peer="$WORK/$name.peer"
  rm -f "$ready"; : > "$peer"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"

  ip netns exec "$NS_SRV" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/$name.py" server \
    --cert "$CERT" --key "$KEY" --bind "$SERVER_IP" --port 443 \
    --ready "$ready" --peerfile "$peer" >"$WORK/$name.server.log" 2>&1 &
  local spid=$!
  if ! wait_file "$ready"; then
    warn "[$name] server never became ready"; cat "$WORK/$name.server.log"
    kill "$spid" 2>/dev/null; emit "$name" err err 0 ""; return
  fi

  start_proxy "$TOML" "$WORK/$name.proxy.log"
  if ! wait_proxy "$WORK/$name.proxy.log"; then
    stop_proxy; kill "$spid" 2>/dev/null; emit "$name" err err 0 ""; return
  fi

  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/$name.py" client \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 \
    --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/$name.client.log" 2>&1
  local crc=$?
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null

  local afwd=fail
  { [ $crc -eq 0 ] && grep -q FORWARD_OK "$WORK/$name.client.log"; } && afwd=ok

  local srcip=missing
  if grep -qF "$BOX_IP" "$peer"; then srcip=BOXLEAK
  elif grep -qF "$CLIENT_IP" "$peer"; then srcip=ok; fi

  local adump=err alvl=0 pout
  pout="$(python3 "$PROTO_DIR/cases/$name.py" parse --dump-dir "$dump" 2>"$WORK/$name.parse.log")"
  echo "$pout" > "$WORK/$name.parse.out"
  case "$pout" in
    DUMP_OK*)      adump=ok;      alvl="$(printf '%s' "$pout" | sed -n 's/.*level=\([0-9]*\).*/\1/p')";;
    DUMP_PARTIAL*) adump=degrade; alvl="$(printf '%s' "$pout" | sed -n 's/.*level=\([0-9]*\).*/\1/p')";;
    DUMP_FAIL*)    adump=fail;;
    DUMP_NA*)      adump=na;;
    *)             adump=err;;
  esac
  [ -z "$alvl" ] && alvl=0

  cp -r "$dump" "$ART/$name" 2>/dev/null || true
  emit "$name" "$afwd" "$adump" "$alvl" "$srcip"
  info "[$name] fwd=$afwd dump=$adump level=$alvl srcip=$srcip"
}

# --- custom lifecycle orchestration ---------------------------------------
_lc_server() {  # start the generic http1 server; args: <ready> <peer> <log>
  ip netns exec "$NS_SRV" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/http1.py" server \
    --cert "$CERT" --key "$KEY" --bind "$SERVER_IP" --port 443 \
    --ready "$1" --peerfile "$2" >"$3" 2>&1 &
  echo $!
}

lc_newconn() {
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/newconn.ready" peer="$WORK/newconn.peer"; rm -f "$ready"; : > "$peer"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/newconn.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit newconn err err 0 ""; return; }
  start_proxy "$TOML" "$WORK/newconn.proxy.log"
  wait_proxy "$WORK/newconn.proxy.log" || { stop_proxy; kill "$spid" 2>/dev/null; emit newconn err err 0 ""; return; }
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" once \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/newconn.client.log" 2>&1
  local crc=$?; stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local afwd=fail; { [ $crc -eq 0 ] && grep -q FORWARD_OK "$WORK/newconn.client.log"; } && afwd=ok
  local adump=fail alvl=0; if grep -rq "GET /once" "$dump" 2>/dev/null; then adump=ok; alvl=2; fi
  local srcip=missing; if grep -qF "$BOX_IP" "$peer"; then srcip=BOXLEAK; elif grep -qF "$CLIENT_IP" "$peer"; then srcip=ok; fi
  cp -r "$dump" "$ART/newconn" 2>/dev/null || true
  emit newconn "$afwd" "$adump" "$alvl" "$srcip"
  info "[newconn] fwd=$afwd dump=$adump srcip=$srcip"
}

lc_preexisting() {
  if [ "$MODE" != ebpf ]; then
    info "[preexisting] SKIP: conntrack path differs under iproute (asserted under ebpf)"
    emit preexisting skip skip 0 na; return
  fi
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/pre.ready" peer="$WORK/pre.peer"; rm -f "$ready"; : > "$peer"
  local connected="$WORK/pre.connected" go="$WORK/pre.go"; rm -f "$connected" "$go"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/pre.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit preexisting err err 0 na; return; }
  # Client connects + first request while the proxy is NOT yet attached (plain-routed).
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" hold \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    --connected "$connected" --go "$go" >"$WORK/pre.client.log" 2>&1 &
  local cpid=$!
  if ! wait_file "$connected" 100; then
    warn "[preexisting] pre-attach connection never established:"; cat "$WORK/pre.client.log"
    kill "$cpid" "$spid" 2>/dev/null; emit preexisting err err 0 na; return
  fi
  start_proxy "$TOML" "$WORK/pre.proxy.log"
  wait_proxy "$WORK/pre.proxy.log" || { stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit preexisting err err 0 na; return; }
  touch "$go"                    # release the second (mid-stream) request now that divert is attached
  wait "$cpid" 2>/dev/null
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local afwd=ok
  grep -q SECOND_RESET "$WORK/pre.client.log" && afwd=fail
  emit preexisting "$afwd" na 0 na
  info "[preexisting] second-request afwd=$afwd (expected fail = reset)"
}

lc_restart() {
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/rst.ready" peer="$WORK/rst.peer"; rm -f "$ready"; : > "$peer"
  local connected="$WORK/rst.connected" go="$WORK/rst.go"; rm -f "$connected" "$go"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/rst.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  start_proxy "$TOML" "$WORK/rst.proxy1.log"
  wait_proxy "$WORK/rst.proxy1.log" || { stop_proxy; kill "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" hold \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    --connected "$connected" --go "$go" >"$WORK/rst.client.log" 2>&1 &
  local cpid=$!
  if ! wait_file "$connected" 100; then
    warn "[restart] intercepted connection never established:"; cat "$WORK/rst.client.log"
    stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit restart err err 0 na; return
  fi
  stop_proxy                     # kill the proxy mid-connection
  start_proxy "$TOML" "$WORK/rst.proxy2.log"
  wait_proxy "$WORK/rst.proxy2.log" || { stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  touch "$go"
  wait "$cpid" 2>/dev/null
  local afwd=ok
  grep -q SECOND_RESET "$WORK/rst.client.log" && afwd=fail
  # recovery: a fresh connection through the restarted proxy should work
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" once \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/rst.newclient.log" 2>&1
  grep -q FORWARD_OK "$WORK/rst.newclient.log" && info "[restart] fresh connection recovered after restart" \
    || warn "[restart] fresh connection did NOT recover"
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  emit restart "$afwd" na 0 na
  info "[restart] in-flight afwd=$afwd (expected fail = dropped)"
}

run_custom() {
  case "$1" in
    newconn)     lc_newconn;;
    preexisting) lc_preexisting;;
    restart)     lc_restart;;
    *) emit "$1" err err 0 "";;
  esac
}

run_case() {
  case "$2" in
    simple) run_simple "$1";;
    custom) run_custom "$1";;
    *) emit "$1" err err 0 "";;
  esac
}

while IFS=$'\t' read -r name kind group class exp_fwd exp_dump exp_level note; do
  case "$name" in ''|\#*) continue;; esac
  [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
  run_case "$name" "$kind"
done < "$PROTO_DIR/manifest.tsv"

stop_proxy; topo_down; trap - EXIT
python3 "$PROTO_DIR/report.py" --manifest "$PROTO_DIR/manifest.tsv" \
  --results "$RESULTS" --json-out "$RUN_DIR/report.json" --mode "$MODE" | tee "$RUN_DIR/report.txt"
rc=${PIPESTATUS[0]}
cp "$PROTO_DIR/manifest.tsv" "$RESULTS" "$RUN_DIR/" 2>/dev/null || true
cp "$WORK"/*.log "$WORK"/*.parse.out "$RUN_DIR/logs/" 2>/dev/null || true
{ echo "suite=matrix"; echo "mode=$MODE"; echo "date=$(date -u +%FT%TZ)"; \
  echo "git=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"; echo "binary=$BIN"; } > "$RUN_DIR/meta.txt"
green "REPORT: $RUN_DIR"
info  "  report.txt | report.json | dumps/<case>/ | logs/<case>.*.log"
exit $rc
