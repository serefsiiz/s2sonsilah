#!/bin/bash
# x64dbg MCP SSE controller - usage:
#   ./sse_helper.sh init                          # initialize session, save SID
#   ./sse_helper.sh call <tool> <json_args>       # call a tool
#   ./sse_helper.sh cmd "<dbg_command>"           # ExecuteDebuggerCommandWithOutput
#   ./sse_helper.sh regs                          # GetAllRegisters

BASE=http://localhost:50300
STATE=/tmp/x64dbg_sse_state
SSE_PIPE=/tmp/x64dbg_sse_pipe
SSE_OUT=/tmp/x64dbg_sse_out

case "$1" in
  init)
    rm -f "$STATE" "$SSE_OUT"
    # Kill any leftover SSE listener
    pkill -f "curl.*localhost:50300/sse" 2>/dev/null
    sleep 0.3
    # Start persistent SSE listener (ALL day)
    nohup curl -sS -N "$BASE/sse" > "$SSE_OUT" 2>/dev/null &
    SSE_PID=$!
    echo "$SSE_PID" > "$STATE.pid"
    # Wait for endpoint event
    for i in 1 2 3 4 5 6 7 8 9 10; do
      sleep 0.2
      SID=$(grep -oE 'sessionId=[A-Za-z0-9_-]+' "$SSE_OUT" 2>/dev/null | head -1 | sed 's/sessionId=//')
      [ -n "$SID" ] && break
    done
    if [ -z "$SID" ]; then
      echo "ERROR: no session ID"; exit 1
    fi
    echo "$SID" > "$STATE"
    echo "Session: $SID (SSE_PID=$SSE_PID)"
    # init handshake
    curl -sS -m 3 -X POST "$BASE/message?sessionId=$SID" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"bashctl","version":"1.0"}}}' > /dev/null
    curl -sS -m 3 -X POST "$BASE/message?sessionId=$SID" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' > /dev/null
    sleep 0.3
    echo "--- handshake response ---"
    tail -20 "$SSE_OUT"
    ;;
  call)
    SID=$(cat "$STATE" 2>/dev/null)
    [ -z "$SID" ] && { echo "no session — run init first"; exit 1; }
    TOOL="$2"
    ARGS="$3"
    [ -z "$ARGS" ] && ARGS='{}'
    # Mark size before request
    BEFORE=$(wc -c < "$SSE_OUT" 2>/dev/null || echo 0)
    REQ_ID=$(date +%N)
    BODY=$(printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$REQ_ID" "$TOOL" "$ARGS")
    curl -sS -m 5 -X POST "$BASE/message?sessionId=$SID" \
      -H "Content-Type: application/json" \
      -d "$BODY" > /dev/null
    # Wait for response in SSE stream
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      sleep 0.25
      AFTER=$(wc -c < "$SSE_OUT" 2>/dev/null || echo 0)
      if [ "$AFTER" != "$BEFORE" ]; then
        # Check if response with our id arrived
        if tail -c $((AFTER - BEFORE)) "$SSE_OUT" | grep -q "\"id\":$REQ_ID"; then
          break
        fi
      fi
    done
    # Print only new bytes
    tail -c +$((BEFORE + 1)) "$SSE_OUT"
    echo
    ;;
  cmd)
    "$0" call ExecuteDebuggerCommandWithOutput "$(printf '{"command":"%s","settleDelayMs":300}' "$2")"
    ;;
  regs)
    "$0" call GetAllRegisters '{}'
    ;;
  bplist)
    "$0" call GetBreakpointInfo '{}'
    ;;
  modules)
    "$0" call GetAllModulesFromMemMap '{}'
    ;;
  threads)
    "$0" call GetAllActiveThreads '{}'
    ;;
  *)
    echo "Usage: $0 {init|call|cmd|regs|bplist|modules|threads}"
    exit 1
    ;;
esac
