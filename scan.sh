#!/usr/bin/env bash
# scan.sh - run Nikto against the three LOCAL lab targets
# Usage:  ./scan.sh
# Output: results/<target>_<scan>.txt  (what Nikto prints on screen)
#         results/<target>_<scan>.htm  (Nikto's HTML report)

# Stop if we use a variable that was never set (catches typos)
set -u

# Only ever scan this machine. The targets are published on 127.0.0.1 only.
HOST="127.0.0.1"
RESULTS="results"
mkdir -p "$RESULTS"

# run_scan <target-name> <port> <scan-name> [extra Nikto options...]
run_scan() {
    name="$1"
    port="$2"
    scan="$3"
    shift 3                          # whatever is left ("$@") = extra options
    out="$RESULTS/${name}_${scan}"

    echo "=================================================="
    echo " $scan scan of $name  ->  http://$HOST:$port"
    echo "=================================================="

    # -h / -p          : target host and port
    # -ask no          : never ask to send data back to the Nikto project
    # -nointeractive   : don't wait for key presses during the scan
    # -o / -Format htm : save an HTML report
    # | tee            : show output on screen AND save it as a text file
    nikto -h "$HOST" -p "$port" -ask no -nointeractive \
          -o "$out.htm" -Format htm "$@" | tee "$out.txt"
}

# 1) BASIC scans - every default test against every target
run_scan dvwa          8080 basic
run_scan misconfigured 8081 basic
run_scan hardened      8082 basic

# 2) TUNED scans - only configuration-related tests:
#    1 = Interesting files, 2 = Misconfiguration / default files,
#    3 = Information disclosure, b = Software identification
run_scan dvwa          8080 tuned-config -Tuning 123b
run_scan misconfigured 8081 tuned-config -Tuning 123b
run_scan hardened      8082 tuned-config -Tuning 123b

# 3) TUNED scan - injection tests only, to see how far Nikto gets
#    against a real vulnerable app:  4 = XSS/injection, 9 = SQL injection
run_scan dvwa          8080 tuned-injection -Tuning 49
