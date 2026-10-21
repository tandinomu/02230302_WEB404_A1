#!/usr/bin/env bash
# verify.sh - manually check the important Nikto findings with curl
# Usage:  ./verify.sh | tee results/manual-verification.txt

A="http://127.0.0.1:8081"   # DVWA
B="http://127.0.0.1:8082"   # misconfigured
C="http://127.0.0.1:8083"   # hardened

# Print a heading so the output is easy to read
title() { echo; echo "========== $1 =========="; }

# Print only the HTTP status code of a URL (e.g. 200, 403, 404)
status() { curl -s -o /dev/null -w "%{http_code}" "$1"; }

# 1. Response headers: version banner, X-Powered-By, cookie flags, security headers
title "1. Headers on B (misconfigured)"
curl -sI "$B/"
title "1. Headers on C (hardened)"
curl -sI "$C/"

# 2. TRACE method: B should echo the request back (200), C should refuse (405)
title "2. TRACE method"
echo "B: $(curl -s -o /dev/null -w '%{http_code}' -X TRACE "$B/")"
echo "C: $(curl -s -o /dev/null -w '%{http_code}' -X TRACE "$C/")"

# 3. Made-up HTTP method: checks Nikto's "junk HTTP methods" warning
title "3. Junk method FOOBAR"
echo "B: $(curl -s -o /dev/null -w '%{http_code}' -X FOOBAR "$B/")"
echo "C: $(curl -s -o /dev/null -w '%{http_code}' -X FOOBAR "$C/")"

# 4. Directory listing and leftover files (200 = exposed, 403/404 = blocked)
title "4. Directory listing and leftover files (B vs C)"
for u in /files/ /backup/ /phpinfo.php /test.php /index.php.bak /backup/config.php.bak; do
    echo "$u    B=$(status "$B$u")  C=$(status "$C$u")"
done

# 5. Contents of the leftover backup file on B (Nikto did NOT report this file)
title "5. B /backup/config.php.bak"
curl -s "$B/backup/config.php.bak"

# 6. Server signature at the bottom of a 404 error page
title "6. Signature on a 404 page"
echo "B: $(curl -s "$B/does-not-exist" | grep -o '<address>.*</address>')"
echo "C: $(curl -s "$C/does-not-exist" | grep -o '<address>.*</address>')"

# 7. DVWA findings: open /config/ folder and the database settings inside it
title "7. DVWA /config/ listing"
curl -s "$A/config/" | grep -o 'href="config[^"]*"'
title "7. DVWA config.inc.php.dist (served as plain text)"
curl -s "$A/config/config.inc.php.dist" | grep "db_"
title "7. DVWA /.gitignore"
curl -s "$A/.gitignore"
