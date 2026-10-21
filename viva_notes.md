# Viva Notes – WEB404 Assignment 1 (Nikto)

Personal study notes. Short, simple answers based on what was actually done in this lab.

---

## Part 1 – The numbers to remember

| Fact | Value |
|---|---|
| Nikto version | **2.6.1** (installed with Homebrew) |
| Targets | **A** DVWA :8081, **B** misconfigured :8082, **C** hardened :8083 (all on 127.0.0.1) |
| Why not 8080? | A local **Jenkins** was already using it |
| Basic scan size | ~**8,000 requests in ~4 seconds** per target |
| Target B findings | **19** items |
| Target C findings | **3** items (junk methods = false positive, HSTS = not applicable, Permissions-Policy = info) |
| DVWA findings | **16** items; **0** injection findings even with `-Tuning 49` |
| Tuning effect | `-Tuning 123b` on B: same 19 items, **4,214** requests instead of 7,969 (~47% fewer) |
| Biggest finding | DVWA `/config/config.inc.php.dist` readable → `root` / `p@ssw0rd` |
| Biggest miss | `.bak` files on B (one contained a DB password) were **not** reported by Nikto |

---

## Part 2 – Likely viva questions

**1. What is Nikto?**
A free, open-source command-line **web server scanner** written in Perl. It sends thousands of requests for known files and checks, then compares the responses against its database of known problems. It's **signature-based**: it only finds what it already knows about.

**2. What kind of problems does Nikto find?**
Server misconfigurations: version banners, missing security headers, cookies without HttpOnly, directory listing, TRACE enabled, default and leftover files (phpinfo, test, backup), and outdated server software.

**3. What are Nikto's main limitations?**
(1) **Noisy**: 8,000 requests in 4 seconds, easily detected. (2) **False positives**, e.g. junk methods and HSTS on HTTP. (3) **False negatives**, e.g. it missed our `.bak` files. (4) It **doesn't test application logic**: no crawling, no forms, no login, so it found zero SQLi/XSS in DVWA.

**4. How is Nikto different from Burp Suite and OWASP ZAP?**
Nikto scans the **server** for known files and settings. Burp and ZAP are **intercepting proxies** that test the **application**: they crawl pages, handle logins, and send payloads into forms and parameters to find SQLi and XSS. Nikto is a quick first check; Burp and ZAP do the deeper testing.

**5. Why did you only scan local targets?**
Scanning a system without written permission is illegal and unethical: it counts as unauthorised access or an attack. Nikto is also very noisy. So everything ran in Docker on my own laptop, and the ports were bound to `127.0.0.1` so nobody else on the network could even reach the vulnerable apps.

**6. Why did you bind the ports to 127.0.0.1?**
`"127.0.0.1:8082:80"` means the port is only open on localhost. Without it, Docker opens the port on every network interface, and anyone on the same Wi-Fi could reach DVWA, which is deliberately vulnerable.

**7. Why did you build both a misconfigured and a hardened site?**
To prove the fixes work. B and C run the **same code**, so any difference in the Nikto results comes only from configuration. 19 → 3 findings is measurable evidence.

**8. What does `-Tuning` do? Which did you use and why?**
It picks which **categories** of tests to run. I used `123b` (interesting files, misconfiguration, information disclosure, software identification) because our problems are configuration problems. It found the same 19 issues with about half the requests. I also used `49` (XSS + SQL injection) on DVWA to show Nikto can't find DVWA's injection flaws.

**9. Why didn't Nikto find SQL injection in DVWA?**
Nikto only requests **known vulnerable paths** from its database. DVWA's SQLi page isn't in it. Nikto also doesn't crawl or fill in forms, and DVWA's vulnerable pages are **behind a login**. You need ZAP, Burp, sqlmap or manual testing for that.

**10. What is a false positive? Give an example from your scan.**
A finding that's reported but isn't a real problem. Example: "**junk HTTP methods**". I sent `curl -X FOOBAR` and got 200, but Apache just returns the homepage, so nothing is exposed. Another: **HSTS missing**, which only matters over HTTPS, and our lab is HTTP.

**11. What is a false negative? Give an example.**
A real problem the scanner **missed**. Example: `/backup/config.php.bak` and `/index.php.bak` were readable and one contained a password, but Nikto didn't report them. It also didn't check the `Secure`/`SameSite` cookie flags.

**12. Why is manual verification important?**
To remove false positives **and** to rate the real risk. Nikto said DVWA's `/config/` "**may** reveal configuration information". When I checked by hand, it exposed the database **root password**, which makes it High risk, not just "info".

**13. Why does `config.php.bak` show the password but `config.php` wouldn't?**
Apache only sends `.php` files to the PHP engine, which runs them and outputs only the result (empty for a config file). A `.bak` file isn't PHP, so Apache sends the **raw source code**. In the browser it downloaded because `.bak` maps to `application/x-trash` in `mime.types`, but the attacker still gets the file.

**14. What's wrong with showing the server version? What did you change?**
Exact versions (e.g. `Apache/2.4.68 (Debian) PHP/8.2.34`) let attackers look up known CVEs for that version. I fixed it with `ServerTokens Prod` (header shows just "Apache"), `ServerSignature Off` (no version on error pages) and `expose_php = Off` (no X-Powered-By). This is "security through obscurity": it helps, but **patching** is the real fix.

**15. What does the HttpOnly flag do? Secure? SameSite?**
- **HttpOnly**: JavaScript can't read the cookie, so an XSS bug can't steal the session.
- **Secure**: the cookie is only sent over HTTPS, so it can't be sniffed on plain HTTP.
- **SameSite=Strict**: the cookie isn't sent on requests from other sites, which helps stop CSRF.

**16. Explain the security headers you added.**
- **X-Frame-Options: DENY**: the page can't be put in a frame, which stops clickjacking.
- **X-Content-Type-Options: nosniff**: the browser trusts the declared file type and doesn't guess.
- **Content-Security-Policy: default-src 'self'**: scripts, styles and images can only load from our own site, which limits XSS. `frame-ancestors 'none'` is the modern replacement for X-Frame-Options.
- **Referrer-Policy**: full URLs aren't leaked to other sites.

**17. What is directory listing and why is it dangerous?**
When a folder has no index page, Apache shows a list of every file in it ("Index of /files"). Attackers can see and download files the developer never linked to: backups, internal documents. Fixed with `Options -Indexes`, so the server returns 403 Forbidden.

**18. What is the TRACE method and why disable it?**
TRACE makes the server echo the request back. Combined with XSS, it was historically used for **Cross-Site Tracing (XST)** to read HttpOnly cookies. Modern browsers block it, so the risk is low, but there's no reason to leave it on. `TraceEnable Off` makes Apache return 405.

**19. Which OWASP Top 10 categories did your findings fall into?**
Mostly **A05:2021 Security Misconfiguration** (banners, headers, listing, leftover files, TRACE). **A06 Vulnerable and Outdated Components** (DVWA's Apache 2.4.25). **A07 Identification and Authentication Failures** (cookie flags). **A01 Broken Access Control** (directory listing). In the 2025 edition, Security Misconfiguration moved up to A02.

**20. Why are there still 3 findings on the hardened site?**
(1) Junk methods: a false positive. (2) HSTS: not applicable without HTTPS. (3) Permissions-Policy: a real but informational item. I could fix it with one more `Header always set Permissions-Policy ...` line. Zero findings isn't the goal; understanding each one is.

**21. If you were doing this on a real company website, what would you do differently?**
Get **written permission and scope** first. Scan a staging server, not production. Use tuning to avoid DoS tests (`-Tuning x6`) and scan outside busy hours. Inform the operations/security team so the noise isn't treated as a real attack. Follow up with ZAP or Burp plus authenticated testing, and write a report with risk ratings and fixes.

**22. Why does C still say `Server: Apache`?**
`ServerTokens Prod` is the minimum Apache allows. Removing the word "Apache" entirely needs ModSecurity or a reverse proxy. That's fine, because the version number is what attackers need.

---

## Part 3 – Line-by-line explanations

### 3.1 `docker-compose.yml`

```yaml
services:
```
A list of the containers to run. Each one below is a "service".

```yaml
  dvwa:
    image: vulnerables/web-dvwa
```
Service named `dvwa`. Use the ready-made DVWA image from Docker Hub instead of building one.

```yaml
    platform: linux/amd64          # image is Intel-only; runs emulated on Apple Silicon
```
The DVWA image only exists for Intel CPUs. My Mac is ARM (Apple Silicon), so this tells Docker to run it under emulation.

```yaml
    container_name: target-a-dvwa
```
A fixed, readable container name (otherwise Docker generates one).

```yaml
    ports:
      - "127.0.0.1:8081:80"
```
Format is `host-ip:host-port:container-port`. Apache listens on port 80 **inside** the container; we reach it on port 8081 of **localhost only**.

```yaml
  misconfigured:
    build:
      context: .
      dockerfile: target-b-misconfigured/Dockerfile
```
Instead of downloading an image, **build** one. `context: .` means the Dockerfile can copy files from the whole project folder (it needs both `site/` and `target-b-misconfigured/`). `dockerfile:` says which Dockerfile to use.

```yaml
    container_name: target-b-misconfigured
    ports:
      - "127.0.0.1:8082:80"
```
Same idea: name it, and publish it on localhost:8082.

The `hardened` service is identical but uses `target-c-hardened/Dockerfile` and port **8083**.

---

### 3.2 `target-b-misconfigured/Dockerfile`

```dockerfile
FROM php:8.2-apache
```
Start from the official PHP 8.2 image, which already includes the Apache web server.

```dockerfile
COPY target-b-misconfigured/security.conf /etc/apache2/conf-available/security.conf
```
Overwrite Apache's built-in `security.conf` (where Debian keeps ServerTokens/ServerSignature/TraceEnable) with our **insecure** version.

```dockerfile
COPY target-b-misconfigured/php.ini /usr/local/etc/php/conf.d/lab.ini
```
PHP automatically loads every `.ini` file in `conf.d/`, so this adds our insecure PHP settings.

```dockerfile
COPY site/ /var/www/html/
```
Copy the shared website into Apache's web root (the folder Apache serves).

```dockerfile
COPY target-b-misconfigured/leftovers/ /var/www/html/
```
Also copy the "forgotten" files: `phpinfo.php`, `test.php`, `index.php.bak`, `backup/config.php.bak`.

### 3.3 `target-c-hardened/Dockerfile`

```dockerfile
FROM php:8.2-apache
```
Same starting image as B.

```dockerfile
RUN a2enmod headers
```
`a2enmod` = "Apache 2 enable module". Turns on **mod_headers**, which is needed for the `Header always set …` lines.

```dockerfile
COPY target-c-hardened/security.conf /etc/apache2/conf-available/security.conf
COPY target-c-hardened/php.ini /usr/local/etc/php/conf.d/lab.ini
```
Same locations as B, but the **hardened** versions.

```dockerfile
COPY site/ /var/www/html/
```
Only the website. **No leftovers line**: that is the "remove leftover files" fix.

---

### 3.4 `target-b-misconfigured/security.conf` (insecure)

| Line | Meaning |
|---|---|
| `ServerTokens Full` | `Server` header shows everything: `Apache/2.4.68 (Debian) PHP/8.2.34` |
| `ServerSignature On` | Adds a line with the server version at the bottom of error pages and directory listings |
| `TraceEnable On` | Allows the HTTP TRACE method (echoes requests back) |
| `<Directory /var/www/html>` | The following rules apply to the website folder |
| `Options Indexes FollowSymLinks` | `Indexes` = show a file list when a folder has no index page. `FollowSymLinks` = allow symbolic links |
| `AllowOverride None` | Ignore `.htaccess` files (all config is in this file) |
| `Require all granted` | Anyone may access the folder |
| `</Directory>` | End of the folder rules |

### 3.5 `target-c-hardened/security.conf` (hardened)

| Line | Meaning |
|---|---|
| `ServerTokens Prod` | `Server` header shows only `Apache`, with no version and no OS |
| `ServerSignature Off` | No version line on error pages |
| `TraceEnable Off` | TRACE returns `405 Method Not Allowed` |
| `Options -Indexes +FollowSymLinks` | `-Indexes` = **turn off** directory listing (403 instead). `+FollowSymLinks` keeps symlinks working |
| `AllowOverride None` / `Require all granted` | Same as B |
| `Header always set X-Frame-Options "DENY"` | Never allow this page inside a frame (anti-clickjacking). `always` = also on error pages |
| `Header always set X-Content-Type-Options "nosniff"` | Browser must not guess file types |
| `Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'"` | Only load resources from our own origin; no site may frame us |
| `Header always set Referrer-Policy "strict-origin-when-cross-origin"` | Send only the domain (not the full URL) to other sites |

### 3.6 `php.ini` files

| Setting | B (insecure) | C (hardened) | Meaning |
|---|---|---|---|
| `expose_php` | `On` | `Off` | Whether PHP adds `X-Powered-By: PHP/8.2.34` |
| `display_errors` | `On` | `Off` | Whether error details (paths, code) are shown to visitors |
| `log_errors` | – | `On` | Write errors to the log instead, for the developer |
| `session.cookie_httponly` | `0` | `1` | Block JavaScript from reading the session cookie |
| `session.cookie_secure` | `0` | `1` | Only send the cookie over HTTPS |
| `session.cookie_samesite` | *(empty)* | `Strict` | Don't send the cookie on cross-site requests |

Lines starting with `;` are comments in `.ini` files.

### 3.7 `site/index.php`

| Line | Meaning |
|---|---|
| `session_start();` | Starts a PHP session, so PHP sends the `PHPSESSID` cookie. Its flags come from `php.ini` |
| `$_SESSION['visits'] = ($_SESSION['visits'] ?? 0) + 1;` | Counts visits. `??` means "use 0 if it doesn't exist yet" |
| `<?php echo (int) $_SESSION['visits']; ?>` | Prints the count. `(int)` forces it to be a number (safe output) |
| `<a href="/files/">` | Link to the folder without an index page, used to test directory listing |

---

### 3.8 `scan.sh`

```bash
#!/usr/bin/env bash
```
"Shebang": run this file with bash (found via `env`, so it works wherever bash is installed).

```bash
set -u
```
Stop with an error if the script uses a variable that was never set, which catches typos.

```bash
HOST="127.0.0.1"
RESULTS="results"
mkdir -p "$RESULTS"
```
The target host is **hard-coded to localhost**, so the script can't scan anything else. `mkdir -p` creates `results/` (no error if it already exists).

```bash
run_scan() {
    name="$1"
    port="$2"
    scan="$3"
    shift 3
    out="$RESULTS/${name}_${scan}"
```
A **function**, so the same Nikto command isn't written 7 times. `$1 $2 $3` are its first three arguments (target name, port, scan name). `shift 3` removes them, so `"$@"` now holds only the **extra Nikto options** (like `-Tuning 123b`). `out` is the file name without extension, e.g. `results/misconfigured_basic`.

```bash
    echo "=================================================="
    echo " $scan scan of $name  ->  http://$HOST:$port"
    echo "=================================================="
```
Prints a heading so you can tell the scans apart in the output.

```bash
    nikto -h "$HOST" -p "$port" -ask no -nointeractive \
          -o "$out.htm" -Format htm "$@" | tee "$out.txt"
}
```
- `-h` / `-p`: host and port to scan
- `-ask no`: never send findings to the Nikto project
- `-nointeractive`: no key presses needed during the scan
- `-o "$out.htm" -Format htm`: Nikto writes an **HTML** report
- `"$@"`: any extra options (tuning)
- `\`: continues the command on the next line
- `| tee "$out.txt"`: the pipe sends Nikto's screen output to `tee`, which **shows it and saves it** as the **text** report

```bash
run_scan dvwa          8081 basic
run_scan misconfigured 8082 basic
run_scan hardened      8083 basic
```
Basic scans: every default test against each target.

```bash
run_scan dvwa          8081 tuned-config -Tuning 123b
run_scan misconfigured 8082 tuned-config -Tuning 123b
run_scan hardened      8083 tuned-config -Tuning 123b
```
Tuned scans: 1 interesting files, 2 misconfiguration/default files, 3 information disclosure, b software identification.

```bash
run_scan dvwa          8081 tuned-injection -Tuning 49
```
Injection-only scan of DVWA: 4 XSS/injection, 9 SQL injection. It shows that Nikto **can't** find DVWA's injection bugs.

### 3.9 `verify.sh`

| Part | Meaning |
|---|---|
| `A=…; B=…; C=…` | Base URLs for the three targets |
| `title() { … }` | Small function that prints a heading |
| `status() { curl -s -o /dev/null -w "%{http_code}" "$1"; }` | Prints only the HTTP status code. `-s` = silent, `-o /dev/null` = throw away the body, `-w "%{http_code}"` = print the code |
| `curl -sI "$B/"` | `-I` = HEAD request, which shows only the **headers** (banner, cookies, security headers) |
| `curl -X TRACE …` | `-X` sends a specific HTTP method. 200 = TRACE on, 405 = off |
| `curl -X FOOBAR …` | Made-up method to test the "junk methods" finding |
| `for u in /files/ /backup/ …; do … done` | Loops over the risky URLs and prints B's and C's status codes side by side |
| `curl -s "$B/backup/config.php.bak"` | Shows the leaked backup file contents |
| `grep -o '<address>.*</address>'` | Pulls the server signature line out of the 404 page |
| `grep 'href="config[^"]*"'` / `grep "db_"` | Shows the DVWA `/config/` file list and the DB settings lines |

> **Gotcha I hit:** in zsh, `path` is a special variable linked to `$PATH`. Using `for path in …` broke every command ("curl: command not found"), so the loop variable is called `u` instead.

### 3.10 `.gitignore` and `.dockerignore`

- **`.gitignore`**: files git should **not** track: `.DS_Store` (macOS junk), editor folders, `*.log`, `*.tmp`. Results and screenshots **are** committed because they are evidence.
- **`.dockerignore`**: files Docker should **not** send to the build: `.git`, `results`, `screenshots`, `*.md`. This makes builds faster and keeps report files out of the images.

---

## Part 4 – One-minute summary (if asked "tell us about your assignment")

> I built a local Docker lab with three targets: DVWA, a deliberately misconfigured Apache/PHP site, and a hardened copy of the same site. All three were bound to localhost only, for ethical reasons. I scanned each one with Nikto 2.6.1 using basic and tuned scans, then verified the findings with curl. Nikto found 19 issues on the misconfigured site, mostly OWASP A05 Security Misconfiguration: version banners, missing security headers, a cookie without HttpOnly, TRACE, directory listing and a phpinfo page. After hardening (ServerTokens Prod, -Indexes, security headers, cookie flags, removing leftover files) this dropped to 3, and none of those were real risks. Manual verification found false positives like junk methods and HSTS on HTTP, and false negatives like `.bak` files with a password that Nikto missed. On DVWA it found an exposed config file with the root DB password, but none of DVWA's SQL injection or XSS. That shows Nikto is a good first step for server configuration, but application testing needs tools like ZAP or Burp.
