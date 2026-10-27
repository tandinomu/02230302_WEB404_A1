# WEB404 Assignment 1 - Vulnerability Assessment with Nikto

| | |
|---|---|
| **Module** | WEB404 Secure Coding Practices |
| **Student** | 02230302 |
| **Programme** | BE Software Engineering |
| **Task** | Use Nikto to conduct a vulnerability assessment on a sample website and interpret the findings |
| **Tools** | Nikto 2.6.1, Docker 29.7 / Docker Compose 5.3, curl 8.7, macOS 26 (Apple Silicon) |

---

## Overview — what this assignment does and how

This assignment uses **Nikto** to perform a vulnerability assessment of web
servers and to interpret the findings.

The approach has five stages:

1. **Build an isolated lab** — three local targets in Docker: DVWA (a realistic
   vulnerable app), a deliberately *misconfigured* site, and a *hardened* copy of
   that same site.
2. **Scan** each target with Nikto (full scans and tuned scans).
3. **Verify** every important finding by hand with `curl` and the browser,
   separating true positives, false positives and false negatives.
4. **Interpret** each finding: rate its risk and map it to the OWASP Top 10.
5. **Compare** the misconfigured site against the hardened one to prove the fixes
   work.

Everything runs locally, bound to `127.0.0.1` only.

---

## Table of contents

0. [Overview](#overview--what-this-assignment-does-and-how)
1. [Introduction](#1-introduction)
2. [Lab setup and ethical considerations](#2-lab-setup-and-ethical-considerations)
3. [Methodology](#3-methodology)
4. [Scan results](#4-scan-results)
5. [Findings table](#5-findings-table)
6. [Manual verification and false positives](#6-manual-verification-and-false-positives)
7. [Before vs after: misconfigured vs hardened](#7-before-vs-after-misconfigured-vs-hardened)
8. [Conclusion](#8-conclusion)
9. [How to reproduce](#9-how-to-reproduce)
10. [References](#10-references)

---

## 1. Introduction

### 1.1 What is Nikto?

**Nikto** is a free, open-source **web server scanner** written in Perl by Chris Sullo (CIRT.net). It sends thousands of HTTP requests to a web server and compares the responses against a database of known problems. It is a **signature-based** scanner: it looks for things it already knows about, much like an antivirus looks for known malware.

### 1.2 What does Nikto check?

| Area | Examples |
|---|---|
| **Server identification** | Reads the `Server` and `X-Powered-By` headers to find the web server and language version |
| **Outdated software** | Compares the version found against the latest known version (e.g. "Apache/2.4.25 appears to be outdated") |
| **Dangerous / default files** | Requests thousands of known paths such as `/phpinfo.php`, `/test.php`, `/backup/`, `/icons/README`, `/.gitignore` |
| **Misconfigurations** | Directory listing, HTTP `TRACE` enabled, unusual HTTP methods accepted |
| **Security headers** | Missing `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, etc. |
| **Cookies** | Cookies created without the `HttpOnly` flag |
| **Known vulnerable scripts** | CGI scripts and web apps with published vulnerabilities |

### 1.3 Limitations of Nikto

- **Noisy.** A basic scan sent about **8,000 requests in 4 seconds** in this lab. On a real network this fills the logs and is immediately detected by any IDS/WAF. Nikto is not designed to be stealthy.
- **False positives.** Nikto reports anything that *might* be a problem. Every finding must be checked by hand (see [Section 6](#6-manual-verification-and-false-positives)).
- **False negatives.** It only finds what is in its database. In this lab it missed `index.php.bak` and `backup/config.php.bak`, which contained source code and a database password.
- **Does not test application logic.** Nikto does not log in, fill in forms, follow the application's workflow or try payloads in the application's own parameters. Against DVWA, an app full of SQL injection and XSS, a scan tuned for injection found **zero** injection vulnerabilities (Section 4.3).
- **No authentication by default.** Pages behind a login are not tested.
- **Version-based guesses.** "Outdated" findings compare version numbers only. They do not know about vendor back-ported patches or supported long-term branches.

### 1.4 Nikto vs Burp Suite vs OWASP ZAP

| | **Nikto** | **Burp Suite** | **OWASP ZAP** |
|---|---|---|---|
| Type | Command-line web **server** scanner | Intercepting proxy + web **application** testing toolkit | Intercepting proxy + web **application** scanner |
| Cost | Free, open source | Community (free, limited) / Professional (paid) | Free, open source (now maintained as "ZAP by Checkmarx") |
| How it works | Requests known paths from a signature database | Sits between browser and server; tester inspects and modifies traffic; Pro adds an automated scanner | Same proxy idea; spider/crawler + passive and active scanners |
| Tests app logic (SQLi, XSS in forms)? | No (only known vulnerable paths) | Yes (Repeater, Intruder, Scanner) | Yes (Active Scan) |
| Handles login/sessions? | Very limited | Yes | Yes |
| Best used for | Quick first check of server configuration, default files and versions | Deep manual testing by a professional | Free automated + manual app testing, CI pipelines |

**In short:** Nikto checks *the server and what is lying around on it*. Burp and ZAP test *the application itself*. They complement each other: Nikto is a good first step, not a complete assessment.

---

## 2. Lab setup and ethical considerations

### 2.1 Ethical and legal considerations

- **Only self-owned systems were scanned.** All three targets run as Docker containers on a local laptop. No external or public website was scanned.
- **Scanning without permission is illegal and unethical.** Port and vulnerability scanning a system you do not own or have written permission to test can count as unauthorised access or an attempted attack under computer misuse laws, and breaks university IT policy. Nikto is noisy, so the owner would see it immediately.
- **The vulnerable targets were never exposed to the network.** Every port is bound to `127.0.0.1` (localhost) in `docker-compose.yml`, so other devices on the Wi-Fi cannot reach DVWA or the misconfigured site.
- **Listening ports were checked before scanning.** Port 8080 was already used by a local Jenkins server (Jetty). The targets were moved to ports 8081–8083 so that no scan was accidentally pointed at a different service.
- **No credentials are real.** The passwords in the leftover files are dummy values made for this lab.
- **`-ask no`** was used so Nikto never sends any data back to its developers.

### 2.2 Lab architecture

```
                    macOS laptop (scanner: Nikto 2.6.1)
                                  │
                 HTTP over 127.0.0.1 only (localhost)
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
   :8081 Target A          :8082 Target B          :8083 Target C
   DVWA                    Sample site             Sample site
   Apache 2.4.25           MISCONFIGURED           HARDENED
   (vulnerables/web-dvwa)  php:8.2-apache          php:8.2-apache
```

| Target | Purpose | Port | Image |
|---|---|---|---|
| **A – DVWA** | A realistic, deliberately vulnerable web application | 8081 | `vulnerables/web-dvwa` (amd64, emulated on Apple Silicon) |
| **B – Misconfigured** | Our sample site with common misconfigurations | 8082 | built from `target-b-misconfigured/Dockerfile` |
| **C – Hardened** | **The same site** with the misconfigurations fixed | 8083 | built from `target-c-hardened/Dockerfile` |

**Important design choice:** Targets B and C run **exactly the same website code** (`site/`). The only differences are the Apache and PHP configuration files and the leftover files. This proves that every finding on B comes from **configuration**, not from the code.

### 2.3 What was misconfigured on purpose (Target B) and how it was fixed (Target C)

| Weakness | Target B (`target-b-misconfigured/`) | Target C (`target-c-hardened/`) |
|---|---|---|
| Version banner | `ServerTokens Full` → `Server: Apache/2.4.68 (Debian) PHP/8.2.34` | `ServerTokens Prod` → `Server: Apache` |
| Version on error pages | `ServerSignature On` | `ServerSignature Off` |
| PHP version leak | `expose_php = On` → `X-Powered-By: PHP/8.2.34` | `expose_php = Off` |
| Directory listing | `Options Indexes` | `Options -Indexes` |
| TRACE method | `TraceEnable On` | `TraceEnable Off` |
| Leftover files | `phpinfo.php`, `test.php`, `index.php.bak`, `backup/config.php.bak` | Not copied into the image |
| Security headers | None | `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy` (via `mod_headers`) |
| Session cookie flags | `session.cookie_httponly = 0`, no `Secure`, no `SameSite` | `HttpOnly`, `Secure`, `SameSite=Strict` |
| Error display | `display_errors = On` | `display_errors = Off`, `log_errors = On` |

### 2.4 Lab running

![All three containers running](screenshots/01-docker-compose-ps.png)
*Figure 1 – `docker compose ps` showing all three targets bound to 127.0.0.1*

![DVWA login page](screenshots/02-dvwa-browser.png)
*Figure 2 – Target A: DVWA on http://127.0.0.1:8081*

![Target B homepage](screenshots/03-target-b-browser.png)
*Figure 3 – Target B (misconfigured) on http://127.0.0.1:8082*

![Target C homepage](screenshots/04-target-c-browser.png)
*Figure 4 – Target C (hardened) on http://127.0.0.1:8083. It looks identical to B in the browser; the differences are only visible in the HTTP responses.*

---

## 3. Methodology

The assessment followed five steps:

1. **Prepare.** Build an isolated local lab with Docker Compose and confirm each target responds.
2. **Scan.** Run Nikto against each target with `scan.sh` (basic scans and tuned scans).
3. **Verify.** Check every important finding by hand with `curl` and the browser (`verify.sh`).
4. **Interpret.** Classify each finding as a true positive, false positive or not applicable; rate its risk and map it to the OWASP Top 10.
5. **Compare.** Compare scans of the misconfigured (B) and hardened (C) site to prove the fixes work.

### 3.1 Commands used

**Start the lab:**
```bash
docker compose up -d --build      # build B and C, download DVWA, start all three
docker compose ps                 # confirm all three are "Up"
```

**Core Nikto command (inside `scan.sh`):**
```bash
nikto -h 127.0.0.1 -p <port> -ask no -nointeractive -o results/<name>.htm -Format htm [-Tuning ...] | tee results/<name>.txt
```

| Option | Why it was used |
|---|---|
| `-h 127.0.0.1` | Target host. Hard-coded to localhost so the script can never scan anything else |
| `-p <port>` | Which target: 8081 (A), 8082 (B), 8083 (C) |
| `-ask no` | Never ask to submit findings to the Nikto project, so no data leaves the machine |
| `-nointeractive` | Do not wait for key presses, so the script runs unattended |
| `-o … -Format htm` | Save Nikto's own HTML report |
| `\| tee …txt` | Show the output on screen **and** save it as a text file at the same time (one scan, two formats) |
| `-Tuning …` | Only run certain categories of tests (see 3.2) |

### 3.2 Nikto tuning options

`-Tuning` chooses **which categories** of tests from Nikto's database are run. This makes a scan faster, quieter and more focused.

| Code | Category | What it looks for |
|---|---|---|
| `1` | Interesting File / Seen in logs | Files attackers commonly request (`/backup/`, `/test.php`) |
| `2` | Misconfiguration / Default File | Default install files and bad settings (`/icons/README`, directory listing) |
| `3` | Information Disclosure | Pages that reveal internal details (`phpinfo.php`, config files) |
| `4` | Injection (XSS/Script/HTML) | Known scripts vulnerable to cross-site scripting / HTML injection |
| `5` | Remote File Retrieval – Inside Web Root | Reading files inside the website folder that should be private |
| `6` | Denial of Service | Requests that may crash or slow the server (**avoid on production**) |
| `7` | Remote File Retrieval – Server Wide | Reading files anywhere on the server (e.g. `/etc/passwd` via path traversal) |
| `8` | Command Execution / Remote Shell | Known scripts that let an attacker run commands |
| `9` | SQL Injection | Known scripts vulnerable to SQL injection |
| `0` | File Upload | Known scripts that allow uploading files |
| `a` | Authentication Bypass | Ways to get past login checks |
| `b` | Software Identification | Identifying installed software and versions |
| `c` | Remote Source Inclusion | Known scripts vulnerable to remote file inclusion |
| `d` | WebService | Web service / API related tests |
| `e` | Administrative Console | Admin panels and consoles (`/admin/`, `/manager/`) |
| `x` | Reverse tuning | Run everything **except** the listed categories (e.g. `-Tuning x6` = all but DoS) |

### 3.3 Scans performed (`scan.sh`)

| # | Target | Scan name | Options | Why |
|---|---|---|---|---|
| 1 | A – DVWA | basic | (default, all tests) | Baseline on a realistic vulnerable app |
| 2 | B – Misconfigured | basic | (default) | Find all the "before" problems |
| 3 | C – Hardened | basic | (default) | Check the "after" state |
| 4 | A – DVWA | tuned-config | `-Tuning 123b` | Configuration-focused scan |
| 5 | B – Misconfigured | tuned-config | `-Tuning 123b` | Does a focused scan find the same issues with fewer requests? |
| 6 | C – Hardened | tuned-config | `-Tuning 123b` | Same, on the hardened site |
| 7 | A – DVWA | tuned-injection | `-Tuning 49` | Can Nikto find DVWA's SQL injection and XSS? |

`-Tuning 123b` was chosen because the target weaknesses are configuration problems: interesting files (1), misconfiguration (2), information disclosure (3) and software identification (b).

### 3.4 Manual verification (`verify.sh`)

Each important finding was then checked with `curl` (e.g. `curl -I` to read headers, `curl -X TRACE` to test the TRACE method) and in the browser. The output is saved in `results/manual-verification.txt`.

---

## 4. Scan results

All raw output is in `results/` (`.txt` and `.htm` for every scan).

| Scan | Requests | Items reported | Time |
|---|---|---|---|
| A – DVWA, basic | 7,973 | **16** | 4 s |
| A – DVWA, tuned-config (`123b`) | 4,218 | 16 | ~3 s |
| A – DVWA, tuned-injection (`49`) | 1,020 | 8 (**no injection findings**) | 1 s |
| B – Misconfigured, basic | 7,969 | **19** | 4 s |
| B – Misconfigured, tuned-config (`123b`) | 4,214 | 19 | 3 s |
| C – Hardened, basic | 8,137 | **3** | 5 s |
| C – Hardened, tuned-config (`123b`) | 4,292 | 3 | 2 s |

### 4.1 Target A – DVWA

![Nikto basic scan of DVWA](screenshots/05-nikto-basic-dvwa.png)
*Figure 5 – Nikto basic scan of DVWA (16 items)*

Main findings: outdated **Apache/2.4.25**, cookies `PHPSESSID` and `security` without `HttpOnly`, five missing security headers, **directory listing on `/config/` and `/docs/`**, "configuration information may be available remotely" on `/config/`, `/.gitignore` readable, `/icons/README` default file, and `/login.php` identified as a login page.

### 4.2 Target B – Misconfigured

![Nikto basic scan of misconfigured site](screenshots/06-nikto-basic-misconfigured.png)
*Figure 6 – Nikto basic scan of Target B (19 items)*

Nikto found every misconfiguration planted on the site **except** the `.bak` files and the missing `SameSite` cookie flag: full version banner, `X-Powered-By`, cookie without `HttpOnly`, TRACE enabled, missing headers, directory listing on `/files/` and `/backup/`, `phpinfo.php` and `test.php`.

![Nikto tuned scan](screenshots/08-nikto-tuned-config.png)
*Figure 7 – Tuned scan `-Tuning 123b` of Target B: the same 19 items with 4,214 requests instead of 7,969*

**Effect of tuning:** the config-focused scan found **all 19 issues with 47% fewer requests**. Because every weakness on B is a configuration issue, the tests that were skipped (injection, command execution, etc.) had nothing to find. In a real engagement, tuning makes a scan faster, quieter and less likely to disturb the server, but you must choose the categories carefully or you will miss things.

![Nikto HTML report](screenshots/09-nikto-html-report.png)
*Figure 8 – Nikto's HTML report (`results/misconfigured_basic.htm`)*

### 4.3 What Nikto did NOT find in DVWA (key limitation)

DVWA contains SQL injection, XSS, command injection, file inclusion, file upload and CSRF vulnerabilities. Scan 7 used `-Tuning 49` (XSS/injection + SQL injection) and reported **8 items, none of which were injection**. They were the same header, cookie and version findings as the basic scan.

Reasons:
1. Nikto only requests **known vulnerable paths** from its database (e.g. a specific old CMS script). DVWA's vulnerable pages (`/vulnerabilities/sqli/?id=…`) are not in that database.
2. Nikto does **not crawl** the site or **fill in forms** with payloads.
3. DVWA's vulnerable pages are **behind a login** and Nikto scanned without credentials.

Finding SQL injection or XSS in DVWA needs an application scanner (OWASP ZAP, Burp Suite), a dedicated tool (sqlmap) or manual testing. **A clean Nikto report does not mean an application is secure.**

---

## 5. Findings table

Risk levels are an independent rating, based on how easily the issue can be exploited and what an attacker gains. They are not Nikto's opinion (Nikto does not rate risk). OWASP categories use the **OWASP Top 10:2021**.

### 5.1 Target B – Misconfigured site

| # | Finding (Nikto) | What it means | Risk | OWASP Top 10:2021 | Recommended fix | Fixed on C? |
|---|---|---|---|---|---|---|
| B1 | `/backup/` directory listing exposes `config.php.bak` *(file itself found manually)* | A backup of a config file is served as plain text, revealing the **database username and password** | **High** | A05 Security Misconfiguration | Delete backup files from the web root; keep backups outside it; block `*.bak`, `*.old`, `*.swp` | ✅ |
| B2 | `/phpinfo.php` – output from `phpinfo()` found | Shows PHP version, modules, server paths, kernel version and environment variables, making it easy for an attacker to plan an attack | **Medium** | A05 Security Misconfiguration | Delete `phpinfo.php` (and any debug pages) before deployment | ✅ |
| B3 | `/files/` – directory indexing found (CWE-548) | Anyone can browse the folder and download every file, including "internal use only" documents | **Medium** | A01 Broken Access Control / A05 | `Options -Indexes`; add an index page; store private files outside the web root | ✅ (403) |
| B4 | Cookie `PHPSESSID` created without the `httponly` flag | JavaScript can read the session cookie, so an XSS bug elsewhere could steal sessions (session hijacking) | **Medium** | A07 Identification & Authentication Failures | `session.cookie_httponly = 1`, plus `cookie_secure = 1` and `cookie_samesite = Strict` | ✅ |
| B5 | HTTP `TRACE` method active (XST) | The server echoes the request back, which can reveal headers/cookies (Cross-Site Tracing). Modern browsers block TRACE from scripts, so real impact is limited | **Low** | A05 Security Misconfiguration | `TraceEnable Off` | ✅ (405) |
| B6 | `Server: Apache/2.4.68 (Debian) PHP/8.2.34` and on error pages | Exact versions help an attacker look up known vulnerabilities (reconnaissance) | **Low** | A05 Security Misconfiguration | `ServerTokens Prod`, `ServerSignature Off` | ✅ |
| B7 | `X-Powered-By: PHP/8.2.34` | Same as B6, for PHP | **Low** | A05 Security Misconfiguration | `expose_php = Off` | ✅ |
| B8 | Missing `Content-Security-Policy` | No browser-side protection to limit where scripts can load from, so XSS is easier to exploit | **Low** | A05 Security Misconfiguration | Add a CSP header, e.g. `default-src 'self'` | ✅ |
| B9 | Missing `X-Content-Type-Options` | The browser may "sniff" and run a file as a different type than intended | **Low** | A05 Security Misconfiguration | `X-Content-Type-Options: nosniff` | ✅ |
| B10 | Missing `X-Frame-Options` (reported as "X-Frame-Options is deprecated") | The site can be put in an invisible frame on another site (clickjacking) | **Low** | A05 Security Misconfiguration | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` | ✅ |
| B11 | Missing `Referrer-Policy` | Full URLs (possibly with tokens) are sent to other sites in the `Referer` header | **Low** | A05 Security Misconfiguration | `Referrer-Policy: strict-origin-when-cross-origin` | ✅ |
| B12 | `/test.php` – "might be interesting" | A leftover test script; harmless here (prints "test ok") but shows poor deployment hygiene | **Low** | A05 Security Misconfiguration | Remove test files before deployment | ✅ |
| B13 | `index.php.bak` *(missed by Nikto, found manually)* | The page's PHP **source code** can be downloaded and read | **Medium** | A05 Security Misconfiguration | Delete; block backup extensions | ✅ |
| B14 | Missing `Permissions-Policy` | Browser features (camera, microphone, location) are not explicitly restricted | **Info** | A05 Security Misconfiguration | `Permissions-Policy: camera=(), microphone=(), geolocation=()` | ❌ (remaining) |
| B15 | Missing `Strict-Transport-Security` | Only meaningful over HTTPS (see 6.2) | **Info (N/A)** | A02 Cryptographic Failures | Enable HTTPS, then add HSTS | ❌ (N/A on HTTP) |
| B16 | PHP/8.2.34 "appears to be outdated" | Partly false positive (see 6.2) | **Info** | A06 Vulnerable & Outdated Components | Plan upgrade to a newer PHP branch before 8.2 end-of-life | ❌ |
| B17 | "Valid response with junk HTTP methods" | False positive (see 6.2) | **Info** | – | None needed | ❌ |

### 5.2 Target A – DVWA

| # | Finding (Nikto) | What it means | Risk | OWASP Top 10:2021 | Recommended fix |
|---|---|---|---|---|---|
| A1 | `/config/`: directory indexing + "configuration information may be available remotely" | Manual check: `config.inc.php.dist` is readable as plain text and contains **`db_user root` / `db_password p@ssw0rd`** | **High** | A05 Security Misconfiguration | Disable listing; move config out of the web root; never use the DB root account; change default passwords |
| A2 | `Apache/2.4.25` appears to be outdated (current ≥ 2.4.68) | Released in 2016; many published CVEs since then, e.g. CVE-2019-0211 (local privilege escalation, affects 2.4.17–2.4.38) | **High** | A06 Vulnerable & Outdated Components | Update to the current Apache 2.4 release; patch regularly |
| A3 | Cookies `PHPSESSID` and `security` without `httponly` | Session cookie can be stolen through XSS (and DVWA *has* XSS) | **Medium** | A07 Identification & Authentication Failures | Set `HttpOnly`, `Secure`, `SameSite` |
| A4 | `/docs/` directory indexing | Documentation folder can be browsed | **Low** | A05 Security Misconfiguration | `Options -Indexes`; remove docs from production |
| A5 | `/.gitignore` file found | Reveals file names the developers wanted to hide (`config/config.inc.php`) | **Low** | A05 Security Misconfiguration | Do not deploy `.git*` files; block dot-files in Apache |
| A6 | Missing CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy | As B8–B11 | **Low** | A05 Security Misconfiguration | Add security headers |
| A7 | `/icons/README` – Apache default file | Confirms Apache and that default files were not cleaned up | **Info** | A05 Security Misconfiguration | Remove the `/icons/` alias or the default file |
| A8 | `/login.php` – admin login page found | Just tells an attacker where to log in; brute-force target | **Info** | A07 Identification & Authentication Failures | Rate limiting / account lockout, strong passwords, MFA |
| A9 | *(not found by Nikto)* SQLi, XSS, command injection, CSRF … | DVWA's main vulnerabilities, completely missed | **High** (in reality) | A03 Injection, A01, A07 … | Requires application testing (ZAP/Burp/sqlmap) |

> **Note on OWASP Top 10:2025:** In the 2025 edition, *Security Misconfiguration* moved up to **A02**, and *Vulnerable and Outdated Components* is part of **A03 Software Supply Chain Failures**. The mapping above uses the 2021 numbering because it is the version most widely referenced.

---

## 6. Manual verification and false positives

> Every finding from an automated scanner is a **claim**, not a fact.
> - **True positive** – Nikto reported it and it is real.
> - **False positive** – Nikto reported it but it is not a real problem.
> - **False negative** – a real problem Nikto did not report.

All checks are in `verify.sh`; output in `results/manual-verification.txt`.

### 6.1 Confirmed findings (true positives)

**Headers – B vs C** (`curl -I`):

![curl headers comparison](screenshots/10-curl-headers-compare.png)
*Figure 9 – `curl -I` on B (top) leaks versions and sets a cookie without flags; C (bottom) sends only `Server: Apache`, four security headers and a cookie with `secure; HttpOnly; SameSite=Strict`*

```
B:  Server: Apache/2.4.68 (Debian) PHP/8.2.34
    X-Powered-By: PHP/8.2.34
    Set-Cookie: PHPSESSID=65b6...; path=/

C:  Server: Apache
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
    Referrer-Policy: strict-origin-when-cross-origin
    Set-Cookie: PHPSESSID=e842...; path=/; secure; HttpOnly; SameSite=Strict
```

**TRACE** (`curl -X TRACE`): B → `200 OK` with `Content-Type: message/http` (request echoed back) ✅ confirmed. C → `405 Method Not Allowed`.

**Directory listing:**

![Directory listing on B](screenshots/11-directory-listing-b.png)
*Figure 10 – "Index of /files" on Target B, listing internal documents and the full server version at the bottom*

![Directory listing blocked on C](screenshots/12-directory-listing-blocked-c.png)
*Figure 11 – The same URL on Target C returns 403 Forbidden*

**phpinfo():**

![phpinfo on B](screenshots/13-phpinfo-b.png)
*Figure 12 – `phpinfo.php` on Target B reveals PHP 8.2.34, the Linux kernel version and the CPU architecture*

**Leftover backup file (false negative – Nikto did not report this file):**

![Backup file on B](screenshots/14-backup-file-b.png)
*Figure 13 – `curl` retrieves `backup/config.php.bak` with the database password*

When opened in a browser this file is **downloaded** rather than displayed. Apache picks the `Content-Type` from the file extension using `/etc/mime.types`, which maps `.bak` to `application/x-trash`. The browser cannot display that type, so it downloads it. **This does not make it safer**: the attacker still receives the whole file. The important point is that `.bak` is not `.php`, so Apache **does not run it through PHP** and sends the source code as-is.

**DVWA configuration file:**

![DVWA config exposed](screenshots/15-dvwa-config-exposed.png)
*Figure 14 – `config.inc.php.dist` in DVWA's listable `/config/` folder exposes the database root password*

Nikto only said "Configuration information **may** be available remotely". Manual verification showed it is a **High** risk: database credentials for the `root` account. The real `config.inc.php` returns 0 bytes because PHP executes it; the `.dist` copy is served as text. This shows why manual verification is needed to rate risk correctly.

**`/.gitignore` on DVWA:** readable; reveals `config/config.inc.php` and `Dockerfile` ✅ confirmed (low impact).

### 6.2 False positives and misleading findings

| Nikto finding | Manual check | Verdict | Explanation |
|---|---|---|---|
| "Web Server returns a valid response with **junk HTTP methods**" (B and C) | `curl -X FOOBAR` → `200` on both | **False positive** | Apache passes any method name to `index.php`, which just returns the page. No data is changed or exposed. Nikto itself warns this "may cause false positives". |
| "Suggested security header missing: **strict-transport-security**" (C) | Site is plain HTTP only | **Not applicable** | HSTS tells browsers "always use HTTPS for this site". Browsers **ignore** HSTS on plain-HTTP responses, so it has no effect here. It becomes a real finding once HTTPS is enabled. |
| "**PHP/8.2.34** appears to be outdated (current is at least 8.5.8)" (B) | 8.2.34 is the patch release shipped in the current official `php:8.2-apache` image | **Partly false positive** | Nikto only compares with the newest version number. 8.2 still receives security fixes, but the branch is near end-of-life (31 Dec 2026), so an upgrade should be planned. |
| "**X-Frame-Options header is deprecated**…" (B and DVWA) | `curl -I` shows these sites send **no** X-Frame-Options at all | **Misleading wording** | The real issue is that the header is **missing** (clickjacking protection absent). It did not appear on C, which does send the header. |
| `/test.php` "This might be interesting" (B) | Prints "test ok" | **True but low impact** | Real leftover file, but it does not reveal anything sensitive. |
| "X-Content-Type-Options header is not set" **and** "Suggested security header missing: x-content-type-options" | Same header | **Duplicate** | One problem reported twice by two different Nikto plugins, so the raw "items reported" count overstates the number of distinct problems. |

### 6.3 False negatives (missed by Nikto)

| Missed issue | How it was found | Why Nikto missed it |
|---|---|---|
| `/index.php.bak` – source code readable | `curl` / knowledge of the site | Nikto only tests backup names in its database; it does not guess `.bak` versions of every file by default |
| `/backup/config.php.bak` – DB password readable | Following the `/backup/` directory listing | Nikto reported the listing but did not open or analyse the files inside it |
| Session cookie missing `Secure` and `SameSite` | `curl -I` | Nikto only checks for `HttpOnly` |
| DVWA SQL injection, XSS, command injection, CSRF | Known DVWA design | Nikto does not crawl, log in or fuzz parameters (Section 4.3) |

---

## 7. Before vs after: misconfigured vs hardened

![Nikto basic scan of hardened site](screenshots/07-nikto-basic-hardened.png)
*Figure 15 – Nikto basic scan of Target C (hardened): only 3 items*

![Before vs after](screenshots/16-before-after.png)
*Figure 16 – Before (Target B) vs after (Target C) Nikto results*

| Check | Before – Target B | After – Target C | Fix that worked |
|---|---|---|---|
| Items reported by Nikto | **19** | **3** | All of the below |
| `Server` header | `Apache/2.4.68 (Debian) PHP/8.2.34` | `Apache` | `ServerTokens Prod` |
| Version on error pages | Yes | No | `ServerSignature Off` |
| `X-Powered-By` | `PHP/8.2.34` | Not sent | `expose_php = Off` |
| Cookie flags | none | `secure; HttpOnly; SameSite=Strict` | `php.ini` session settings |
| TRACE | 200 (enabled) | 405 (blocked) | `TraceEnable Off` |
| `/files/` listing | 200 – listing shown | 403 Forbidden | `Options -Indexes` |
| `/backup/`, `phpinfo.php`, `test.php`, `*.bak` | 200 – exposed | 404 – not present | Leftover files not deployed |
| X-Frame-Options | missing | `DENY` | `mod_headers` |
| X-Content-Type-Options | missing | `nosniff` | `mod_headers` |
| Content-Security-Policy | missing | `default-src 'self'; frame-ancestors 'none'` | `mod_headers` |
| Referrer-Policy | missing | `strict-origin-when-cross-origin` | `mod_headers` |

**The 3 remaining items on Target C:**

1. **Junk HTTP methods**: false positive (6.2).
2. **Strict-Transport-Security missing**: not applicable without HTTPS (6.2).
3. **Permissions-Policy missing**: a real but informational finding. It could be fixed by adding one more line to `target-c-hardened/security.conf`:
   ```apache
   Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
   ```

So **every real Low-to-High risk issue found on Target B was eliminated on Target C**, using only configuration changes and by not deploying leftover files, with no change to the website code.

**What hardening could not do:** `ServerTokens Prod` still reveals that the server is *Apache*. Hiding it entirely needs a reverse proxy or a module such as ModSecurity. This is acceptable: the aim is to stop revealing **exact versions**, which is what attackers use to match known CVEs.

---

## 8. Conclusion

This assessment used Nikto 2.6.1 to scan three locally hosted targets: DVWA, a deliberately misconfigured Apache/PHP site and a hardened copy of the same site.

**What Nikto did well:**
- In about **4 seconds per target** it found almost every server-level misconfiguration planted on Target B: version banners, missing security headers, a cookie without `HttpOnly`, TRACE, directory listing and leftover debug pages.
- On DVWA it flagged an outdated Apache version and a listable `/config/` folder that, on manual inspection, exposed **database root credentials**.
- The before/after comparison (**19 → 3 items**, with the remaining 3 being a false positive, a not-applicable item and an informational item) gives clear, measurable evidence that the hardening worked.
- `-Tuning 123b` found the same 19 issues with **47% fewer requests**, showing how tuning makes scans faster and quieter.

**What Nikto cannot do:**
- It produced **false positives** (junk methods, HSTS on HTTP, "outdated" PHP 8.2.34), **misleading** wording (X-Frame-Options "deprecated" when it is missing) and **duplicate** findings.
- It produced **false negatives**: two readable `.bak` files (one containing a password) and missing `Secure`/`SameSite` cookie flags.
- It found **none** of DVWA's SQL injection or XSS vulnerabilities, because it does not crawl, log in or test the application's own inputs.

**Key lessons:**
1. Nikto is a fast, useful **first step** for finding server **misconfigurations** (OWASP A05) and **outdated components** (A06), but it is not a complete vulnerability assessment.
2. **Every finding must be verified manually**, both to remove false positives and to rate the real risk (the DVWA `/config/` finding went from "may be available" to High).
3. Most of the problems found are fixed by **secure configuration and clean deployment**, not by code changes: `ServerTokens Prod`, `ServerSignature Off`, `-Indexes`, `TraceEnable Off`, security headers, cookie flags and removing leftover files.
4. Application-level flaws require application-level tools such as **OWASP ZAP** or **Burp Suite**, plus manual testing and secure coding.
5. Only scan systems you **own or have written permission** to test.

---

## 9. How to reproduce

```bash
# 1. Start the three targets (localhost only)
docker compose up -d --build

# 2. Run all Nikto scans (results/ gets .txt and .htm files)
./scan.sh

# 3. Manually verify the findings
./verify.sh | tee results/manual-verification.txt

# 4. Stop the lab when finished
docker compose down
```

**Project structure**

```
.
├── README.md                     ← this report
├── viva_notes.md                 ← viva questions + line-by-line explanations
├── docker-compose.yml            ← defines and starts targets A, B, C
├── scan.sh                       ← runs the 7 Nikto scans
├── verify.sh                     ← curl checks for manual verification
├── site/                         ← shared website code (used by B and C)
├── target-b-misconfigured/       ← Dockerfile, insecure security.conf + php.ini, leftovers/
├── target-c-hardened/            ← Dockerfile, hardened security.conf + php.ini
├── results/                      ← Nikto output (.txt/.htm) + manual verification
└── screenshots/                  ← evidence screenshots used in this report
```

---

## 10. References

- Nikto – https://github.com/sullo/nikto and https://cirt.net/Nikto2
- OWASP Top 10:2021 – https://owasp.org/Top10/
- OWASP Secure Headers Project – https://owasp.org/www-project-secure-headers/
- OWASP Cross-Site Tracing – https://owasp.org/www-community/attacks/Cross_Site_Tracing
- MDN – Set-Cookie (HttpOnly, Secure, SameSite) – https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
- Apache HTTP Server documentation – `ServerTokens`, `ServerSignature`, `Options`, `TraceEnable`, `mod_headers` – https://httpd.apache.org/docs/2.4/
- CWE-548: Exposure of Information Through Directory Listing – https://cwe.mitre.org/data/definitions/548.html
- DVWA – https://github.com/digininja/DVWA
- OWASP ZAP – https://www.zaproxy.org/ ; Burp Suite – https://portswigger.net/burp
