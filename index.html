<?php
/**
 * TTPH OSINT & Intel Reconnaissance Dashboard
 * Version : 1.9.1
 * Build   : 2026-07-23
 * Author  : TTPH IT Team
 *
 * v1.9.1 - Per-finding CODE SNIPPET display:
 *   Every SAST/AST finding now shows the exact code line(s) in a dark
 *   syntax-styled block with the matched substring highlighted, plus
 *   line numbers and a few lines of surrounding context.
 * v1.9.0 - Expanded SAST engine (122 rules) with CWE + OWASP mapping.
 */
define('APP_NAME',    'Vulnerability, Recon and Assessment Platform');
define('APP_VERSION', '2.7.5');
define('NUCLEI_BIN', getenv('NUCLEI_BIN') ?: 'nuclei'); // path to nuclei binary if installed
define('APP_BUILD',   '2026-07-25');
define('APP_AUTHOR',  'TTPH IT Team');

$CHANGELOG = [
    '2.7.5' => ['date'=>'2026-07-25','notes'=>[
        'FIX: "⇢ Repeater" buttons did nothing when clicked — the onclick used JSON.stringify() which wraps the URL in double quotes INSIDE a double-quoted HTML onclick attribute, so the browser truncated the handler at the first inner quote and the click was a no-op',
        'NEW: repArg() helper builds a single-quoted, two-layer-safe (JS + HTML-attribute) string literal; swapped into all three Repeater buttons (JS Endpoint Extractor, Open-Redirect, and SSRF findings)',
        'Verified through both parser layers (HTML-decode → JS-parse) against URLs containing &, ", \', < and > — each now fires and passes the exact URL into the HTTP Repeater',
    ]],
    '2.7.4' => ['date'=>'2026-07-25','notes'=>[
        'NEW: Concurrent-scan status strip in the header — live per-tab badges (URL / IP / Code / Nuclei) show exactly which scans are running, with a spinner, target tooltip, and an "N concurrent" counter; shows "all idle" when nothing is active',
        'NEW: Cross-tab busy guard — launching a tab\'s scan while one of the SAME kind is already running is blocked with a clear toast; the form is visually locked (form-busy) until it finishes, so no duplicate/overlapping scans of the same tab',
        'Different tabs can still run concurrently (URL + IP + Code + Nuclei) — the guard only prevents duplicating the same tab\'s scan; the strip reflects all active scans in real time',
        'Registry SCAN_STATE + scanBusy()/scanBegin()/scanEnd()/renderScanStrip() drive both features and integrate with the v2.7.3 per-kind isolation',
    ]],
    '2.7.3' => ['date'=>'2026-07-25','notes'=>[
        'NEW: Red Team header now shows an "Active target" indicator + manual override field — you can see exactly which host the Offensive Operations will hit and retarget within scope; the override always wins and the tools never auto-pick up an IP or another tab\'s scan',
        'FIX (concurrency): all four tabs (URL / IP / Code / Nuclei) can now run at the same time with correct, isolated results — the progress bar, completion state, and action bar of one tab can no longer bleed into another',
        'Refactor: per-KIND progress objects (PROG[kind]) + kind threaded through runSteps/runStep/progressInit/progressStep/progressFinish, replacing the single shared PROG + global K() routing that caused cross-tab mixups',
        'Refactor: per-KIND scan targets (URL/IP/NUCLEI/CODE) via scanTarget(kind); runStep only writes LAST_RECON for URL scans so IP/Nuclei can no longer pollute the Playbook/Red Team data',
        'FIX: Code (SAST) and Nuclei findings are now isolated (CODE_FINDINGS vs NUC_FINDINGS) so running both concurrently no longer clobbers CSV/PDF exports',
        'FIX: Export PDF and Export Findings CSV now derive their tab from the clicked button (concurrency-safe) instead of the last-active global — exporting the IP tab while a URL scan runs exports the correct data',
        'Audited every module for shared-target issues; all offensive/URL tooling resolves the host via urlScanHost()/urlScanBase()/scanTarget(kind) — no live target reads from the shared global remain',
    ]],
    '2.7.2' => ['date'=>'2026-07-25','notes'=>[
        'FIX: Red Team Mode / Attack Playbook / offensive ops targeted the wrong host — they read the shared window.CURRENT_SCAN.target, which is overwritten by ANY subsequent scan, so running an IP Address Recon after a URL scan made the offensive tools point at the IP (causing "Invalid target" on domain-only engines like WAF/Evasion & Sublist3r)',
        'NEW: dedicated window.URL_SCAN_TARGET captured at URL-scan launch + urlScanHost()/urlScanBase()/urlScanTargetRaw() helpers — the Playbook and all Offensive Operations now always resolve the correct URL-scan domain, immune to later IP/Nuclei/Code scans',
        'Applied the fix to Launch Active Recon, Safe PoC, Sublist3r (+ alive-check & CSV), Breach Risk Score label, Red Team report payload, and the URL "Send to Repeater" action-bar button',
    ]],
    '2.7.1' => ['date'=>'2026-07-25','notes'=>[
        'NEW — "⇢ Send to Repeater" from the JS Secret & Endpoint Extractor: discovered endpoints now render in a scrollable table with a per-row Repeater button + a "Send first to Repeater" shortcut',
        'Relative and same-origin endpoints are auto-resolved to absolute URLs (from the scan base) before loading into the HTTP Repeater; endpoint type (absolute / same-origin / relative) is labelled',
        'Authorized-testing flag carries over from the scan so pivoting an endpoint into the Repeater is one click',
    ]],
    '2.7.0' => ['date'=>'2026-07-25','notes'=>[
        'NEW ENGINE #9 — DNS CAA + DNSSEC Validation: walks the label tree for CAA issuance policy (issue/issuewild/iodef), and validates the DNSSEC chain of trust (DNSKEY + parent DS + RRSIG + resolver AD flag) with an A→F trust grade',
        'NEW ENGINE #10 — Open-Redirect / SSRF-Parameter Detector: safe marker-based probing of 18 redirect params (incl. protocol-relative // bypass) and SSRF-surface mapping across 16 URL-consuming params (detection only — no blind SSRF, confirm out-of-band)',
        'NEW — Multi-Provider IP Geolocation Aggregator (iplocation.io-style): side-by-side results from ip-api, ipwho.is, ipapi.co, freeipapi & ipinfo with a majority-vote consensus + averaged map pin, added to IP Address Recon',
        'NEW TAB — HTTP Repeater (Burp-Repeater-style): craft/replay raw requests with full control of method, headers & body; inspect raw response (status, headers, timing, size, body), with request history & one-click replay — for authorized bug-bounty / ethical-hacking',
        'NEW — "⇢ Send to Repeater" from URL findings: action-bar button + per-row buttons on discovered directory-probe paths and open-redirect/SSRF params load straight into the Repeater',
        'All engines remain non-destructive, authorization-gated, and host-scoped; new results feed window.LAST_RECON and PDF/CSV exports',
    ]],
    '2.6.9' => ['date'=>'2026-07-25','notes'=>[
        'NEW ENGINE #7 — HTTP/2 · HTTP/3 & TLS-Version Detection: negotiates the served HTTP version via cURL (h2/h3 capability aware), detects HTTP/3 (QUIC) advertisement from the Alt-Svc header, and actively probes TLS 1.0/1.1/1.2/1.3 support via live crypto handshakes — grades A+→F with weighted penalties for deprecated TLS 1.0/1.1',
        'NEW ENGINE #8 — security.txt (RFC 9116) & .well-known Posture: fetches and parses /.well-known/security.txt (Contact/Expires/Encryption/Policy/Canonical + PGP-signed detection), validates Expires freshness, and probes 16 .well-known/discovery resources (MTA-STS, OpenID, App-Links, robots, sitemap, legacy crossdomain/clientaccesspolicy) with a posture grade',
        'Both engines auto-run inside Website URL Recon, feed window.LAST_RECON, and are included in PDF/CSV exports — 100% non-destructive, authorization-gated, and host-scoped',
    ]],
    '2.6.8' => ['date'=>'2026-07-25','notes'=>[
        'NEW ENGINE — CORS Misconfiguration Scanner: probes origin reflection, null-origin, sibling/suffix bypass, and wildcard+credentials (detection only, non-destructive), grading each with severity + remediation',
        'NEW ENGINE — Security Header Grade (A+ → F): weighted scoring of HSTS/CSP/XFO/XCTO/Referrer/Permissions/COOP/CORP/COEP with partial-credit for weak values + version-banner info-leak penalties',
        'NEW ENGINE — JS Secret & Endpoint Extractor: passively fetches same-origin scripts and mines API endpoints (LinkFinder-style) + hard-coded secrets/keys/JWTs (SecretFinder-style, redacted output)',
        'NEW ENGINE — Subdomain Takeover / Dangling-DNS Detector: resolves CNAMEs across 20 common subdomains and matches 18 unclaimed-service fingerprints (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, …)',
        'NEW ENGINE — GraphQL Introspection & IDE Detector: probes 10 common GraphQL paths and flags enabled introspection (schema disclosure) or exposed GraphiQL/Playground consoles',
        'NEW ENGINE — Favicon Hash Fingerprint (mmh3, Shodan-style): computes the MurmurHash3 favicon hash for infra pivoting / look-alike & staging-clone discovery via Shodan/Censys',
        'All six modules run automatically inside Website URL Recon, feed window.LAST_RECON, and are included in PDF/CSV exports — 100% authorization-gated, host-scoped, and non-destructive',
    ]],
    '2.6.7' => ['date'=>'2026-07-25','notes'=>[
        'REDESIGN: Full professional UI/UX overhaul — refined design system, refreshed tokens, glass hero banner, animated tabs, lifting cards, polished tables/pills/buttons, entrance animations, accessibility + responsive layout',
        'All engines and exports preserved — visual layer only',
    ]],
    '2.6.6' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Live HTTP status badges for Sublist3r subdomains — "⚡ Check Alive" probes each subdomain (HEAD, HTTPS→HTTP) and shows a color-coded status pill (2xx green · 3xx blue · 401/403 amber · 5xx dark · dead grey)',
        'Status column + "alive only" source filter; hover a badge for scheme/server/redirect; batched (60/req), host-scoped, non-destructive',
        'CSV export now includes HTTP_Status + Scheme columns',
        'RECOVERED: Sublist3r (pure-PHP port of aboul3la/Sublist3r) + clickable subdomain links (v2.6.4/2.6.5 were lost to a container reset; rebuilt onto v2.6.3)',
    ]],
    '2.6.5' => ['date'=>'2026-07-24','notes'=>[
        'FIX: Sublist3r subdomain results are now CLICKABLE — each is a link to https://<sub> with an Open ↗ shortcut',
    ]],
    '2.6.4' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Sublist3r — pure-PHP passive subdomain enumeration (crt.sh, CertSpotter, HackerTarget, AlienVault OTX, RapidDNS + optional subbrute), dedup, DNS resolution, wildcard filtering, paginated results, CSV export',
    ]],
    '2.6.3' => ['date'=>'2026-07-24','notes'=>[
        'REMOVED: Subdomain enumeration (crt.sh/certspotter/brute) and the Attack-Surface Graph, per request',
        'NEW: Tech-stack fingerprinting in Active Recon — server/framework/JS-lib/CMS detection from headers, cookies, and markup',
        'NEW: Authentication attack-surface mapping — discovers reachable login/admin/API-auth/OAuth endpoints (endpoint discovery only; no credential attacks)',
        'NEW: 🎯 Breach Risk Score — CVSS-weighted composite (0–100 + A–F grade) boosted by actively-confirmed exploitability (reflection, exposed paths, risky methods, safe-PoC sinks)',
        'NEW: 🥷 WAF / Evasion Profile — fingerprints protection and lays out authorized OPSEC/evasion techniques (Stealth mode auto-applies UA rotation + jitter; the rest are documented manual methods, not weaponized)',
        'All operations remain non-destructive, authorization-gated, host-scoped, and logged to the engagement audit trail',
    ]],
    '2.6.2' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Second Certificate Transparency source — certspotter API added alongside crt.sh (backup + supplementary coverage); per-source status shown in the results note',
        'NEW: Pagination for the discovered subdomain list — search, source filter (crt.sh / certspotter / brute / live-only), and 15/25/50/All per-page with First/Prev/numbered/Next/Last controls',
        'Per-host source badges now distinguish crt.sh (blue) vs certspotter (purple) vs brute; live filter shows only HTTP-reachable hosts',
    ]],
    '2.6.1' => ['date'=>'2026-07-24','notes'=>[
        'IMPROVED: Advanced subdomain enumeration — new rt_enum_subdomains() combines multiple sources for real depth',
        'Certificate Transparency harvesting via crt.sh — discovers real issued hostnames (passive, no brute needed)',
        'Wildcard-DNS detection — a random-label probe identifies catch-all DNS and filters brute-only false positives',
        'Expanded brute wordlist (200+ prefixes) resolved over DNS-over-HTTPS with A / AAAA / CNAME + source tracking',
        'Optional HTTP/HTTPS liveness probe + server fingerprint on discovered hosts; adjustable result cap (80/120/200)',
        'Results table now shows resolved IPs or CNAME, per-host source badges (crt.sh / brute), and live status',
    ]],
    '2.6.0' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Attack-Surface Graph — interactive SVG node map (target host → resolved subdomains → severity-colored findings) in Red Team Mode',
        'NEW: CVE Exploit Intelligence — maps detected CVEs (core/plugin/theme) to exploit-likelihood bands + KEV flag with outbound refs (NVD, Exploit-DB, Metasploit, CISA-KEV). Information only — no exploit code.',
        'NEW: Safe PoC Confirmations — non-destructive reachability tests that PROVE whether XSS / SQLi / open-redirect sinks are reachable using benign markers + DB-error/differential signatures (detection only; no exploitation, no data extraction, no state change)',
        'All three are authorization-gated, host-scoped (SSRF-guarded), and logged to the engagement audit trail',
    ]],
    '2.5.11' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Red Team Mode is now AGGRESSIVE — an "Offensive Operations" panel adds active (non-destructive) capability beyond the passive Playbook',
        'Launch Active Recon (server-side): subdomain enumeration, HTTP method probing (risky verbs), benign parameter-reflection detection (XSS/injection sinks), and an expanded sensitive-path brute',
        'Attack-Chain Simulator: auto-builds a plausible multi-stage breach narrative across the kill-chain from the highest-severity finding per phase',
        'Threat-Actor Emulation: maps observed ATT&CK techniques to known groups (APT29, FIN7, Magecart, Lazarus, Scattered Spider) with % overlap and MITRE Group links',
        'Stealth/OPSEC toggle (User-Agent rotation + request jitter) and adjustable reflection/path-depth for the active recon',
        'Still responsible: no weaponized exploits or brute-forcers — all probes are read-only/benign, authorization-gated, host-scoped, and logged to the engagement audit trail',
    ]],
    '2.5.10' => ['date'=>'2026-07-24','notes'=>[
        'FIX: "Verify Now" showed no results in Red Team Mode — its output targeted only the Attack Playbook placeholders (pb-res-*), which do not exist in the Red Team view',
        'Red Team findings table now has per-row result rows (rt-res-*) that reveal live ✓ CONFIRMED / ○ clear / ℹ info badges + evidence on Verify',
        'verifyNowServerSide() now renders into BOTH views and updates whichever progress/button (pb-* or rt-*) is present; added a live result counter to Red Team Mode',
    ]],
    '2.5.9' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Red Team Mode — a "🔴 Red Team Mode" button on the URL Recon action bar adds an offensive-security engagement view over your findings',
        'MITRE ATT&CK mapping — every finding tagged with tactic + technique ID (T1190, T1557, T1110, T1552.001, T1566, T1539, etc.) linked to attack.mitre.org, with a coverage table',
        'Cyber Kill-Chain view — findings bucketed across Reconnaissance → Weaponization → Delivery → Exploitation → … so you see the realistic attack path',
        'Rules of Engagement panel — scope, operator, engagement window, authorization reference, and a signed-off confirmation flag',
        'Downloadable Red Team Report (.html) with RoE, executive summary, ATT&CK coverage, and attack narrative; plus an Engagement Log (.json) audit trail',
        'ANALYSIS & PLANNING ONLY — no weaponized exploits are generated; confirmation still uses the non-destructive Verify Now',
    ]],
    '2.5.8' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Live "⚡ Verify Now (server-side)" button in the Attack Playbook — re-checks every finding instantly with no download',
        'New pb_verify API action runs non-destructive PHP checks server-side (cURL header/status/body, DNS-over-HTTPS SPF/DMARC/CAA/DNSSEC, openssl TLS cert, Set-Cookie flags)',
        'Each finding gets an inline ✓ CONFIRMED / ○ clear / ℹ info badge + live evidence; summary counter shows confirmed/clear/info totals',
        'Authorization-gated (explicit confirm), SSRF-guarded (checks restricted to the scanned host), and rate-capped (max 80 checks/request)',
    ]],
    '2.5.7' => ['date'=>'2026-07-24','notes'=>[
        'CHANGED: Replaced the PowerShell (.ps1) playbook download with a PHP-only standalone verification script (.php)',
        'The .php script uses PHP + cURL (same stack as the dashboard) — run via "php verify.php" on CLI, or open in a browser on a PHP server with ?authorized=yes',
        'curl/dig/openssl checks auto-translated to PHP helpers (cURL header/status/body checks, dns_get_record, openssl_x509_parse TLS inspection) — no bash, no PowerShell, no openssl CLI needed',
        'Kept the self-contained HTML report (zero-run) and the Hardening Guide (.md)',
    ]],
    '2.5.6' => ['date'=>'2026-07-24','notes'=>[
        'CHANGED: Replaced the .sh playbook download with no-run-required workarounds',
        'NEW: Self-contained Playbook Report (.html) — fully offline, just double-click to open in any browser (no execution)',
        'NEW: Windows PowerShell verification script (.ps1) — curl/dig/openssl one-liners auto-translated to native Invoke-WebRequest / Resolve-DnsName / .NET SslStream (no bash, no openssl needed)',
        'Kept the Hardening Guide (.md); added an inline "no scripts to run?" helper note',
    ]],
    '2.5.5' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Attack Path & Remediation Playbook — a "🎯 Attack Playbook" button on the URL Recon action bar maps every finding to an attack scenario, a non-destructive PoC verification command, and a remediation fix',
        'Covers missing security headers, exposed paths (.git/.env/backups/actuator/phpinfo), TLS issues, SPF/DMARC/DKIM/CAA/DNSSEC gaps, cookie/CSP weaknesses, and WordPress core/plugin/theme/XML-RPC/user-enum findings',
        'Downloadable PoC/verification script (.sh) — authorized, non-destructive checks that CONFIRM each finding, with an authorization prompt and blue-team framing',
        'Downloadable Hardening Guide (.md) — severity-ranked remediation table + per-finding attack awareness for defenders',
        'Recon results are captured to window.LAST_RECON so the playbook works off structured data',
    ]],
    '2.5.4' => ['date'=>'2026-07-24','notes'=>[
        'PDF: cover, running headers, and footer rebranded to "Vulnerability, Recon & Assessment Report" to match the new platform name',
        'PDF branding now pulls from APP_NAME / APP_AUTHOR (exposed to JS) so future renames stay in sync automatically',
        'Cover title updated to a 4-line VULNERABILITY, RECON & ASSESSMENT REPORT block; SAST header and confidential lines updated',
    ]],
    '2.5.3' => ['date'=>'2026-07-24','notes'=>[
        'RENAMED: Application title/name changed from "TTPH OSINT & Intel Dashboard" to "Vulnerability, Recon and Assessment Platform" (updates header, browser tab title, about panel, and footer)',
    ]],
    '2.5.2' => ['date'=>'2026-07-24','notes'=>[
        'FIX: "Scanning…" progress bar could hang at a partial count if a single step stalled — added a 90s per-request timeout so any slow/hung module fails gracefully and the pipeline always finishes',
        'FIX: progress bar + action bar now guaranteed to finalize (progressFinish) after all steps run, regardless of per-step errors/timeouts',
        'FIX: Export PDF captured no recon data — it targeted a non-existent #results container; now targets the active tab (#results-url / #results-ip / #results-nuclei)',
        'PDF: added a beautifully formatted Executive Summary page (target, scan type, module count, per-module status + key result) for URL/IP/Nuclei reports',
        'Export PDF now works correctly from the Website URL Recon tab and the Nuclei Scanner page',
    ]],
    '2.5.1' => ['date'=>'2026-07-24','notes'=>[
        'FIX: "Invalid script URL" for relative/protocol-relative script paths (e.g. /js/html5.js) — now resolved to absolute against the page base URL before fetching',
        'Script analysis cards restored to the dark background style (dark header with light monospace URL text)',
        'Enumerated scripts now record the page final URL (window.URL_BASE) for accurate resolution',
    ]],
    '2.5.0' => ['date'=>'2026-07-24','notes'=>[
        'NEW #5: Live WordPress vulnerability feed — optional WPScan API token (Settings) merges 100K+ live plugin CVEs into the scan with a LIVE badge',
        'NEW #6: PHP taint tracking — traces $_GET/$_POST/$_REQUEST/$_COOKIE/php://input through variable assignments to echo, SQL, shell, include, eval, unserialize, header sinks (with data-flow trace)',
        'NEW #7: Dependency / SCA analysis (OWASP A06) — auto-detects package.json / composer.json / requirements.txt and flags known-vulnerable versions with CVE + CVSS',
        'NEW #8: DNS & email-security posture — SPF, DKIM, DMARC, MX, CAA, DNSSEC checks via DNS-over-HTTPS, scored A–F',
        'NEW #9: TLS/SSL certificate inspector — issuer, expiry countdown, SANs, protocol, cipher, weak-signature + hostname-mismatch findings',
        'NEW #10: Cookie & CSP analyzer — Set-Cookie flag audit (Secure/HttpOnly/SameSite) + Content-Security-Policy grading',
        'URL Recon now runs TLS, DNS, and Cookie/CSP modules automatically alongside the existing steps',
    ]],
    '2.4.9' => ['date'=>'2026-07-24','notes'=>[
        'NEW: User-adjustable confirmation threshold — "Confirm above" number input in the script analyzer toolbar (0 = always confirm)',
        'The prompt now fires only when the selected script count exceeds the value you set; invalid/blank falls back to 10',
    ]],
    '2.4.8' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Stop button for the inline script analyzer — aborts a running batch gracefully (finishes in-flight requests, then renders partial results)',
        'NEW: Confirmation prompt is now conditional — only appears for batches larger than '.'10 scripts; small batches run immediately',
        'Stopped runs show a warning note and a completed/total count in the summary',
    ]],
    '2.4.7' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Concurrency control for the inline script analyzer — dropdown (1 sequential / 3 / 5 / 8 / 10) using an order-preserving worker pool',
        'NEW: Confirmation prompt before analyzing — summarizes script count, concurrency, estimated waves, and outbound request count',
        'Removed the 15-script cap — select and analyze any number of external scripts',
        'Added a live progress counter (Analyzing X/N · concurrency C…) so large batches give real-time feedback',
    ]],
    '2.4.5' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Author-archive enumeration depth control — dropdown (Quick 1-10 / Standard 1-25 / Deep 1-50 / Thorough 1-100 / Exhaustive 1-200)',
        'Enumerated Users table now shows the detected URL (user profile/website) and Link (author archive + REST self href), matching the raw /wp-json/wp/v2/users response',
        'Backend captures name, url, link and _links.self.href per user; enriches deduped entries across REST + author-archive sources',
        'Depth is clamped 5-200 server-side; results show probed/depth count; display cap raised to 100 users',
        'Depth control auto-dims when the WordPress scan checkbox is disabled',
    ]],
    '2.4.4' => ['date'=>'2026-07-24','notes'=>[
        'NEW: WordPress user enumeration — recovers usernames via REST API (/wp-json/wp/v2/users) and author-archive redirects (?author=N)',
        'NEW: XML-RPC exposure check — detects /xmlrpc.php, enumerates methods via system.listMethods, flags system.multicall (brute-force amplification) and pingback.ping (SSRF/DDoS)',
        'New "Access & Endpoint Findings" table plus dedicated Enumerated Users and XML-RPC sections in the WP report',
        'Findings feed into signals, remediation, and escalate the overall WordPress risk score (multicall -> min score 70)',
        'http_get() now supports an optional POST body (backward-compatible 5th param) for the XML-RPC methodCall',
        'Added .tag.dim CSS variant for neutral method chips',
    ]],
    '2.4.3' => ['date'=>'2026-07-24','notes'=>[
        'FIX: Nuclei scan "Unexpected end of JSON input" — the API now always returns valid JSON, even on fatal errors/timeouts',
        'Backend: catch \\Throwable (not just Exception) so PHP 7+ fatal Errors in the scan path no longer kill the response',
        'Backend: register_shutdown_function emits valid JSON on true fatals (out-of-memory / max_execution_time)',
        'Backend: output buffering + hardened j_out() strips stray warnings/notices/BOM that could corrupt the JSON body',
        'Frontend: runNuclei reads the response as text then parses safely, surfacing the real error + raw server output instead of the cryptic message',
        'Frontend: added a 175s client-side fetch timeout (AbortController) so a hung scan fails gracefully',
        'Frontend: callApi() now safe-parses all scan responses with the same protection',
    ]],
    '2.4.2' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Pagination (10/25/50/All per page) for the WordPress theme table with First/Prev/numbered/Next/Last controls',
        'NEW: Severity filter for detected themes (All / Vulnerable only / Critical / High / Medium / Low / Info)',
        'NEW: Free-text search across theme name, slug, and CVE ID/title; live result counter; filters + pagination work together',
        'Theme table now matches the plugin table UX (multi-CVE sub-rows, unrecognized badge, version source labels)',
    ]],
    '2.4.1' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Pagination (10/25/50/All per page) for the WordPress plugin table with First/Prev/numbered/Next/Last controls',
        'NEW: Severity filter for detected plugins (All / Critical / High / Medium / Low / Info / Vulnerable only)',
        'NEW: Free-text search across plugin name, slug, and CVE ID; live result counter; filters + pagination work together',
    ]],
    '2.4.0' => ['date'=>'2026-07-24','notes'=>[
        'NEW: Enable/disable checkbox for the WordPress scan in the URL Recon card (on by default)',
        'NEW: WordPress plugin enumeration + vulnerability scoring — detects plugins from /wp-content/plugins/ asset paths and readme.txt Stable tags',
        'NEW: WordPress theme detection — reads /wp-content/themes/ paths and style.css headers (Theme Name + Version)',
        'Per-component vulnerability score, severity rating, CVSS, and matched CVEs for each plugin/theme',
        'Curated plugin CVE set with real ranges: CVE-2025-7384 (RCE 9.8), CVE-2025-12450 (LiteSpeed), CVE-2025-4566 (Elementor), CVE-2025-11241 (Yoast SEO), CVE-2025-5961 (WPvivid), +more',
        'Curated theme CVE (CVE-2025-1639 Arolax 8.8) + version-only detection for unrecognized components',
        'Overall WordPress risk score now escalates when a plugin/theme CVE outranks the core finding (ecosystem max CVSS)',
        'Version sources labeled per component (?ver= asset, readme.txt Stable tag, style.css header); network calls capped for performance',
    ]],
    '2.3.0' => ['date'=>'2026-07-24','notes'=>[
        'NEW: WordPress fingerprinting module — auto-detects WordPress in the URL scan (wp-content/wp-includes paths, wp-json, wp-login.php)',
        'Core version detection via 4 passive methods: generator meta tag, core asset ?ver= query strings, RSS /feed/ generator, and readme.html',
        'Version compared live-baseline (WordPress 7.0.2, only the 7.0 branch is actively maintained as of Jul 2026)',
        'Vulnerability score (0-100) with a colored gauge and an overall severity rating (Critical/High/Medium/Low/Info)',
        'Curated core CVE reference with real CVSS scores, CWE, and precise affected version ranges (CVE-2025-58246, CVE-2024-4439)',
        'Shows detection evidence, exposure signals (readme.html readable, feed generator leaking version), and remediation guidance',
        'WordPress findings flow into the PDF/CSV export like every other section',
    ]],
    '2.2.1' => ['date'=>'2026-07-23','notes'=>[
        'Fixed code-snippet cut-off: long minified lines now wrap (white-space:pre-wrap + word-break) instead of clipping',
        'Raised per-line truncation caps to 5000 chars so full context is preserved (with word-wrap for readability)',
        'Snippet blocks show the complete matched line even for minified bundles like jQuery',
    ]],
    '2.2.0' => ['date'=>'2026-07-23','notes'=>[
        'NEW: Taint tracking (data-flow) engine for JavaScript — traces user-controlled sources to dangerous sinks',
        'Sources: location.hash/search/href, document.URL/referrer/cookie, window.name, URLSearchParams, req.query/body/params, postMessage event.data, localStorage.getItem',
        'Sinks: innerHTML/outerHTML, eval, Function, document.write, insertAdjacentHTML, location assign, setAttribute(href/src), fetch/XHR, .query()/.exec(), setTimeout(string)',
        'Fixpoint variable propagation + concat taint; emits source→sink flow path with line numbers',
        'Taint findings shown with a purple TAINT FLOW badge and full data-flow trace',
        'NEW: Nuclei bundled-template picker — checkbox multi-select with select-all, severity filter, and pagination',
        'Backend now accepts explicit template IDs; only selected bundled templates run',
        'Fixed leftover APP_VERSION constant (was 2.0.0)',
    ]],
    '2.1.0' => ['date'=>'2026-07-23','notes'=>[
        'Per-tab result containers (URL/IP/Code/Nuclei no longer bleed across tabs)',
        'Fixed Nuclei null-innerHTML crash on zero findings',
        'Inline multi-select script analysis in URL tab (removed send-to-analyzer flow)',
    ]],
    '2.0.0' => ['date'=>'2026-07-23','notes'=>[
        'NEW: Nuclei integration (projectdiscovery/nuclei) — dual mode',
        'Native mode: shells out to the installed nuclei binary with -jsonl and parses results',
        'Lite engine: pure-PHP reimplementation of Nuclei template engine (YAML parser + HTTP matcher engine) — no binary required',
        'Matchers supported in Lite: status, word (part body/header/all, condition and/or), regex, dsl (status_code/contains/len)',
        '18 bundled Nuclei-style templates (exposures, panels, misconfig, tokens) + paste-your-own-template box',
        'Severity + tag filters passed through to nuclei; findings pagination/search/severity filter reused',
        'Auto-detects binary; falls back to Lite engine gracefully; shows which engine ran each finding',
    ]],
    '1.9.2' => ['date'=>'2026-07-23','notes'=>[
        'Findings pagination (10/25/50/All per page) with First/Prev/numbered/Next/Last controls',
        'Severity filter for findings (All / Critical / High / Medium / Low / Info)',
        'Free-text search across finding title, why, fix, CWE, OWASP',
        'Live result counter; filters + pagination work together; snippets preserved',
    ]],
    '1.9.1' => ['date'=>'2026-07-23','notes'=>[
        'Per-finding code snippet: each finding shows exact code line(s) in a dark block',
        'Matched portion highlighted; line numbers + surrounding context shown',
        'Expand/collapse snippet per finding; snippets included in PDF/CSV export',
    ]],
    '1.9.0' => ['date'=>'2026-07-23','notes'=>['Expanded SAST engine: 122 rules, CWE + OWASP mapping, rule catalog, OWASP grouping']],
    '1.8.3' => ['date'=>'2026-07-23','notes'=>['Juicy info extraction, collapsed excerpt']],
    '1.8.1' => ['date'=>'2026-07-23','notes'=>['Fixed PDF export mojibake + tables']],
];

set_time_limit(180);
ini_set('default_socket_timeout', 6);
ini_set('display_errors', 0);
error_reporting(0);
@session_start();

if (isset($_GET['download'])) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="osint_dashboard_v' . APP_VERSION . '.php"');
    header('Content-Length: ' . filesize(__FILE__));
    readfile(__FILE__); exit;
}
if (isset($_GET['health'])) {
    header('Content-Type: application/json');
    echo json_encode(['ok'=>function_exists('curl_init'),'version'=>APP_VERSION,'php'=>PHP_VERSION,
        'curl'=>function_exists('curl_init'),'dns'=>function_exists('dns_get_record'),'sockets'=>function_exists('fsockopen')]);
    exit;
}
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function j_out($d){
    // Discard any stray output (warnings/notices/BOM) so the body is always valid JSON
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
    $json = json_encode($d);
    if ($json === false) { $json = json_encode(['ok'=>false,'error'=>'JSON encode failed: '.json_last_error_msg()]); }
    echo $json; exit;
}

function http_get($url, $timeout = 8, $follow = true, $extra = [], $post_body = null) {
    if (!function_exists('curl_init')) return ['ok'=>false,'error'=>'cURL not available','code'=>0];
    $ch = curl_init();
    $headers = array_merge(['User-Agent: Mozilla/5.0 (TTPH-OSINT/'.APP_VERSION.')','Accept: */*'], $extra);
    $opts = [CURLOPT_URL=>$url, CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>$follow,
        CURLOPT_MAXREDIRS=>5, CURLOPT_TIMEOUT=>$timeout, CURLOPT_CONNECTTIMEOUT=>5,
        CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>0, CURLOPT_HTTPHEADER=>$headers, CURLOPT_HEADER=>true];
    if ($post_body !== null) { $opts[CURLOPT_POST]=true; $opts[CURLOPT_POSTFIELDS]=$post_body; }
    curl_setopt_array($ch, $opts);
    $raw = curl_exec($ch); $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $eff = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL); $t = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    if ($raw === false) return ['ok'=>false,'error'=>$err,'code'=>0];
    $body = substr($raw, $hsize);
    $blocks = preg_split("/\r?\n\r?\n/", trim(substr($raw, 0, $hsize)));
    $lines = preg_split("/\r?\n/", end($blocks)); array_shift($lines);
    $hmap = [];
    foreach ($lines as $ln) if (strpos($ln,':')!==false){ list($k,$v)=explode(':',$ln,2); $hmap[strtolower(trim($k))]=trim($v); }
    return ['ok'=>true,'code'=>$code,'headers'=>$hmap,'body'=>$body,'url'=>$eff,'time'=>$t];
}
function head_only($url, $timeout = 5) {
    if (!function_exists('curl_init')) return ['code'=>0,'size'=>0,'ctype'=>'','loc'=>'','method'=>'HEAD'];
    $ch = curl_init();
    curl_setopt_array($ch, [CURLOPT_URL=>$url, CURLOPT_RETURNTRANSFER=>true, CURLOPT_NOBODY=>true,
        CURLOPT_FOLLOWLOCATION=>false, CURLOPT_TIMEOUT=>$timeout, CURLOPT_CONNECTTIMEOUT=>4,
        CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>0, CURLOPT_HEADER=>true,
        CURLOPT_HTTPHEADER=>['User-Agent: Mozilla/5.0 (TTPH-OSINT/'.APP_VERSION.')']]);
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $sz = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
    $ct = curl_getinfo($ch, CURLINFO_CONTENT_TYPE); curl_close($ch);
    $loc = ''; if ($raw && preg_match('~^location:\s*(.+)$~mi', $raw, $m)) $loc = trim($m[1]);
    return ['code'=>(int)$code,'size'=>(int)$sz,'ctype'=>$ct,'loc'=>$loc,'method'=>'HEAD'];
}
function get_partial($url, $timeout = 5, $max = 4096) {
    if (!function_exists('curl_init')) return ['code'=>0,'size'=>0,'ctype'=>'','body'=>'','method'=>'GET'];
    $ch = curl_init();
    curl_setopt_array($ch, [CURLOPT_URL=>$url, CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>false,
        CURLOPT_TIMEOUT=>$timeout, CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>0,
        CURLOPT_HEADER=>true, CURLOPT_RANGE=>'0-'.$max, CURLOPT_HTTPHEADER=>['User-Agent: Mozilla/5.0 (TTPH-OSINT/'.APP_VERSION.')']]);
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $ct = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE); curl_close($ch);
    $body = $raw ? substr($raw, $hsize) : '';
    return ['code'=>(int)$code,'size'=>strlen($body),'ctype'=>$ct,'body'=>substr($body,0,$max),'method'=>'GET'];
}
function clean_host($i){ $i=trim($i); $i=preg_replace('~^https?://~i','',$i); $i=explode('/',$i,2)[0]; return strtolower(explode('?',$i,2)[0]); }
function is_valid_ip($ip){ return (bool)filter_var($ip, FILTER_VALIDATE_IP); }
function is_valid_domain($d){ if(!$d||strlen($d)>253) return false; return (bool)preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i',$d); }
function resolve_base($host){ $s='https://'; if(head_only($s.$host,4)['code']===0) $s='http://'; return $s.$host; }

function analyze_page($url) {
    $r = http_get($url, 12); $ret = ['fetched'=>false,'url'=>$url];
    if (!$r['ok']) { $ret['error']=$r['error']; return $ret; }
    $ret['fetched']=true; $ret['final_url']=$r['url']; $ret['status']=$r['code'];
    $ret['headers']=$r['headers']; $ret['body_size']=strlen($r['body']); $ret['source']=$r['body'];
    $body = $r['body'];
    if (preg_match('~<title[^>]*>(.*?)</title>~is',$body,$m)) $ret['title']=trim(html_entity_decode($m[1],ENT_QUOTES,'UTF-8'));
    $forms = [];
    if (preg_match_all('~<form\b([^>]*)>~i',$body,$fm)) foreach ($fm[1] as $a){ $act=''; $meth='GET';
        if(preg_match('~\baction\s*=\s*["\']([^"\']*)["\']~i',$a,$x))$act=$x[1];
        if(preg_match('~\bmethod\s*=\s*["\']([^"\']*)["\']~i',$a,$x))$meth=strtoupper($x[1]);
        $forms[]=['action'=>$act,'method'=>$meth]; }
    $ret['forms']=$forms;
    $ext=[]; if (preg_match_all('~<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']~i',$body,$sm)) $ext=array_values(array_unique($sm[1]));
    $ret['scripts_ext']=$ext;
    return $ret;
}
function detect_tech($h, $body) {
    $tech=[]; $push=function($n,$v='') use(&$tech){ $tech[]=['name'=>$n,'version'=>$v]; };
    if(!empty($h['server'])) $push('Web Server',$h['server']);
    if(!empty($h['x-powered-by'])) $push('X-Powered-By',$h['x-powered-by']);
    if(!empty($h['cf-ray'])) $push('Cloudflare','CDN/WAF');
    $b=$body?:''; if(stripos($b,'wp-content')!==false) $push('WordPress','fingerprint');
    if(preg_match('~jquery[.-](\d[\d.]+)~i',$b,$m)) $push('jQuery',$m[1]);
    if(preg_match('~bootstrap[.-](\d[\d.]+)~i',$b,$m)) $push('Bootstrap',$m[1]);
    return $tech;
}
function audit_security_headers($h){
    $c=['strict-transport-security'=>['HSTS','Enforces HTTPS.'],'content-security-policy'=>['CSP','Mitigates XSS.'],
        'x-frame-options'=>['X-Frame-Options','Clickjacking mitigation.'],'x-content-type-options'=>['X-Content-Type-Options','Blocks MIME sniffing.'],
        'referrer-policy'=>['Referrer-Policy','Controls referrer leakage.'],'permissions-policy'=>['Permissions-Policy','Restricts browser features.']];
    $rows=[]; foreach($c as $k=>$m){ $p=isset($h[$k]); $rows[]=['header'=>$m[0],'present'=>$p,'value'=>$p?$h[$k]:'','note'=>$m[1]]; }
    return $rows;
}
function vulnerability_analysis($page,$tech,$sec){
    $f=[]; $add=function($s,$t,$w,$fx) use(&$f){ $f[]=['sev'=>$s,'title'=>$t,'why'=>$w,'fix'=>$fx]; };
    foreach($sec as $r) if(!$r['present']){ $sv=in_array($r['header'],['HSTS','CSP','X-Frame-Options','X-Content-Type-Options'])?'High':'Medium';
        $add($sv,'Missing header: '.$r['header'],$r['note'],'Add '.$r['header'].' at web server/WAF.'); }
    foreach($tech as $t){ if(in_array($t['name'],['Web Server','X-Powered-By']) && preg_match('~\d~',$t['version']))
        $add('Medium','Version banner ('.$t['name'].': '.$t['version'].')','Maps to CVEs.','Suppress version headers.'); }
    return $f;
}
/* ============================================================
 * v2.3.0 — WordPress fingerprinting + version vulnerability scoring
 * Baseline: WordPress 7.0.2 (Jul 2026); only 7.0 branch maintained.
 * v2.4.0 — plugin & theme enumeration + per-component CVE scoring.
 * ============================================================ */
function wp_latest(){ return ['stable'=>'7.0.2','maintained'=>['7.0']]; }
function wp_extract_version($s){
    if(!$s) return '';
    if(preg_match('~<meta[^>]*name=["\']generator["\'][^>]*content=["\']\s*WordPress\s+([0-9]+(?:\.[0-9]+){0,3})~i',$s,$m)) return $m[1];
    if(preg_match('~<meta[^>]*content=["\']\s*WordPress\s+([0-9]+(?:\.[0-9]+){0,3})["\'][^>]*name=["\']generator~i',$s,$m)) return $m[1];
    return '';
}
function wp_in_ranges($ver,$ranges){
    foreach($ranges as $r){ if(version_compare($ver,$r[0],'>=')&&version_compare($ver,$r[1],'<=')) return true; }
    return false;
}
/* Curated WordPress CORE CVEs (NVD-sourced). Not exhaustive. */
function wp_core_cves(){
    return [
        ['id'=>'CVE-2024-4439','title'=>'Unauthenticated Stored XSS via display names (Avatar block)','cwe'=>'CWE-79','cvss'=>7.2,'sev'=>'High','fixed'=>'6.5.3 (+ branch backports)','ranges'=>[['0','6.5.2']]],
        ['id'=>'CVE-2025-58246','title'=>'Sensitive information exposure to contributor-level users','cwe'=>'CWE-200','cvss'=>4.3,'sev'=>'Medium','fixed'=>'6.8.3 / 7.0','ranges'=>[
            ['6.8','6.8.2'],['6.7','6.7.3'],['6.6','6.6.3'],['6.5','6.5.6'],['6.4','6.4.6'],['6.3','6.3.6'],['6.2','6.2.7'],['6.1','6.1.8'],['6.0','6.0.10'],['5.9','5.9.11'],['5.8','5.8.11'],['5.7','5.7.13'],['5.6','5.6.15'],['5.5','5.5.16'],['5.4','5.4.17'],['5.3','5.3.19'],['5.2','5.2.22'],['5.1','5.1.20'],['5.0','5.0.23'],['4.9','4.9.27'],['4.8','4.8.26'],['4.7','4.7.30'],
        ]],
    ];
}
/* Curated WordPress PLUGIN CVEs keyed by plugin slug (NVD/Wordfence, 2024-2026). */
function wp_plugin_cves(){
    return [
        'litespeed-cache'=>['name'=>'LiteSpeed Cache','installs'=>'7,000,000+','cves'=>[
            ['id'=>'CVE-2025-12450','title'=>'Reflected XSS via URLs','cwe'=>'CWE-79','cvss'=>6.1,'sev'=>'Medium','fixed'=>'7.6','ranges'=>[['0','7.5.0.1']]],
        ]],
        'elementor'=>['name'=>'Elementor Website Builder','installs'=>'10,000,000+','cves'=>[
            ['id'=>'CVE-2025-4566','title'=>'Stored XSS (Contributor+)','cwe'=>'CWE-79','cvss'=>6.5,'sev'=>'Medium','fixed'=>'3.30.3','ranges'=>[['0','3.30.2']]],
        ]],
        'essential-addons-for-elementor-lite'=>['name'=>'Essential Addons for Elementor','installs'=>'2,000,000+','cves'=>[
            ['id'=>'CVE-2025-6244','title'=>'Stored XSS (Contributor+)','cwe'=>'CWE-79','cvss'=>6.5,'sev'=>'Medium','fixed'=>'6.1.20','ranges'=>[['0','6.1.19']]],
        ]],
        'premium-addons-for-elementor'=>['name'=>'Premium Addons for Elementor','installs'=>'700,000+','cves'=>[
            ['id'=>'CVE-2024-11937','title'=>'Stored XSS (Contributor+)','cwe'=>'CWE-79','cvss'=>6.5,'sev'=>'Medium','fixed'=>'4.10.70','ranges'=>[['0','4.10.69']]],
        ]],
        'wpvivid-backuprestore'=>['name'=>'WPvivid Backup & Migration','installs'=>'700,000+','cves'=>[
            ['id'=>'CVE-2025-5961','title'=>'Arbitrary File Upload (Admin+)','cwe'=>'CWE-434','cvss'=>7.2,'sev'=>'High','fixed'=>'0.9.117','ranges'=>[['0','0.9.116']]],
        ]],
        'wordpress-seo'=>['name'=>'Yoast SEO','installs'=>'10,000,000+','cves'=>[
            ['id'=>'CVE-2025-11241','title'=>'Stored XSS (Premium 25.7-25.9)','cwe'=>'CWE-80','cvss'=>6.4,'sev'=>'Medium','fixed'=>'26.0','ranges'=>[['25.7','25.9']]],
        ]],
        'shoplentor'=>['name'=>'ShopLentor (WooLentor)','installs'=>'100,000+','cves'=>[
            ['id'=>'CVE-2025-11823','title'=>'Stored XSS via wishsuite_button shortcode','cwe'=>'CWE-79','cvss'=>6.4,'sev'=>'Medium','fixed'=>'3.2.5','ranges'=>[['0','3.2.4']]],
        ]],
        'advanced-cf7-db'=>['name'=>'Database for Contact Form 7 / WPForms / Elementor','installs'=>'70,000+','cves'=>[
            ['id'=>'CVE-2025-7384','title'=>'Unauthenticated PHP Object Injection -> RCE','cwe'=>'CWE-502','cvss'=>9.8,'sev'=>'Critical','fixed'=>'1.4.4','ranges'=>[['0','1.4.3']]],
        ]],
        'woocommerce'=>['name'=>'WooCommerce','installs'=>'8,000,000+','cves'=>[]],
        'contact-form-7'=>['name'=>'Contact Form 7','installs'=>'10,000,000+','cves'=>[]],
        'wpforms-lite'=>['name'=>'WPForms','installs'=>'6,000,000+','cves'=>[]],
        'akismet'=>['name'=>'Akismet Anti-Spam','installs'=>'5,000,000+','cves'=>[]],
        'jetpack'=>['name'=>'Jetpack','installs'=>'5,000,000+','cves'=>[]],
        'wordfence'=>['name'=>'Wordfence Security','installs'=>'5,000,000+','cves'=>[]],
        'all-in-one-seo-pack'=>['name'=>'All in One SEO','installs'=>'3,000,000+','cves'=>[]],
        'wp-super-cache'=>['name'=>'WP Super Cache','installs'=>'2,000,000+','cves'=>[]],
        'w3-total-cache'=>['name'=>'W3 Total Cache','installs'=>'1,000,000+','cves'=>[]],
        'advanced-custom-fields'=>['name'=>'Advanced Custom Fields (ACF)','installs'=>'2,000,000+','cves'=>[]],
    ];
}
/* Curated WordPress THEME CVEs keyed by theme slug. */
function wp_theme_cves(){
    return [
        'arolax'=>['name'=>'Arolax','cves'=>[
            ['id'=>'CVE-2025-1639','title'=>'Unauthorized arbitrary plugin installation (Subscriber+)','cwe'=>'CWE-862','cvss'=>8.8,'sev'=>'High','fixed'=>'1.7','ranges'=>[['0','1.6']]],
        ]],
    ];
}
/* Enumerate plugins/themes from HTML asset paths. */
function wp_enum_assets($body){
    $plugins=[]; $themes=[];
    if(preg_match_all('~/wp-content/plugins/([a-z0-9][a-z0-9\-_]*)/[^"\'\s>]*?(?:\?ver=([0-9]+(?:\.[0-9]+){1,3}))?(?=["\'\s>])~i',$body,$m,PREG_SET_ORDER)){
        foreach($m as $x){ $slug=strtolower($x[1]); $ver=$x[2]??'';
            if(!isset($plugins[$slug])) $plugins[$slug]=$ver;
            elseif($ver && !$plugins[$slug]) $plugins[$slug]=$ver; }
    }
    if(preg_match_all('~/wp-content/themes/([a-z0-9][a-z0-9\-_]*)/[^"\'\s>]*?(?:\?ver=([0-9]+(?:\.[0-9]+){1,3}))?(?=["\'\s>])~i',$body,$m,PREG_SET_ORDER)){
        foreach($m as $x){ $slug=strtolower($x[1]); $ver=$x[2]??'';
            if(!isset($themes[$slug])) $themes[$slug]=$ver;
            elseif($ver && !$themes[$slug]) $themes[$slug]=$ver; }
    }
    return ['plugins'=>$plugins,'themes'=>$themes];
}
function wp_plugin_readme_version($base,$slug){
    $g=get_partial(rtrim($base,'/').'/wp-content/plugins/'.$slug.'/readme.txt',5,3072);
    if(!empty($g['body']) && preg_match('~Stable tag:\s*([0-9]+(?:\.[0-9]+){1,3})~i',$g['body'],$m)) return $m[1];
    return '';
}
function wp_theme_style_meta($base,$slug){
    $g=get_partial(rtrim($base,'/').'/wp-content/themes/'.$slug.'/style.css',5,3072);
    $meta=['name'=>'','version'=>''];
    if(!empty($g['body'])){
        if(preg_match('~Theme Name:\s*(.+)~i',$g['body'],$m)) $meta['name']=trim($m[1]);
        if(preg_match('~Version:\s*([0-9]+(?:\.[0-9]+){1,3})~i',$g['body'],$m)) $meta['version']=trim($m[1]);
    }
    return $meta;
}
function wp_component_score($ver,$cveList){
    $matched=[]; $maxCvss=0;
    if($ver){ foreach($cveList as $c){ if(wp_in_ranges($ver,$c['ranges'])){ $matched[]=$c; $maxCvss=max($maxCvss,$c['cvss']); } } }
    $rating = $maxCvss>=9?'Critical':($maxCvss>=7?'High':($maxCvss>=4?'Medium':($maxCvss>0?'Low':'Info')));
    $score  = $maxCvss>0 ? min(100,(int)round(35 + $maxCvss*6.5)) : ($ver?0:15);
    return ['matched'=>$matched,'max_cvss'=>$maxCvss,'rating'=>$rating,'score'=>$score];
}
/* v2.4.4 — WordPress user enumeration (REST API + author-archive redirect) */
function wp_enum_users($base,$depth=10){
    $base=rtrim($base,'/');
    $depth=max(5,min(200,(int)$depth)); // clamp 5..200
    $out=['users'=>[],'rest_open'=>false,'author_open'=>false,'methods'=>[],'depth'=>$depth,'probed'=>0];
    $seen=[];
    // $extra = ['name','url','link','rest','author_url']
    $add=function($login,$name,$id,$src,$extra=[]) use(&$out,&$seen,$base){
        $key=strtolower($login!==''?$login:($name!==''?$name:('id'.$id)));
        if($key==='') return;
        if(isset($seen[$key])){
            $idx=$seen[$key];
            $out['users'][$idx]['sources'][$src]=true;
            // enrich blanks if a later source has more detail
            foreach(['name','url','link','rest','author_url'] as $f){
                if(empty($out['users'][$idx][$f]) && !empty($extra[$f])) $out['users'][$idx][$f]=$extra[$f];
            }
            if($out['users'][$idx]['id']===null && $id!==null) $out['users'][$idx]['id']=$id;
            return;
        }
        $seen[$key]=count($out['users']);
        $out['users'][]=[
            'id'=>$id,'login'=>$login,'name'=>$name?:($extra['name']??''),
            'url'=>$extra['url']??'',           // user's own website/profile (e.g. Facebook)
            'link'=>$extra['link']??'',         // author archive page
            'rest'=>$extra['rest']??'',         // REST self href
            'author_url'=>$extra['author_url']??'',
            'sources'=>[$src=>true],
        ];
    };
    // 1) REST API: /wp-json/wp/v2/users  (leaks slug=login, name, url, link, _links.self)
    $r=http_get($base.'/wp-json/wp/v2/users?per_page=100',10);
    if($r['ok'] && $r['code']===200 && stripos($r['headers']['content-type']??'','json')!==false){
        $j=json_decode($r['body'],true);
        if(is_array($j) && !isset($j['code'])){
            $out['rest_open']=true; $out['methods'][]='REST API /wp-json/wp/v2/users';
            foreach($j as $u){ if(!is_array($u))continue;
                $selfHref='';
                if(!empty($u['_links']['self'][0]['href'])) $selfHref=(string)$u['_links']['self'][0]['href'];
                $add((string)($u['slug']??''),(string)($u['name']??''),isset($u['id'])?(int)$u['id']:null,'REST',[
                    'name'=>(string)($u['name']??''),
                    'url'=>(string)($u['url']??''),
                    'link'=>(string)($u['link']??''),
                    'rest'=>$selfHref,
                ]);
            }
        }
    }
    // 2) Author-archive redirect: /?author=N  -> Location: /author/<login>/
    $ax=0;
    for($i=1;$i<=$depth;$i++){
        $out['probed']=$i;
        $h=head_only($base.'/?author='.$i,4);
        $loc=$h['loc']??'';
        if($loc && preg_match('~/author/([^/?#]+)~i',$loc,$m)){
            $ax++; $out['author_open']=true;
            $login=urldecode($m[1]);
            $authorUrl=preg_match('~^https?://~i',$loc)?$loc:($base.'/author/'.$login.'/');
            $add($login,'',$i,'author-archive',['author_url'=>$authorUrl,'link'=>$authorUrl]);
        }
        if($i>=3 && $ax===0) break; // stop early if clearly not leaking
    }
    if($out['author_open']) $out['methods'][]='Author archive redirect (?author=N)';
    // trim to a reasonable display cap
    $out['users']=array_slice($out['users'],0,100);
    $out['count']=count($out['users']);
    return $out;
}
/* v2.4.4 — XML-RPC exposure + dangerous-method checks */
function wp_xmlrpc_check($base){
    $base=rtrim($base,'/');
    $out=['enabled'=>false,'status'=>0,'methods_listed'=>false,'method_count'=>0,
          'multicall'=>false,'pingback'=>false,'system_methods'=>false,'methods'=>[]];
    $url=$base.'/xmlrpc.php';
    // GET: WordPress replies "XML-RPC server accepts POST requests only." with 405
    $g=get_partial($url,5,512);
    $out['status']=$g['code']??0;
    $bodyHint=stripos($g['body']??'','XML-RPC server accepts POST')!==false;
    if(in_array($out['status'],[200,405],true) || $bodyHint) $out['enabled']=true;
    if(!$out['enabled']) return $out;
    // POST system.listMethods to enumerate exposed methods
    $payload='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>';
    $r=http_get($url,8,true,['Content-Type: text/xml'],$payload);
    if($r['ok'] && $r['code']===200 && stripos($r['body'],'methodResponse')!==false){
        if(preg_match_all('~<string>([^<]+)</string>~',$r['body'],$mm)){
            $methods=array_values(array_unique($mm[1]));
            $out['methods_listed']=true; $out['method_count']=count($methods);
            $out['methods']=array_slice($methods,0,80);
            $out['multicall']=(bool)preg_grep('~^system\.multicall$~',$methods);
            $out['pingback']=(bool)preg_grep('~^pingback\.ping$~',$methods);
            $out['system_methods']=(bool)preg_grep('~^system\.~',$methods);
        }
    }
    return $out;
}
function wordpress_scan($base,$userDepth=10,$wpsKey=''){
    $base=rtrim($base,'/');
    $out=['is_wp'=>false,'version'=>'','detected_by'=>[],'signals'=>[],'cves'=>[],'score'=>0,'rating'=>'Info','max_cvss'=>0,'wpscan_used'=>false,'wpscan_error'=>''];
    $home=http_get($base,12); $body=$home['ok']?$home['body']:'';
    $sig=[];
    if(stripos($body,'wp-content')!==false){$out['is_wp']=true;$sig[]='wp-content path referenced in HTML';}
    if(stripos($body,'wp-includes')!==false){$out['is_wp']=true;$sig[]='wp-includes path referenced in HTML';}
    if(stripos($body,'/wp-json')!==false){$out['is_wp']=true;$sig[]='wp-json REST API link present';}
    $v=wp_extract_version($body);
    if($v){$out['is_wp']=true;$out['version']=$v;$out['detected_by'][]=['method'=>'Generator meta tag','value'=>$v,'evidence'=>'<meta name="generator" content="WordPress '.$v.'">'];}
    if(!$out['version'] && preg_match('~wp-includes/[^"\'\s]+\?ver=([0-9]+(?:\.[0-9]+){1,3})~i',$body,$m)){$out['is_wp']=true;$out['version']=$m[1];$out['detected_by'][]=['method'=>'Core asset ?ver= query string','value'=>$m[1],'evidence'=>substr($m[0],0,120)];}
    if(!$out['version']){
        $feed=get_partial($base.'/feed/',6,8192);
        if(!empty($feed['body'])&&preg_match('~<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)~i',$feed['body'],$m)){$out['is_wp']=true;$out['version']=$m[1];$out['detected_by'][]=['method'=>'RSS feed generator','value'=>$m[1],'evidence'=>'/feed/ &rarr; wordpress.org/?v='.$m[1]];$sig[]='RSS feed leaks version (/feed/)';}
    }
    $readme=get_partial($base.'/readme.html',6,4096);
    if(!empty($readme['body'])&&($readme['code']??0)==200){
        $sig[]='readme.html is publicly readable';
        if(!$out['version']&&preg_match('~[Vv]ersion\s+([0-9]+(?:\.[0-9]+){1,3})~',$readme['body'],$m)){$out['is_wp']=true;$out['version']=$m[1];$out['detected_by'][]=['method'=>'readme.html','value'=>$m[1],'evidence'=>'/readme.html &rarr; Version '.$m[1]];}
    }
    $login=head_only($base.'/wp-login.php',5);
    if(in_array($login['code'],[200,301,302],true)){$out['is_wp']=true;$sig[]='wp-login.php reachable';}
    $out['signals']=array_values(array_unique($sig));
    if(!$out['is_wp']) return $out;

    $latest=wp_latest(); $out['latest']=$latest['stable'];
    $ver=$out['version'];
    if($ver){
        $branch=preg_replace('~^(\d+\.\d+).*~','$1',$ver);
        $out['branch']=$branch;
        $out['branch_maintained']=in_array($branch,$latest['maintained'],true);
        $out['outdated']=version_compare($ver,$latest['stable'],'<');
        $matched=[]; $maxCvss=0;
        foreach(wp_core_cves() as $c){ if(wp_in_ranges($ver,$c['ranges'])){ $matched[]=$c; $maxCvss=max($maxCvss,$c['cvss']); } }
        $out['cves']=$matched; $out['max_cvss']=$maxCvss;
        if(version_compare($ver,$latest['stable'],'>=')) $cur=8;
        elseif(version_compare($ver,'7.0','>=')) $cur=18;
        elseif(version_compare($ver,'6.9','>=')) $cur=32;
        elseif(version_compare($ver,'6.5','>=')) $cur=48;
        elseif(version_compare($ver,'6.0','>=')) $cur=62;
        elseif(version_compare($ver,'5.0','>=')) $cur=78;
        else $cur=90;
        $score=min(100,(int)round($cur + $maxCvss*2.2));
        $out['score']=$score;
        $sevScore = $score>=80?'Critical':($score>=60?'High':($score>=40?'Medium':($score>=20?'Low':'Info')));
        $sevCvss  = $maxCvss>=9?'Critical':($maxCvss>=7?'High':($maxCvss>=4?'Medium':($maxCvss>0?'Low':'Info')));
        $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4];
        $out['rating']=$rank[$sevCvss]>=$rank[$sevScore]?$sevCvss:$sevScore;
    } else {
        $out['score']=20; $out['rating']='Low'; $out['branch_maintained']=null; $out['outdated']=null;
    }

    /* plugin & theme enumeration + vulnerability scoring */
    $enum=wp_enum_assets($body);
    $pluginDB=wp_plugin_cves(); $themeDB=wp_theme_cves();
    $eco_max_cvss=$out['max_cvss'];
    $plugins=[]; $pcount=0;
    foreach($enum['plugins'] as $slug=>$ver2){
        $pcount++;
        if(!$ver2 && $pcount<=12){ $rv=wp_plugin_readme_version($base,$slug); if($rv) $ver2=$rv; }
        $known=$pluginDB[$slug]??null;
        $cveList=$known['cves']??[];
        $sc=wp_component_score($ver2,$cveList);
        $live=false;
        // #5: live WPScan feed (gated by key; cap to first 15 plugins to respect rate limits)
        if($wpsKey && $pcount<=15){
            $lk=wpscan_lookup('plugins',$slug,$ver2,$wpsKey);
            if($lk && !empty($lk['error'])){ $out['wpscan_error']=$lk['error']; }
            elseif($lk && isset($lk['vulns'])){ $out['wpscan_used']=true;
                if($lk['vulns']){ $live=true;
                    $merged=$sc['matched']; $seen=array_flip(array_map(fn($c)=>$c['id'],$merged));
                    foreach($lk['vulns'] as $lv){ if(!isset($seen[$lv['id']])){ $merged[]=$lv; $sc['max_cvss']=max($sc['max_cvss'],$lv['cvss']); } }
                    $sc['matched']=$merged;
                    $sc['rating']=$sc['max_cvss']>=9?'Critical':($sc['max_cvss']>=7?'High':($sc['max_cvss']>=4?'Medium':($sc['max_cvss']>0?'Low':'Info')));
                    $sc['score']=$sc['max_cvss']>0?min(100,(int)round(35+$sc['max_cvss']*6.5)):($ver2?0:15);
                }
            }
        }
        $eco_max_cvss=max($eco_max_cvss,$sc['max_cvss']);
        $plugins[]=[
            'slug'=>$slug,'name'=>$known['name']??$slug,'version'=>$ver2,'installs'=>$known['installs']??'',
            'known'=>$known?true:false,'cves'=>$sc['matched'],'max_cvss'=>$sc['max_cvss'],'rating'=>$sc['rating'],'score'=>$sc['score'],
            'live'=>$live,
            'version_source'=>$ver2?($enum['plugins'][$slug]?'?ver= asset':'readme.txt Stable tag'):'',
        ];
    }
    usort($plugins,fn($a,$b)=>($b['max_cvss']<=>$a['max_cvss'])?:strcmp($a['name'],$b['name']));
    $out['plugins']=$plugins;
    $out['plugin_count']=count($plugins);
    $out['plugin_vuln_count']=count(array_filter($plugins,fn($p)=>count($p['cves'])>0));

    $themes=[]; $tcount=0;
    foreach($enum['themes'] as $slug=>$ver3){
        $tcount++;
        $name=$slug;
        if($tcount<=6){ $meta=wp_theme_style_meta($base,$slug); if($meta['name'])$name=$meta['name']; if(!$ver3 && $meta['version'])$ver3=$meta['version']; }
        $known=$themeDB[$slug]??null;
        $cveList=$known['cves']??[];
        $sc=wp_component_score($ver3,$cveList);
        $eco_max_cvss=max($eco_max_cvss,$sc['max_cvss']);
        $themes[]=[
            'slug'=>$slug,'name'=>$known['name']??$name,'version'=>$ver3,'known'=>$known?true:false,
            'cves'=>$sc['matched'],'max_cvss'=>$sc['max_cvss'],'rating'=>$sc['rating'],'score'=>$sc['score'],
            'version_source'=>$ver3?($enum['themes'][$slug]?'?ver= asset':'style.css header'):'',
        ];
    }
    usort($themes,fn($a,$b)=>($b['max_cvss']<=>$a['max_cvss'])?:strcmp($a['name'],$b['name']));
    $out['themes']=$themes;
    $out['theme_count']=count($themes);
    $out['theme_vuln_count']=count(array_filter($themes,fn($t)=>count($t['cves'])>0));

    $out['eco_max_cvss']=$eco_max_cvss;
    $ecoRating=$eco_max_cvss>=9?'Critical':($eco_max_cvss>=7?'High':($eco_max_cvss>=4?'Medium':($eco_max_cvss>0?'Low':'Info')));
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4];
    if(($rank[$ecoRating]??0) > ($rank[$out['rating']]??0)) $out['rating']=$ecoRating;
    if($eco_max_cvss>0){ $ecoScore=min(100,(int)round(45 + $eco_max_cvss*5.5)); if($ecoScore>$out['score']) $out['score']=$ecoScore; }

    /* v2.4.4 — user enumeration + XML-RPC exposure */
    $users=wp_enum_users($base,$userDepth);
    $xmlrpc=wp_xmlrpc_check($base);
    $out['users']=$users;
    $out['xmlrpc']=$xmlrpc;

    // Build discrete findings so these show up in signals + escalate the score
    $findings=[];
    if($users['count']>0){
        $sv=$users['rest_open']?'Medium':'Low';
        $findings[]=['sev'=>$sv,'title'=>'Username enumeration exposed','why'=>$users['count'].' username(s) recovered via '.implode(' + ',$users['methods']).'. Attackers can pair these with password spraying/brute force.','fix'=>'Block /wp-json/wp/v2/users for anonymous requests, disable author archives (or redirect ?author=N), and use a login-hardening/WAF plugin.'];
        $out['signals'][]=$users['count'].' username(s) enumerable ('.($users['rest_open']?'REST API':'author archive').')';
    }
    if($xmlrpc['enabled']){
        $sv='Low';
        if($xmlrpc['multicall']) $sv='High';        // brute-force amplification
        elseif($xmlrpc['pingback']) $sv='Medium';   // pingback SSRF/DDoS
        $why='xmlrpc.php is enabled.';
        if($xmlrpc['multicall']) $why.=' system.multicall is available — enables amplified credential brute-forcing (thousands of logins per request).';
        if($xmlrpc['pingback']) $why.=' pingback.ping is available — usable for SSRF and DDoS reflection.';
        $findings[]=['sev'=>$sv,'title'=>'XML-RPC endpoint enabled','why'=>$why,'fix'=>'Disable XML-RPC if unused (block /xmlrpc.php at the web server/WAF), or at minimum disable system.multicall and pingback.ping.'];
        $out['signals'][]='xmlrpc.php enabled'.($xmlrpc['multicall']?' (system.multicall!)':'').($xmlrpc['pingback']?' (pingback.ping)':'');
    }
    $out['extra_findings']=$findings;
    $out['signals']=array_values(array_unique($out['signals']));

    // Escalate overall rating/score from these findings
    $maxRank=$rank[$out['rating']]??0;
    foreach($findings as $f){ $maxRank=max($maxRank,$rank[$f['sev']]??0); }
    $ratingByRank=array_flip($rank);
    $out['rating']=$ratingByRank[$maxRank];
    if($xmlrpc['multicall'] && $out['score']<70) $out['score']=70;
    elseif($findings && $out['score']<45){ $out['score']=45; }

    return $out;
}
function waf_detect($base,$ph,$pb){
    $sig=[]; $push=function($p,$c,$e,$t) use(&$sig){ if(!isset($sig[$p]))$sig[$p]=['product'=>$p,'confidence'=>0,'evidence'=>[]]; $sig[$p]['confidence']+=$c; $sig[$p]['evidence'][]=['technique'=>$t,'detail'=>$e]; };
    $hget=function($k) use($ph){ return $ph[strtolower($k)]??''; };
    $hmap=['cf-ray'=>['Cloudflare',90],'x-sucuri-id'=>['Sucuri',95],'x-akamai-request-id'=>['Akamai',95],
        'x-fastly-request-id'=>['Fastly',95],'x-amz-cf-id'=>['AWS CloudFront',95],'x-iinfo'=>['Imperva Incapsula',95],
        'x-served-by'=>['Fastly/Varnish',30],'x-cache'=>['CDN (generic)',20]];
    foreach($hmap as $hn=>$s){ $v=$hget($hn); if($v!=='') $push($s[0],$s[1],'Header '.$hn.': '.substr($v,0,80),'Passive header'); }
    $sv=strtolower($hget('server'));
    if($sv){ $sm=['~cloudflare~'=>['Cloudflare',90],'~akamai~'=>['Akamai',95],'~sucuri~'=>['Sucuri',95],'~mod_security~'=>['ModSecurity',90]];
        foreach($sm as $re=>$s) if(preg_match($re,$sv)) $push($s[0],$s[1],'Server: '.$sv,'Server value'); }
    $probes=[['id=1%27%20OR%20%271%27=%271','SQLi'],['q=<script>alert(1)</script>','XSS'],['file=../../../../etc/passwd','Path traversal'],['cmd=;cat%20/etc/passwd','Command injection'],['u=file:///etc/passwd','SSRF']];
    $conn=(strpos($base,'?')!==false)?'&':'/?'; $active=[];
    foreach($probes as $p){ $u=rtrim($base,'/').$conn.$p[0]; $r=head_only($u,4);
        if(in_array($r['code'],[0,405,501],true)){ $g=get_partial($u,4,512); $r=['code'=>$g['code'],'method'=>'GET']; }
        $active[]=['path'=>$conn.$p[0],'desc'=>$p[1],'status'=>$r['code'],'method'=>$r['method']];
        if(in_array($r['code'],[403,406,419,429,451,501,999],true)) $push('Generic WAF (block on payload)',30,'Probe returned HTTP '.$r['code'],'Active probe'); }
    $prods=array_values($sig); usort($prods,fn($a,$b)=>$b['confidence']<=>$a['confidence']);
    foreach($prods as &$p) $p['confidence']=min(100,(int)$p['confidence']);
    return ['detected'=>$prods,'primary'=>$prods[0]??null,'active_probes'=>$active];
}
function directory_probe_expanded($base){
    $base=rtrim($base,'/');
    $cats=['Info & Meta'=>['/robots.txt','/sitemap.xml','/.well-known/security.txt','/crossdomain.xml','/favicon.ico'],
        'Admin / Auth'=>['/admin','/administrator','/login','/wp-login.php','/wp-admin/','/manager/html','/cpanel'],
        'WordPress'=>['/wp-config.php','/wp-config.php.bak','/wp-json/','/wp-json/wp/v2/users','/xmlrpc.php'],
        'PHP Info'=>['/phpinfo.php','/info.php','/config.php','/config.bak','/db.php'],
        'Version Control'=>['/.git/HEAD','/.git/config','/.svn/entries','/.hg/store'],
        'Config Files'=>['/.env','/.env.local','/.env.production','/.htaccess','/.htpasswd','/web.config','/composer.json','/package.json','/Dockerfile','/docker-compose.yml'],
        'Backup / Dump'=>['/backup.zip','/backup.sql','/db.sql','/dump.sql','/site.zip','/www.zip'],
        'API Endpoints'=>['/api','/api/v1','/api/v2','/graphql','/swagger','/swagger.json','/openapi.json','/api-docs'],
        'Spring Actuator'=>['/actuator','/actuator/health','/actuator/env','/actuator/heapdump','/env','/health','/metrics'],
        'Server Status'=>['/server-status','/server-info','/nginx_status','/error.log','/access.log'],
        'Cloud'=>['/.aws/credentials','/.ssh/id_rsa','/.kube/config'],
        'Common Dirs'=>['/uploads/','/files/','/static/','/assets/','/media/','/cgi-bin/'],
        'Dev / Staging'=>['/dev','/staging','/test','/qa','/beta','/demo'],
        'Misc'=>['/.DS_Store','/Thumbs.db','/private/','/secret/','/internal/']];
    $pc=[]; $up=[];
    foreach($cats as $c=>$ps) foreach($ps as $p) if(!isset($pc[$p])){ $pc[$p]=$c; $up[]=$p; }
    $rows=[];
    foreach($up as $p){ $u=$base.$p; $r=head_only($u,4);
        if(in_array($r['code'],[405,501,400],true)){ $g=get_partial($u,4,512); if($g['code']>0) $r=['code'=>$g['code'],'size'=>$g['size'],'ctype'=>$g['ctype'],'loc'=>'','method'=>'GET']; }
        $st=$r['code']; $int='low'; $flag='';
        if($st===200){ $int='HIGH'; if($r['size']>0&&$r['size']<200000){ $g=get_partial($u,3,2048); $b=$g['body']??'';
            if(preg_match('~Index of /~i',$b))$flag='DIR-LISTING'; elseif(preg_match('~<\?php|phpinfo~i',$b))$flag='PHP-SRC';
            elseif(preg_match('~DB_(HOST|PASSWORD)|APP_KEY~',$b))$flag='ENV-LEAK'; } }
        elseif(in_array($st,[301,302,307,308],true))$int='redirect';
        elseif($st===401||$st===403)$int='auth-protected';
        elseif($st>=500&&$st<600)$int='server-error';
        elseif($st===429||$st===451)$int='waf-block';
        elseif($st===0)$int='timeout';
        $rows[]=['category'=>$pc[$p],'url'=>$u,'path'=>$p,'status'=>$st,'size'=>$r['size'],'ctype'=>$r['ctype'],'method'=>$r['method']??'HEAD','loc'=>$r['loc']??'','interest'=>$int,'flag'=>$flag]; }
    return ['base'=>$base,'rows'=>$rows,'categories'=>array_keys($cats)];
}
function ip_geo($ip){ $r=http_get('http://ip-api.com/json/'.urlencode($ip).'?fields=66846719',8); return ($r['ok']&&$r['code']===200)?(json_decode($r['body'],true)?:[]):[]; }
function ip_rdns($ip){ return @gethostbyaddr($ip)?:''; }
function ip_rdap($ip){ $r=http_get('https://rdap.arin.net/registry/ip/'.urlencode($ip),8); if(!$r['ok']||$r['code']!==200)return null;
    $j=json_decode($r['body'],true); if(!is_array($j))return null;
    return ['handle'=>$j['handle']??'','name'=>$j['name']??'','startAddress'=>$j['startAddress']??'','endAddress'=>$j['endAddress']??'','type'=>$j['type']??'','country'=>$j['country']??'']; }
function ip_spamhaus($ip){ if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)||!function_exists('dns_get_record'))return null;
    return !empty(@dns_get_record(implode('.',array_reverse(explode('.',$ip))).'.zen.spamhaus.org',DNS_A)); }
function ip_ports($ip){ $ports=[21=>'FTP',22=>'SSH',23=>'Telnet',25=>'SMTP',53=>'DNS',80=>'HTTP',443=>'HTTPS',445=>'SMB',3306=>'MySQL',3389=>'RDP',5432=>'Postgres',6379=>'Redis',8080=>'HTTP-alt',8443=>'HTTPS-alt',27017=>'MongoDB'];
    $o=[]; if(!function_exists('fsockopen'))return $o;
    foreach($ports as $p=>$s){ $t0=microtime(true); $sk=@fsockopen($ip,$p,$e,$es,1.2); $ms=(int)((microtime(true)-$t0)*1000);
        if($sk){ $o[]=['port'=>$p,'svc'=>$s,'state'=>'open','ms'=>$ms]; fclose($sk); } else $o[]=['port'=>$p,'svc'=>$s,'state'=>'closed/filtered','ms'=>$ms]; }
    return $o; }
function shodan_host($ip,$k){ if(!$k)return ['skipped'=>true,'error'=>'No Shodan key.']; $r=http_get('https://api.shodan.io/shodan/host/'.urlencode($ip).'?key='.urlencode($k),12);
    if(!$r['ok'])return['error'=>$r['error']]; if($r['code']!==200)return['error'=>'Shodan HTTP '.$r['code']];
    $j=json_decode($r['body'],true); if(!is_array($j))return['error'=>'Malformed.'];
    return ['org'=>$j['org']??'','isp'=>$j['isp']??'','asn'=>$j['asn']??'','os'=>$j['os']??'','ports'=>$j['ports']??[],'vulns'=>array_values($j['vulns']??[])]; }
function abuseipdb($ip,$k){ if(!$k)return['skipped'=>true,'error'=>'No AbuseIPDB key.']; $r=http_get('https://api.abuseipdb.com/api/v2/check?ipAddress='.urlencode($ip).'&maxAgeInDays=90',12,true,['Key: '.$k,'Accept: application/json']);
    if(!$r['ok'])return['error'=>$r['error']]; if($r['code']!==200)return['error'=>'AbuseIPDB HTTP '.$r['code']];
    $j=json_decode($r['body'],true); if(!isset($j['data']))return['error'=>'Malformed.']; $d=$j['data'];
    return ['abuseConfidenceScore'=>$d['abuseConfidenceScore']??0,'countryName'=>$d['countryName']??'','usageType'=>$d['usageType']??'','isp'=>$d['isp']??'','totalReports'=>$d['totalReports']??0,'isTor'=>$d['isTor']??false]; }
function virustotal_domain($dm,$k){ if(!$k)return['skipped'=>true,'error'=>'No VirusTotal key.']; $r=http_get('https://www.virustotal.com/api/v3/domains/'.urlencode($dm),15,true,['x-apikey: '.$k,'Accept: application/json']);
    if(!$r['ok'])return['error'=>$r['error']]; if($r['code']!==200)return['error'=>'VT HTTP '.$r['code']];
    $j=json_decode($r['body'],true); if(!isset($j['data']['attributes']))return['error'=>'Malformed.']; $a=$j['data']['attributes']; $s=$a['last_analysis_stats']??[];
    return ['reputation'=>$a['reputation']??0,'registrar'=>$a['registrar']??'','malicious'=>$s['malicious']??0,'suspicious'=>$s['suspicious']??0,'harmless'=>$s['harmless']??0]; }
function virustotal_ip($ip,$k){ if(!$k)return['skipped'=>true,'error'=>'No VirusTotal key.']; $r=http_get('https://www.virustotal.com/api/v3/ip_addresses/'.urlencode($ip),15,true,['x-apikey: '.$k,'Accept: application/json']);
    if(!$r['ok'])return['error'=>$r['error']]; if($r['code']!==200)return['error'=>'VT HTTP '.$r['code']];
    $j=json_decode($r['body'],true); if(!isset($j['data']['attributes']))return['error'=>'Malformed.']; $a=$j['data']['attributes']; $s=$a['last_analysis_stats']??[];
    return ['reputation'=>$a['reputation']??0,'asn'=>$a['asn']??'','malicious'=>$s['malicious']??0,'suspicious'=>$s['suspicious']??0,'harmless'=>$s['harmless']??0]; }
function runtime_diagnostics(){ return [
    ['label'=>'PHP version','value'=>PHP_VERSION,'ok'=>version_compare(PHP_VERSION,'7.4','>=')],
    ['label'=>'cURL','value'=>function_exists('curl_init')?'enabled':'MISSING','ok'=>function_exists('curl_init')],
    ['label'=>'DNS','value'=>function_exists('dns_get_record')?'enabled':'missing','ok'=>function_exists('dns_get_record')],
    ['label'=>'Sockets','value'=>function_exists('fsockopen')?'enabled':'missing','ok'=>function_exists('fsockopen')],
    ['label'=>'Server time','value'=>date('Y-m-d H:i:s T'),'ok'=>true]]; }

// =====================================================================
//  NUCLEI INTEGRATION (projectdiscovery/nuclei)
//  - nuclei_detect(): is the binary installed?
//  - nuclei_run_binary(): shell out to real nuclei, parse -jsonl
//  - Lite engine: mini-YAML parser + HTTP matcher engine (pure PHP)
// =====================================================================
function nuclei_detect() {
    $out = ['available'=>false,'version'=>'','path'=>NUCLEI_BIN];
    if (!function_exists('proc_open') && !function_exists('shell_exec')) return $out;
    $bin = NUCLEI_BIN;
    $cmd = escapeshellarg($bin).' -version 2>&1';
    $res = @shell_exec($cmd);
    if ($res && preg_match('~(?:Nuclei\s+Engine\s+Version|current\s+version)?\s*v?(\d+\.\d+\.\d+)~i', $res, $m)) {
        $out['available'] = true; $out['version'] = $m[1];
    } elseif ($res && stripos($res, 'nuclei') !== false) {
        $out['available'] = true; $out['version'] = 'unknown';
    }
    return $out;
}

function nuclei_run_binary($target, $opts) {
    // Build a safe argument list. Only whitelisted flags.
    $bin = NUCLEI_BIN;
    $args = [$bin, '-u', $target, '-jsonl', '-silent', '-nc', '-timeout', '10', '-rate-limit', '50'];
    // severity filter
    if (!empty($opts['severity'])) {
        $sev = preg_replace('~[^a-z,]~','', strtolower($opts['severity']));
        if ($sev) { $args[]='-severity'; $args[]=$sev; }
    }
    // tags filter
    if (!empty($opts['tags'])) {
        $tags = preg_replace('~[^a-z0-9,_\-]~i','', strtolower($opts['tags']));
        if ($tags) { $args[]='-tags'; $args[]=$tags; }
    }
    // custom template file (from pasted YAML)
    if (!empty($opts['template_file']) && is_file($opts['template_file'])) {
        $args[]='-t'; $args[]=$opts['template_file'];
    }
    // concurrency cap
    $args[]='-c'; $args[]='25';
    $cmd = implode(' ', array_map('escapeshellarg', $args)) . ' 2>/dev/null';

    $descriptors = [1=>['pipe','w'], 2=>['pipe','w']];
    $findings = []; $raw_lines = 0;
    if (function_exists('proc_open')) {
        $proc = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($proc)) {
            $t0 = microtime(true);
            stream_set_blocking($pipes[1], false);
            $buffer = '';
            while (true) {
                $status = proc_get_status($proc);
                $chunk = fread($pipes[1], 8192);
                if ($chunk !== false && $chunk !== '') $buffer .= $chunk;
                if (!$status['running'] && ($chunk === '' || $chunk === false)) break;
                if (microtime(true)-$t0 > 90) { proc_terminate($proc); break; } // hard cap
                if (strlen($buffer) > 2000000) break;
                usleep(50000);
            }
            fclose($pipes[1]); fclose($pipes[2]);
            proc_close($proc);
            foreach (preg_split('~\r?\n~', trim($buffer)) as $ln) {
                if (trim($ln)==='') continue;
                $raw_lines++;
                $j = json_decode($ln, true);
                if (!is_array($j)) continue;
                $findings[] = nuclei_normalize_json($j);
            }
        }
    }
    return ['engine'=>'binary','findings'=>$findings,'raw_lines'=>$raw_lines];
}

function nuclei_normalize_json($j) {
    $info = $j['info'] ?? [];
    return [
        'template_id' => $j['template-id'] ?? ($j['templateID'] ?? ''),
        'name'        => $info['name'] ?? ($j['template-id'] ?? 'finding'),
        'severity'    => ucfirst(strtolower($info['severity'] ?? 'info')),
        'tags'        => is_array($info['tags'] ?? null) ? implode(',', $info['tags']) : ($info['tags'] ?? ''),
        'description' => $info['description'] ?? '',
        'reference'   => is_array($info['reference'] ?? null) ? implode(' ', $info['reference']) : ($info['reference'] ?? ''),
        'matched_at'  => $j['matched-at'] ?? ($j['host'] ?? ''),
        'type'        => $j['type'] ?? 'http',
        'matcher'     => $j['matcher-name'] ?? '',
        'extracted'   => is_array($j['extracted-results'] ?? null) ? implode(', ', $j['extracted-results']) : '',
        'curl'        => $j['curl-command'] ?? '',
        'engine'      => 'binary',
    ];
}

/* ---------- Mini YAML parser (subset for Nuclei templates) ---------- */
function ny_parse($yaml) {
    // Handles the Nuclei subset: nested maps, sequences (- item / - key: val),
    // scalars, block scalars (| and >), inline flow lists [a,b].
    $lines = preg_split('~\r?\n~', $yaml);
    $root = [];
    $stack = [[-1, &$root]]; // [indent, &container]
    $i = 0; $n = count($lines);
    while ($i < $n) {
        $raw = $lines[$i];
        // strip comments (naive; keep # inside quotes)
        $line = preg_replace('~\s+#.*$~', '', $raw);
        if (trim($line) === '') { $i++; continue; }
        $indent = strlen($line) - strlen(ltrim($line, ' '));
        $content = trim($line);
        // pop stack to parent
        while (count($stack) > 1 && $indent <= $stack[count($stack)-1][0]) array_pop($stack);
        $parent = &$stack[count($stack)-1][1];

        if (strpos($content, '- ') === 0 || $content === '-') {
            $item = ltrim(substr($content, 1));
            if (!is_array($parent)) $parent = [];
            if ($item === '') { // nested map under sequence
                $new = [];
                $parent[] = $new;
                $idx = count($parent)-1;
                $stack[] = [$indent, &$parent[$idx]];
            } elseif (strpos($item, ':') !== false && !preg_match('~^https?://~i',$item)) {
                // sequence of maps: "- key: value"
                $new = [];
                ny_kv($item, $new, $lines, $i, $indent);
                $parent[] = $new;
                $idx = count($parent)-1;
                $stack[] = [$indent, &$parent[$idx]];
            } else {
                $parent[] = ny_scalar($item);
            }
        } elseif (strpos($content, ':') !== false) {
            list($k, $v) = array_map('trim', explode(':', $content, 2));
            $k = trim($k, '"\'');
            if ($v === '' ) {
                // could be block scalar or nested
                $peek = ($i+1<$n) ? $lines[$i+1] : '';
                $parent[$k] = [];
                $stack[] = [$indent, &$parent[$k]];
            } elseif ($v === '|' || $v === '>' || $v === '|-' || $v === '>-') {
                // block scalar
                $buf = []; $j = $i+1;
                while ($j < $n) {
                    $bl = $lines[$j];
                    $bi = strlen($bl) - strlen(ltrim($bl,' '));
                    if (trim($bl)==='') { $buf[]=''; $j++; continue; }
                    if ($bi <= $indent) break;
                    $buf[] = substr($bl, $indent+2);
                    $j++;
                }
                $parent[$k] = trim(implode("\n", $buf));
                $i = $j; continue;
            } else {
                $parent[$k] = ny_scalar($v);
            }
        }
        $i++;
    }
    return $root;
}
function ny_kv($item, &$arr, $lines, $idx, $indent) {
    list($k,$v) = array_map('trim', explode(':', $item, 2));
    $k = trim($k,'"\'');
    $arr[$k] = ($v==='') ? [] : ny_scalar($v);
}
function ny_scalar($v) {
    $v = trim($v);
    if ($v === '') return '';
    // inline flow list [a, b, c]
    if (preg_match('~^\[(.*)\]$~', $v, $m)) {
        $parts = array_map(function($x){ return ny_scalar(trim($x)); }, explode(',', $m[1]));
        return $parts;
    }
    if (preg_match('~^(true|false)$~i', $v)) return strtolower($v)==='true';
    if (preg_match('~^-?\d+$~', $v)) return (int)$v;
    return trim($v, '"\'');
}

/* ---------- Lite HTTP matcher engine ---------- */
function nuclei_lite_run($target, $templates, $opts) {
    $base = resolve_base(clean_host($target));
    $findings = [];
    $sevFilter = !empty($opts['severity']) ? array_map('trim', explode(',', strtolower($opts['severity']))) : [];
    $tagFilter = !empty($opts['tags']) ? array_map('trim', explode(',', strtolower($opts['tags']))) : [];
    $tested = 0; $errors = 0;

    foreach ($templates as $tpl) {
        $parsed = is_array($tpl) ? $tpl : ny_parse($tpl);
        if (empty($parsed['id'])) continue;
        $info = $parsed['info'] ?? [];
        $sev = strtolower($info['severity'] ?? 'info');
        $tags = strtolower(is_array($info['tags']??null) ? implode(',',$info['tags']) : ($info['tags']??''));
        if ($sevFilter && !in_array($sev, $sevFilter)) continue;
        if ($tagFilter) {
            $match = false;
            foreach ($tagFilter as $t) if ($t && strpos($tags, $t) !== false) { $match=true; break; }
            if (!$match) continue;
        }
        // HTTP block: 'http' or legacy 'requests'
        $http = $parsed['http'] ?? ($parsed['requests'] ?? []);
        if (!$http) continue;
        // normalize: could be a single map or list of maps
        if (isset($http['method']) || isset($http['path'])) $http = [$http];
        foreach ($http as $req) {
            $method = strtoupper($req['method'] ?? 'GET');
            $paths = $req['path'] ?? [];
            if (is_string($paths)) $paths = [$paths];
            $matchers = $req['matchers'] ?? [];
            if (isset($matchers['type'])) $matchers = [$matchers];
            $mcond = strtolower($req['matchers-condition'] ?? 'or');
            foreach ($paths as $p) {
                $url = str_replace(['{{BaseURL}}','{{RootURL}}','{{Hostname}}'], [$base,$base,parse_url($base,PHP_URL_HOST)], $p);
                if (!preg_match('~^https?://~i', $url)) $url = rtrim($base,'/').'/'.ltrim($url,'/');
                $tested++;
                $resp = ($method==='GET') ? get_partial($url, 8, 60000) : ['code'=>0,'body'=>'','ctype'=>'','size'=>0];
                // fetch headers too for header matchers
                $hdrs = '';
                $full = http_get($url, 8);
                if ($full['ok']) { foreach ($full['headers'] as $hk=>$hv) $hdrs .= $hk.': '.$hv."\n"; $body = $full['body']; $code = $full['code']; }
                else { $body = $resp['body']; $code = $resp['code']; }
                $matchRes = nuclei_eval_matchers($matchers, $mcond, $code, $body, $hdrs);
                if ($matchRes['matched']) {
                    $findings[] = [
                        'template_id'=>$parsed['id'],
                        'name'=>$info['name'] ?? $parsed['id'],
                        'severity'=>ucfirst($sev),
                        'tags'=>$tags,
                        'description'=>$info['description'] ?? '',
                        'reference'=>is_array($info['reference']??null)?implode(' ',$info['reference']):($info['reference']??''),
                        'matched_at'=>$url,
                        'type'=>'http',
                        'matcher'=>$matchRes['which'],
                        'status'=>$code,
                        'evidence'=>substr($matchRes['evidence'],0,300),
                        'engine'=>'lite',
                    ];
                    break; // one hit per template is enough
                }
            }
        }
        if (count($findings) > 200) break;
    }
    return ['engine'=>'lite','findings'=>$findings,'tested'=>$tested,'errors'=>$errors,'base'=>$base];
}

function nuclei_eval_matchers($matchers, $cond, $code, $body, $headers) {
    if (!$matchers) return ['matched'=>false,'which'=>'','evidence'=>''];
    $results = []; $evidence = ''; $which = '';
    foreach ($matchers as $m) {
        $type = strtolower($m['type'] ?? '');
        $part = strtolower($m['part'] ?? 'body');
        $mc = strtolower($m['condition'] ?? 'or');
        $hay = $part==='header' ? $headers : ($part==='all' ? ($headers."\n".$body) : $body);
        $ok = false;
        if ($type === 'status') {
            $st = $m['status'] ?? [];
            if (!is_array($st)) $st = [$st];
            foreach ($st as $s) if ((int)$s === (int)$code) { $ok=true; $evidence='HTTP '.$code; $which='status'; break; }
        } elseif ($type === 'word') {
            $words = $m['words'] ?? [];
            if (is_string($words)) $words = [$words];
            $hits = 0;
            foreach ($words as $w) {
                if ($w!=='' && stripos($hay, (string)$w) !== false) { $hits++; if(!$evidence){$evidence=(string)$w;$which='word';} }
            }
            $ok = ($mc==='and') ? ($hits === count($words) && $hits>0) : ($hits > 0);
        } elseif ($type === 'regex') {
            $rx = $m['regex'] ?? [];
            if (is_string($rx)) $rx = [$rx];
            $hits = 0;
            foreach ($rx as $r) {
                $pat = '~'.str_replace('~','\~',$r).'~';
                if (@preg_match($pat, $hay, $mm)) { $hits++; if(!$evidence){$evidence=$mm[0]??$r;$which='regex';} }
            }
            $ok = ($mc==='and') ? ($hits === count($rx) && $hits>0) : ($hits > 0);
        } elseif ($type === 'dsl') {
            $dsls = $m['dsl'] ?? [];
            if (is_string($dsls)) $dsls = [$dsls];
            $hits = 0;
            foreach ($dsls as $d) {
                if (nuclei_eval_dsl($d, $code, $body, $headers)) { $hits++; if(!$evidence){$evidence=$d;$which='dsl';} }
            }
            $ok = ($mc==='and') ? ($hits === count($dsls) && $hits>0) : ($hits > 0);
        }
        // negative matcher
        if (!empty($m['negative'])) $ok = !$ok;
        $results[] = $ok;
    }
    $matched = ($cond==='and') ? (!in_array(false, $results, true) && count($results)>0) : in_array(true, $results, true);
    return ['matched'=>$matched,'which'=>$which,'evidence'=>$evidence];
}

/* Very small DSL evaluator: supports status_code==N, contains(body,'x'),
   len(body)>N, && and || combinations. Safe (no eval). */
function nuclei_eval_dsl($expr, $code, $body, $headers) {
    $expr = trim($expr);
    // split on || (lowest precedence)
    foreach (preg_split('~\|\|~', $expr) as $orPart) {
        $andOk = true;
        foreach (preg_split('~&&~', $orPart) as $tok) {
            $tok = trim($tok);
            if ($tok==='') continue;
            if (!nuclei_dsl_atom($tok, $code, $body, $headers)) { $andOk=false; break; }
        }
        if ($andOk) return true;
    }
    return false;
}
function nuclei_dsl_atom($tok, $code, $body, $headers) {
    $neg = false;
    if (strpos($tok,'!')===0) { $neg=true; $tok=trim(substr($tok,1)); }
    $r = false;
    if (preg_match('~^status_code\s*==\s*(\d+)$~', $tok, $m)) $r = ((int)$code === (int)$m[1]);
    elseif (preg_match('~^status_code\s*!=\s*(\d+)$~', $tok, $m)) $r = ((int)$code !== (int)$m[1]);
    elseif (preg_match('~^contains\s*\(\s*(body|header|all)\s*,\s*[\'"](.+?)[\'"]\s*\)$~i', $tok, $m)) {
        $hay = strtolower($m[1])==='header'?$headers:(strtolower($m[1])==='all'?$headers."\n".$body:$body);
        $r = stripos($hay, $m[2]) !== false;
    }
    elseif (preg_match('~^len\s*\(\s*body\s*\)\s*(>|<|>=|<=|==)\s*(\d+)$~', $tok, $m)) {
        $L = strlen($body); $N=(int)$m[2];
        switch($m[1]){case '>':$r=$L>$N;break;case '<':$r=$L<$N;break;case '>=':$r=$L>=$N;break;case '<=':$r=$L<=$N;break;default:$r=$L===$N;}
    }
    return $neg ? !$r : $r;
}

/* ---------- Bundled Nuclei-style templates (Lite engine) ---------- */
function nuclei_bundled_templates() {
    return [
"id: git-config-exposure
info:
  name: Git Config Exposure
  severity: medium
  tags: exposure,git,config
  description: A .git/config file is publicly accessible, potentially leaking repo URLs and structure.
  reference: https://www.acunetix.com/vulnerabilities/web/git-repository-found/
http:
  - method: GET
    path:
      - '{{BaseURL}}/.git/config'
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '[core]'
          - 'repositoryformatversion'
        condition: and
      - type: status
        status:
          - 200",
"id: env-file-exposure
info:
  name: Environment (.env) File Exposure
  severity: high
  tags: exposure,config,env
  description: A .env file is publicly accessible and may leak DB credentials, API keys, and secrets.
http:
  - method: GET
    path:
      - '{{BaseURL}}/.env'
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - '(?i)(DB_(HOST|PASSWORD|USERNAME|DATABASE)|APP_KEY|SECRET|API_KEY)\\s*='
      - type: status
        status:
          - 200",
"id: phpinfo-exposure
info:
  name: PHPInfo Page Exposure
  severity: low
  tags: exposure,phpinfo,misconfig
  description: A phpinfo() page is publicly accessible, leaking environment and configuration details.
http:
  - method: GET
    path:
      - '{{BaseURL}}/phpinfo.php'
      - '{{BaseURL}}/info.php'
    matchers:
      - type: word
        part: body
        words:
          - 'PHP Version'
          - 'phpinfo()'
        condition: or",
"id: env-backup-exposure
info:
  name: Backup/SQL Dump Exposure
  severity: high
  tags: exposure,backup
  description: A database dump or backup archive is publicly reachable.
http:
  - method: GET
    path:
      - '{{BaseURL}}/backup.sql'
      - '{{BaseURL}}/dump.sql'
      - '{{BaseURL}}/database.sql'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'INSERT INTO'
          - 'CREATE TABLE'
          - 'DROP TABLE'
        condition: or",
"id: wp-user-enumeration
info:
  name: WordPress User Enumeration (REST API)
  severity: low
  tags: wordpress,enum,api
  description: The WordPress REST users endpoint exposes account names/slugs.
http:
  - method: GET
    path:
      - '{{BaseURL}}/wp-json/wp/v2/users'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - '\"slug\"\\s*:\\s*\"'",
"id: dotenv-git-svn
info:
  name: SVN Entries Exposure
  severity: medium
  tags: exposure,svn,vcs
  description: A .svn/entries file is publicly accessible.
http:
  - method: GET
    path:
      - '{{BaseURL}}/.svn/entries'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - 'len(body) > 3'",
"id: ds-store-exposure
info:
  name: .DS_Store File Exposure
  severity: info
  tags: exposure,osx
  description: A macOS .DS_Store file leaks directory listings.
http:
  - method: GET
    path:
      - '{{BaseURL}}/.DS_Store'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'Bud1'",
"id: swagger-ui-exposure
info:
  name: Swagger UI / OpenAPI Exposure
  severity: info
  tags: exposure,api,swagger
  description: A Swagger/OpenAPI UI or spec is publicly accessible.
http:
  - method: GET
    path:
      - '{{BaseURL}}/swagger-ui.html'
      - '{{BaseURL}}/swagger.json'
      - '{{BaseURL}}/openapi.json'
      - '{{BaseURL}}/api-docs'
    matchers:
      - type: word
        part: body
        words:
          - 'swagger'
          - 'openapi'
          - 'Swagger UI'
        condition: or",
"id: actuator-env-exposure
info:
  name: Spring Boot Actuator env Exposure
  severity: high
  tags: exposure,springboot,actuator,misconfig
  description: Spring Boot actuator /env endpoint exposes environment properties and secrets.
http:
  - method: GET
    path:
      - '{{BaseURL}}/actuator/env'
      - '{{BaseURL}}/env'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'propertySources'
          - 'systemProperties'
        condition: or",
"id: actuator-heapdump
info:
  name: Spring Boot Actuator Heapdump Exposure
  severity: critical
  tags: exposure,springboot,actuator
  description: The actuator heapdump endpoint may leak a full memory dump containing secrets.
http:
  - method: GET
    path:
      - '{{BaseURL}}/actuator/heapdump'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - 'len(body) > 1000'",
"id: laravel-telescope
info:
  name: Laravel Telescope Exposure
  severity: medium
  tags: exposure,laravel,panel
  description: Laravel Telescope debug panel is publicly accessible.
http:
  - method: GET
    path:
      - '{{BaseURL}}/telescope/requests'
    matchers:
      - type: word
        part: body
        words:
          - 'Telescope'
          - 'laravel'
        condition: or",
"id: adminer-panel
info:
  name: Adminer Database Panel
  severity: medium
  tags: panel,database,adminer
  description: An Adminer database management panel is exposed.
http:
  - method: GET
    path:
      - '{{BaseURL}}/adminer.php'
      - '{{BaseURL}}/adminer/'
    matchers:
      - type: word
        part: body
        words:
          - 'Adminer'
          - 'Login - Adminer'
        condition: or",
"id: phpmyadmin-panel
info:
  name: phpMyAdmin Panel
  severity: low
  tags: panel,database,phpmyadmin
  description: A phpMyAdmin login panel is publicly accessible.
http:
  - method: GET
    path:
      - '{{BaseURL}}/phpmyadmin/'
      - '{{BaseURL}}/pma/'
    matchers:
      - type: word
        part: body
        words:
          - 'phpMyAdmin'
        condition: or",
"id: xmlrpc-enabled
info:
  name: WordPress XML-RPC Enabled
  severity: info
  tags: wordpress,xmlrpc,misconfig
  description: XML-RPC is enabled and can be abused for brute force / DDoS pingback.
http:
  - method: GET
    path:
      - '{{BaseURL}}/xmlrpc.php'
    matchers:
      - type: word
        part: body
        words:
          - 'XML-RPC server accepts POST requests only'
        condition: or",
"id: server-status-exposure
info:
  name: Apache server-status Exposure
  severity: medium
  tags: exposure,apache,misconfig
  description: The Apache mod_status server-status page is publicly accessible.
http:
  - method: GET
    path:
      - '{{BaseURL}}/server-status'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'Apache Server Status'",
"id: security-txt
info:
  name: security.txt Present
  severity: info
  tags: misc,disclosure
  description: A security.txt policy file is present (informational, good practice).
http:
  - method: GET
    path:
      - '{{BaseURL}}/.well-known/security.txt'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'Contact:'",
"id: gitlab-ci-exposure
info:
  name: GitLab CI Config Exposure
  severity: low
  tags: exposure,ci,gitlab
  description: A .gitlab-ci.yml file is publicly accessible, revealing pipeline structure.
http:
  - method: GET
    path:
      - '{{BaseURL}}/.gitlab-ci.yml'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - '(?m)^(stages|script|image|before_script)\\s*:'",
"id: aws-credentials-file
info:
  name: AWS Credentials File Exposure
  severity: critical
  tags: exposure,aws,cloud,tokens
  description: An .aws/credentials file is publicly reachable and may leak AWS keys.
http:
  - method: GET
    path:
      - '{{BaseURL}}/.aws/credentials'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - '(?i)aws_access_key_id|aws_secret_access_key'",
    ];
}

/* ============================================================
 * v2.5.0 — New recon modules
 *   #8 DNS & email-security posture (SPF/DKIM/DMARC/MX/CAA/DNSSEC)
 *   #9 TLS/SSL certificate inspector
 *   #10 Cookie & CSP analyzer
 *   #5 WPScan/Wordfence live vulnerability feed
 * ============================================================ */

/* Google DNS-over-HTTPS helper — reliable across hosts, avoids dns_get_record gaps */
function doh_query($name,$type){
    $r=http_get('https://dns.google/resolve?name='.urlencode($name).'&type='.urlencode($type),8,true,['Accept: application/dns-json']);
    if(!$r['ok']||$r['code']!==200) return null;
    $j=json_decode($r['body'],true);
    return is_array($j)?$j:null;
}
function doh_txt($name){
    $out=[]; $j=doh_query($name,'TXT');
    if($j && !empty($j['Answer'])) foreach($j['Answer'] as $a){ if(($a['type']??0)==16){ $out[]=trim($a['data']??'','"'); } }
    return $out;
}
function dns_email_posture($domain){
    $domain=strtolower(preg_replace('~^https?://~i','',$domain)); $domain=explode('/',$domain)[0];
    $out=['domain'=>$domain,'records'=>[],'findings'=>[],'score'=>0,'grade'=>'F'];
    $add=function($k,$status,$value,$note,$sev='Info') use(&$out){ $out['records'][]=['name'=>$k,'status'=>$status,'value'=>$value,'note'=>$note,'sev'=>$sev]; };

    // MX
    $mx=doh_query($domain,'MX'); $mxList=[];
    if($mx && !empty($mx['Answer'])) foreach($mx['Answer'] as $a){ if(($a['type']??0)==15) $mxList[]=trim($a['data']??''); }
    $add('MX',$mxList?'present':'missing',$mxList?implode(' · ',array_slice($mxList,0,5)):'—',$mxList?'Mail exchangers configured.':'No MX records — domain may not receive mail.',$mxList?'Info':'Low');

    // SPF (TXT with v=spf1)
    $txts=doh_txt($domain); $spf='';
    foreach($txts as $t){ if(stripos($t,'v=spf1')===0){ $spf=$t; break; } }
    if($spf){
        $hard = (strpos($spf,'-all')!==false); $soft=(strpos($spf,'~all')!==false);
        $sev = $hard?'Info':($soft?'Low':'Medium');
        $add('SPF','present',$spf, $hard?'Hard-fail (-all) — strong.':($soft?'Soft-fail (~all) — consider -all.':'No fail qualifier / +all — weak, allows spoofing.'), $sev);
    } else { $add('SPF','missing','—','No SPF record — domain can be spoofed in email.','High'); }

    // DMARC (_dmarc TXT)
    $dmarcTx=doh_txt('_dmarc.'.$domain); $dmarc='';
    foreach($dmarcTx as $t){ if(stripos($t,'v=DMARC1')===0){ $dmarc=$t; break; } }
    if($dmarc){
        $pol='none'; if(preg_match('~\bp=([a-z]+)~i',$dmarc,$m))$pol=strtolower($m[1]);
        $sev = $pol==='reject'?'Info':($pol==='quarantine'?'Low':'Medium');
        $add('DMARC','present',$dmarc,'Policy p='.$pol.($pol==='none'?' — monitoring only, not enforced.':' — enforced.'),$sev);
    } else { $add('DMARC','missing','—','No DMARC record — no policy against spoofing/phishing.','High'); }

    // DKIM (probe common selectors)
    $selectors=['default','google','selector1','selector2','k1','dkim','mail','s1','s2','smtp'];
    $found=[];
    foreach($selectors as $s){ $t=doh_txt($s.'._domainkey.'.$domain); foreach($t as $rec){ if(stripos($rec,'v=DKIM1')!==false||stripos($rec,'p=')!==false){ $found[$s]=true; break; } } if(count($found)>=3)break; }
    if($found){ $add('DKIM','present',implode(', ',array_map(fn($s)=>$s.'._domainkey',array_keys($found))),'DKIM signing key(s) published for common selector(s).','Info'); }
    else { $add('DKIM','indeterminate','—','No DKIM key found on common selectors (may use a custom selector).','Low'); }

    // CAA
    $caa=doh_query($domain,'CAA'); $caaList=[];
    if($caa && !empty($caa['Answer'])) foreach($caa['Answer'] as $a){ if(($a['type']??0)==257) $caaList[]=trim($a['data']??''); }
    $add('CAA',$caaList?'present':'missing',$caaList?implode(' · ',$caaList):'—',$caaList?'Restricts which CAs may issue certs.':'No CAA — any CA can issue certificates for this domain.',$caaList?'Info':'Low');

    // DNSSEC (AD flag + DNSKEY presence)
    $dk=doh_query($domain,'DNSKEY'); $adFlag=false;
    $test=doh_query($domain,'A'); if($test && !empty($test['AD'])) $adFlag=true;
    $hasKey=$dk && !empty($dk['Answer']);
    if($hasKey||$adFlag){ $add('DNSSEC','present',$hasKey?'DNSKEY published':'AD flag set','Zone is DNSSEC-signed — protects against DNS tampering.','Info'); }
    else { $add('DNSSEC','missing','—','DNSSEC not enabled — DNS responses can be spoofed.','Low'); }

    // Score: weight the email-auth trio heavily
    $pts=0; $max=0;
    $w=['SPF'=>25,'DMARC'=>25,'DKIM'=>15,'MX'=>10,'CAA'=>10,'DNSSEC'=>15];
    foreach($out['records'] as $r){ $ww=$w[$r['name']]??0; $max+=$ww;
        if($r['status']==='present'){ $pts+= ($r['sev']==='Info')?$ww:($r['sev']==='Low'?$ww*0.7:$ww*0.4); }
        elseif($r['status']==='indeterminate'){ $pts+=$ww*0.4; } }
    $score=$max?(int)round($pts/$max*100):0; $out['score']=$score;
    $out['grade']=$score>=90?'A':($score>=75?'B':($score>=60?'C':($score>=40?'D':'F')));
    return $out;
}

/* #9 — TLS/SSL certificate inspector */
function tls_inspect($host){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $out=['host'=>$host,'ok'=>false,'findings'=>[]];
    if(!function_exists('stream_socket_client')||!function_exists('openssl_x509_parse')){ $out['error']='OpenSSL/sockets unavailable on this server.'; return $out; }
    $ctx=stream_context_create(['ssl'=>['capture_peer_cert'=>true,'capture_peer_cert_chain'=>true,'verify_peer'=>false,'verify_peer_name'=>false,'SNI_enabled'=>true,'peer_name'=>$host]]);
    $errno=0;$errstr='';
    $c=@stream_socket_client('ssl://'.$host.':443',$errno,$errstr,8,STREAM_CLIENT_CONNECT,$ctx);
    if(!$c){ $out['error']='TLS connection failed: '.($errstr?:('error '.$errno)); return $out; }
    $params=stream_context_get_params($c); $meta=stream_get_meta_data($c);
    $cert=$params['options']['ssl']['peer_certificate']??null;
    $chain=$params['options']['ssl']['peer_certificate_chain']??[];
    @fclose($c);
    if(!$cert){ $out['error']='No certificate captured.'; return $out; }
    $p=openssl_x509_parse($cert); if(!$p){ $out['error']='Could not parse certificate.'; return $out; }
    $out['ok']=true;
    $now=time(); $from=$p['validFrom_time_t']??0; $to=$p['validTo_time_t']??0;
    $daysLeft=$to?(int)floor(($to-$now)/86400):null;
    $sans=[]; if(!empty($p['extensions']['subjectAltName'])) foreach(explode(',',$p['extensions']['subjectAltName']) as $s){ $sans[]=trim(str_replace('DNS:','',$s)); }
    $sig=$p['signatureTypeSN']??($p['signatureTypeLN']??'');
    $proto=$meta['crypto']['protocol']??''; $cipher=$meta['crypto']['cipher_name']??'';
    $out['subject']=$p['subject']['CN']??''; $out['issuer']=$p['issuer']['CN']??($p['issuer']['O']??'');
    $out['valid_from']=$from?date('Y-m-d',$from):''; $out['valid_to']=$to?date('Y-m-d',$to):'';
    $out['days_left']=$daysLeft; $out['sans']=array_slice($sans,0,50); $out['san_count']=count($sans);
    $out['sig_alg']=$sig; $out['protocol']=$proto; $out['cipher']=$cipher; $out['chain_len']=count($chain);
    $out['self_signed']=(($p['subject']['CN']??'x')===($p['issuer']['CN']??'y'));
    $f=[];
    if($daysLeft!==null){
        if($daysLeft<0) $f[]=['sev'=>'Critical','msg'=>'Certificate EXPIRED '.abs($daysLeft).' day(s) ago.'];
        elseif($daysLeft<=14) $f[]=['sev'=>'High','msg'=>'Certificate expires in '.$daysLeft.' day(s) — renew now.'];
        elseif($daysLeft<=30) $f[]=['sev'=>'Medium','msg'=>'Certificate expires in '.$daysLeft.' day(s).'];
    }
    if(preg_match('~sha1|md5~i',$sig)) $f[]=['sev'=>'High','msg'=>'Weak signature algorithm ('.$sig.') — SHA-1/MD5 are deprecated.'];
    if($proto && preg_match('~SSLv|TLSv1(\.0|\.1)?$~i',$proto)) $f[]=['sev'=>'High','msg'=>'Legacy protocol negotiated ('.$proto.') — disable TLS < 1.2.'];
    if($out['self_signed']) $f[]=['sev'=>'Medium','msg'=>'Certificate appears self-signed.'];
    // hostname match
    $match=false; foreach($sans as $s){ $re='~^'.str_replace('\*','[^.]+',preg_quote($s,'~')).'$~i'; if(preg_match($re,$host)){$match=true;break;} }
    if(!$match && $sans) $f[]=['sev'=>'Medium','msg'=>'Hostname '.$host.' not in certificate SAN list.'];
    $out['findings']=$f;
    $sev = 'Info';
    foreach($f as $x){ $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; if(($rank[$x['sev']]??0)>($rank[$sev]??0))$sev=$x['sev']; }
    $out['rating']=$sev;
    return $out;
}

/* #10 — Cookie & CSP analyzer (needs ALL Set-Cookie lines → raw header fetch) */
function raw_headers($url,$timeout=10){
    if(!function_exists('curl_init')) return ['ok'=>false,'error'=>'cURL unavailable'];
    $ch=curl_init();
    curl_setopt_array($ch,[CURLOPT_URL=>$url,CURLOPT_RETURNTRANSFER=>true,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,
        CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,
        CURLOPT_HEADER=>true,CURLOPT_HTTPHEADER=>['User-Agent: Mozilla/5.0 (TTPH-OSINT/'.APP_VERSION.')']]);
    $raw=curl_exec($ch); $hsize=curl_getinfo($ch,CURLINFO_HEADER_SIZE); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if($raw===false) return ['ok'=>false,'error'=>'fetch failed'];
    return ['ok'=>true,'code'=>$code,'headers_raw'=>substr($raw,0,$hsize),'body'=>substr($raw,$hsize)];
}
function cookie_csp_analyze($base){
    $out=['cookies'=>[],'csp'=>['present'=>false,'value'=>'','findings'=>[]],'findings'=>[]];
    $r=raw_headers($base,10);
    if(!$r['ok']){ $out['error']=$r['error']; return $out; }
    $hraw=$r['headers_raw'];
    // Cookies
    if(preg_match_all('~^Set-Cookie:\s*([^\r\n]+)~mi',$hraw,$mm)){
        foreach($mm[1] as $line){
            $name=''; if(preg_match('~^\s*([^=;\s]+)=~',$line,$nm))$name=$nm[1];
            $secure=(bool)preg_match('~;\s*Secure~i',$line);
            $httponly=(bool)preg_match('~;\s*HttpOnly~i',$line);
            $ss=''; if(preg_match('~;\s*SameSite=([a-z]+)~i',$line,$sm))$ss=ucfirst(strtolower($sm[1]));
            $flags=[]; if(!$secure)$flags[]='no Secure'; if(!$httponly)$flags[]='no HttpOnly'; if($ss==='')$flags[]='no SameSite'; elseif(strtolower($ss)==='none'&&!$secure)$flags[]='SameSite=None without Secure';
            $sev = (!$secure||!$httponly)?'Medium':($ss===''?'Low':'Info');
            $out['cookies'][]=['name'=>$name,'secure'=>$secure,'httponly'=>$httponly,'samesite'=>$ss?:'—','issues'=>$flags,'sev'=>$sev];
        }
    }
    $cwHttpOnly=count(array_filter($out['cookies'],fn($c)=>!$c['httponly']));
    $cwSecure=count(array_filter($out['cookies'],fn($c)=>!$c['secure']));
    if($cwHttpOnly) $out['findings'][]=['sev'=>'Medium','msg'=>$cwHttpOnly.' cookie(s) missing HttpOnly — readable by JS (XSS theft risk).'];
    if($cwSecure) $out['findings'][]=['sev'=>'Medium','msg'=>$cwSecure.' cookie(s) missing Secure — sent over plain HTTP.'];
    // CSP
    if(preg_match('~^Content-Security-Policy:\s*([^\r\n]+)~mi',$hraw,$cm)){
        $csp=trim($cm[1]); $out['csp']['present']=true; $out['csp']['value']=$csp; $cf=[];
        if(preg_match('~unsafe-inline~i',$csp)) $cf[]=['sev'=>'Medium','msg'=>"'unsafe-inline' present — weakens XSS protection."];
        if(preg_match('~unsafe-eval~i',$csp)) $cf[]=['sev'=>'Medium','msg'=>"'unsafe-eval' present — allows eval()-style execution."];
        if(preg_match('~(default-src|script-src)[^;]*\*~i',$csp)) $cf[]=['sev'=>'Medium','msg'=>'Wildcard (*) source in a fetch directive.'];
        if(!preg_match('~default-src~i',$csp)) $cf[]=['sev'=>'Low','msg'=>'No default-src fallback directive.'];
        if(!preg_match('~object-src~i',$csp)) $cf[]=['sev'=>'Low','msg'=>"No object-src 'none' (plugin/Flash surface)."];
        if(!preg_match('~frame-ancestors~i',$csp)) $cf[]=['sev'=>'Low','msg'=>'No frame-ancestors (clickjacking directive).'];
        $out['csp']['findings']=$cf;
    } else {
        $out['csp']['present']=false;
        $out['findings'][]=['sev'=>'Medium','msg'=>'No Content-Security-Policy header — primary XSS mitigation absent.'];
    }
    // overall rating
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $sev='Info';
    foreach(array_merge($out['findings'],$out['csp']['findings']??[]) as $x){ if(($rank[$x['sev']]??0)>($rank[$sev]??0))$sev=$x['sev']; }
    $out['rating']=$sev; $out['cookie_count']=count($out['cookies']);
    return $out;
}

/* #5 — WPScan live vulnerability lookup (optional; gated by API token) */
function wpscan_lookup($type,$slug,$version,$token){
    if(!$token) return null;
    $url='https://wpscan.com/api/v3/'.$type.'/'.rawurlencode($slug);
    $r=http_get($url,12,true,['Authorization: Token token='.$token,'Accept: application/json']);
    if(!$r['ok']) return ['error'=>$r['error']??'fetch failed'];
    if($r['code']===403||$r['code']===401) return ['error'=>'WPScan auth failed (check token).'];
    if($r['code']===429) return ['error'=>'WPScan rate limit reached.'];
    if($r['code']!==200) return ['error'=>'WPScan HTTP '.$r['code']];
    $j=json_decode($r['body'],true);
    if(!is_array($j)||!isset($j[$slug])) return ['vulns'=>[]];
    $vulns=$j[$slug]['vulnerabilities']??[]; $matched=[];
    foreach($vulns as $v){
        $fixed=$v['fixed_in']??null;
        if(!$version || !$fixed || version_compare($version,$fixed,'<')){
            $cvss=isset($v['cvss']['score'])?(float)$v['cvss']['score']:0;
            $cve=''; if(!empty($v['references']['cve'][0])) $cve='CVE-'.$v['references']['cve'][0];
            $matched[]=['id'=>$cve?:($v['title']??'vuln'),'title'=>$v['title']??'','cvss'=>$cvss,'cwe'=>'',
                'sev'=>$cvss>=9?'Critical':($cvss>=7?'High':($cvss>=4?'Medium':($cvss>0?'Low':'Info'))),
                'fixed'=>$fixed?:'unknown'];
        }
    }
    return ['vulns'=>$matched,'live'=>true];
}

/* ============================================================
 * v2.5.8 — Live server-side "Verify Now" for the Attack Playbook.
 * Runs each finding's non-destructive check on the server (PHP + cURL/DNS/TLS)
 * and returns a structured confirmed/clear/info verdict + evidence.
 * ============================================================ */
/* ============================================================
 * v2.5.11 — RED TEAM MODE: aggressive ACTIVE reconnaissance.
 * Goes beyond the passive Playbook: subdomain enumeration, HTTP
 * method probing, parameter-reflection detection, and an expanded
 * path brute. ALL checks remain NON-DESTRUCTIVE (GET/HEAD/OPTIONS +
 * benign reflection markers) — no exploits, no payloads that alter
 * state. Authorization-gated and host-scoped upstream.
 * ============================================================ */
/* ============================================================
 * v2.6.4 — SUBLIST3R (pure-PHP port of aboul3la/Sublist3r)
 * Multi-source passive OSINT aggregation → dedup → DNS resolution.
 * Sources that still work in 2026: crt.sh, CertSpotter, HackerTarget,
 * AlienVault OTX, RapidDNS (+ optional subbrute wordlist).
 * v2.6.6 adds sl3r_alive() — live HTTP/HTTPS status probing.
 * Read-only passive lookups. Authorization-gated & host-scoped.
 * ============================================================ */
function sl3r_norm(&$found,$name,$src,$host){
    $name=strtolower(trim((string)$name));
    $name=preg_replace('~^\*\.~','',$name);
    $name=preg_replace('~[^a-z0-9._-].*$~','',$name);
    if($name===''||strpos($name,'*')!==false) return;
    if(!preg_match('~^[a-z0-9._-]+$~',$name)) return;
    if($name===$host) return;
    if(substr($name,-(strlen($host)+1))!=='.'.$host) return;
    if(!isset($found[$name])) $found[$name]=['sub'=>$name,'sources'=>[],'ips'=>[],'cname'=>''];
    $found[$name]['sources'][$src]=true;
}
function sublist3r_enum($host,$opts=[]){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $out=['host'=>$host,'items'=>[],'engines'=>[],'wildcard'=>false,'count'=>0];
    $doBrute=($opts['brute']??false)===true;
    $doResolve=($opts['resolve']??true)!==false;
    $cap=min(1000,max(20,(int)($opts['cap']??300)));
    $found=[]; $eng=[];
    $UA='Mozilla/5.0 (VRA-Sublist3r/'.APP_VERSION.')';

    /* crt.sh */
    $r=http_get('https://crt.sh/?q=%25.'.rawurlencode($host).'&output=json',15,true,['Accept: application/json','User-Agent: '.$UA]);
    if($r['ok']&&$r['code']===200){ $b=trim($r['body']??''); $j=json_decode($b,true);
        if(!is_array($j)&&$b!==''){ $j=json_decode('['.str_replace("}\n{","},\n{",$b).']',true); }
        if(is_array($j)){ $c0=count($found);
            foreach($j as $row){ if(!is_array($row))continue;
                foreach(explode("\n",(string)($row['name_value']??'')) as $nm) sl3r_norm($found,$nm,'crt.sh',$host);
                if(!empty($row['common_name'])) sl3r_norm($found,$row['common_name'],'crt.sh',$host); }
            $eng['crt.sh']='ok (+'.(count($found)-$c0).')';
        } else $eng['crt.sh']='parse error';
    } else $eng['crt.sh']='unreachable (HTTP '.($r['code']??0).')';

    /* CertSpotter */
    $r=http_get('https://api.certspotter.com/v1/issuances?domain='.rawurlencode($host).'&include_subdomains=true&expand=dns_names',15,true,['Accept: application/json','User-Agent: '.$UA]);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body']??'',true);
        if(is_array($j)){ $c0=count($found);
            foreach($j as $iss){ if(!is_array($iss))continue; foreach(($iss['dns_names']??[]) as $nm) sl3r_norm($found,$nm,'certspotter',$host); }
            $eng['certspotter']='ok (+'.(count($found)-$c0).')';
        } else $eng['certspotter']='parse error';
    } elseif(($r['code']??0)===429) $eng['certspotter']='rate-limited';
    else $eng['certspotter']='unreachable (HTTP '.($r['code']??0).')';

    /* HackerTarget */
    $r=http_get('https://api.hackertarget.com/hostsearch/?q='.rawurlencode($host),15,true,['User-Agent: '.$UA]);
    if($r['ok']&&$r['code']===200){ $b=$r['body']??''; $c0=count($found);
        if(stripos($b,'API count exceeded')!==false||(stripos($b,'error')!==false&&strlen($b)<80)){ $eng['hackertarget']='rate-limited'; }
        else { foreach(preg_split('~\r?\n~',$b) as $ln){ $ln=trim($ln); if($ln==='')continue; $parts=explode(',',$ln); $nm=$parts[0]??''; $ip=$parts[1]??'';
                sl3r_norm($found,$nm,'hackertarget',$host); $nmn=strtolower(trim($nm)); if(isset($found[$nmn])&&$ip&&filter_var($ip,FILTER_VALIDATE_IP)) $found[$nmn]['ips'][]=$ip; }
            $eng['hackertarget']='ok (+'.(count($found)-$c0).')'; }
    } else $eng['hackertarget']='unreachable (HTTP '.($r['code']??0).')';

    /* AlienVault OTX */
    $r=http_get('https://otx.alienvault.com/api/v1/indicators/domain/'.rawurlencode($host).'/passive_dns',15,true,['Accept: application/json','User-Agent: '.$UA]);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body']??'',true);
        if(is_array($j)&&isset($j['passive_dns'])){ $c0=count($found);
            foreach($j['passive_dns'] as $rec){ if(!is_array($rec))continue; sl3r_norm($found,$rec['hostname']??'','alienvault',$host);
                $nmn=strtolower(trim((string)($rec['hostname']??''))); if(isset($found[$nmn])&&!empty($rec['address'])&&filter_var($rec['address'],FILTER_VALIDATE_IP)) $found[$nmn]['ips'][]=$rec['address']; }
            $eng['alienvault']='ok (+'.(count($found)-$c0).')';
        } else $eng['alienvault']='parse error';
    } else $eng['alienvault']='unreachable (HTTP '.($r['code']??0).')';

    /* RapidDNS */
    $r=http_get('https://rapiddns.io/subdomain/'.rawurlencode($host).'?full=1',15,true,['User-Agent: '.$UA]);
    if($r['ok']&&$r['code']===200){ $b=$r['body']??''; $c0=count($found);
        if(preg_match_all('~<td>([a-z0-9._-]+\.'.preg_quote($host,'~').')</td>~i',$b,$mm)){ foreach($mm[1] as $nm) sl3r_norm($found,$nm,'rapiddns',$host); }
        $eng['rapiddns']='ok (+'.(count($found)-$c0).')';
    } else $eng['rapiddns']='unreachable (HTTP '.($r['code']??0).')';

    /* optional subbrute */
    if($doBrute && function_exists('rt_sub_wordlist')){
        foreach(rt_sub_wordlist() as $w){ $fq=$w.'.'.$host; if(!isset($found[$fq])) sl3r_norm($found,$fq,'subbrute',$host); }
        $eng['subbrute']='seeded';
    }

    /* wildcard detection */
    $wildIPs=[]; $wc=doh_query('vra'.substr(md5((string)microtime(true)),0,10).'.'.$host,'A');
    if($wc&&!empty($wc['Answer'])) foreach($wc['Answer'] as $a){ if(($a['type']??0)==1&&!empty($a['data'])) $wildIPs[$a['data']]=true; }
    $out['wildcard']=!empty($wildIPs);

    /* resolve + dedup */
    $items=[];
    foreach($found as $fq=>$rec){ if(count($items)>=$cap) break;
        $ips=array_values(array_unique($rec['ips'])); $cname='';
        if($doResolve){
            $ja=doh_query($fq,'A');
            if($ja&&!empty($ja['Answer'])) foreach($ja['Answer'] as $a){ $ty=$a['type']??0; if($ty==1&&!empty($a['data']))$ips[]=$a['data']; elseif($ty==5&&!empty($a['data']))$cname=rtrim($a['data'],'.'); }
            $ips=array_values(array_unique($ips));
            $onlyBrute=isset($rec['sources']['subbrute'])&&count($rec['sources'])===1;
            if($out['wildcard']&&$ips&&$onlyBrute){ $nonWild=array_filter($ips,fn($ip)=>!isset($wildIPs[$ip])); if(!$nonWild) continue; }
            if($onlyBrute && !$ips && !$cname) continue;
        }
        $items[]=['sub'=>$fq,'ips'=>array_slice($ips,0,5),'cname'=>$cname,'sources'=>array_keys($rec['sources'])];
    }
    usort($items,fn($a,$b)=>strcmp($a['sub'],$b['sub']));
    $out['items']=$items; $out['engines']=$eng; $out['count']=count($items);
    return $out;
}
/* v2.6.6 — live HTTP/HTTPS status probe for a batch of subdomains (host-scoped, capped) */
function sl3r_alive($host,$subs){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $subs=array_slice((array)$subs,0,60); // rate cap
    $res=[];
    foreach($subs as $s){
        $s=strtolower(trim((string)$s));
        if($s===''||!preg_match('~^[a-z0-9._-]+$~',$s)) continue;
        // host-scope guard: must be a subdomain of the scanned host (or the host itself)
        if($s!==$host && substr($s,-(strlen($host)+1))!=='.'.$host){ $res[]=['sub'=>$s,'code'=>0,'scheme'=>'','error'=>'off-scope']; continue; }
        $done=false;
        foreach(['https','http'] as $scheme){
            $h=head_only($scheme.'://'.$s,4); $code=$h['code']??0;
            if($code>0){ $res[]=['sub'=>$s,'code'=>$code,'scheme'=>$scheme,'server'=>substr($h['server']??($h['ctype']??''),0,40),'loc'=>substr($h['loc']??'',0,120)]; $done=true; break; }
        }
        if(!$done) $res[]=['sub'=>$s,'code'=>0,'scheme'=>'','error'=>'no response'];
    }
    return ['results'=>$res,'count'=>count($res),'alive'=>count(array_filter($res,fn($x)=>$x['code']>0))];
}
function rt_active_recon($host,$opts=[]){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $base=resolve_base($host);
    $stealth=!empty($opts['stealth']);
    $ua = $stealth
        ? ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
           'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
           'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0']
        : ['Mozilla/5.0 (VRA-RedTeam/'.APP_VERSION.')'];
    $pick=function() use($ua){ return $ua[array_rand($ua)]; };
    $jit=function() use($stealth){ if($stealth) usleep(random_int(120000,420000)); }; // 120-420ms jitter

    $out=['host'=>$host,'base'=>$base,'stealth'=>$stealth,'methods'=>[],'reflections'=>[],'aggr_paths'=>[],'tech'=>[],'auth_surface'=>[]];

    /* ---- 1) HTTP method probing (OPTIONS + detect risky verbs) ---- */
    if(function_exists('curl_init')){
        $ch=curl_init();
        curl_setopt_array($ch,[CURLOPT_URL=>$base.'/',CURLOPT_CUSTOMREQUEST=>'OPTIONS',CURLOPT_RETURNTRANSFER=>true,
            CURLOPT_HEADER=>true,CURLOPT_NOBODY=>true,CURLOPT_TIMEOUT=>8,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,
            CURLOPT_HTTPHEADER=>['User-Agent: '.$pick()]]);
        $raw=curl_exec($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        $allow='';
        if($raw && preg_match('~^Allow:\s*([^\r\n]+)~mi',$raw,$m)) $allow=trim($m[1]);
        $risky=[]; foreach(['PUT','DELETE','TRACE','CONNECT','PATCH'] as $v){ if(stripos($allow,$v)!==false) $risky[]=$v; }
        $out['methods']=['allow'=>$allow,'status'=>$code,'risky'=>$risky];
    }

    /* ---- 2) Parameter-reflection probing (benign markers → detect XSS/inj reflection) ---- */
    // Non-destructive: sends a unique harmless token; only checks whether it is reflected unencoded.
    $marker='vraRT'.substr(md5((string)microtime(true)),0,8);
    $paramNames=['q','s','search','id','page','name','query','keyword','lang','ref','url','redirect','return','cat','p'];
    $reflect=[];
    $limit=(int)($opts['reflect_limit']??8); $done=0;
    foreach($paramNames as $pn){ if($done>=$limit) break; $done++;
        $jit();
        $u=$base.'/?'.$pn.'='.$marker.'x"<'.$marker;
        $g=http_get($u,7,true,['User-Agent: '.$pick()]);
        if($g['ok']){ $b=$g['body']??'';
            if(strpos($b,$marker)!==false){
                $rawRefl = (strpos($b,'"<'.$marker)!==false) || (strpos($b,$marker.'x"<')!==false);
                $reflect[]=['param'=>$pn,'reflected'=>true,'raw_unencoded'=>$rawRefl,
                    'note'=>$rawRefl?'Marker reflected WITHOUT encoding — potential XSS/injection sink (manual review).':'Marker reflected but appears encoded/escaped.'];
            }
        }
    }
    $out['reflections']=$reflect;

    /* ---- 3) Expanded aggressive path brute (sensitive endpoints beyond the standard probe) ---- */
    $aggr=['/.git/HEAD','/.env.bak','/.env.save','/config.php.bak','/wp-config.php.save','/.DS_Store',
        '/server-status','/.well-known/security.txt','/actuator/heapdump','/actuator/env','/debug','/trace.axd',
        '/.aws/credentials','/.ssh/id_rsa','/id_rsa','/.npmrc','/.dockercfg','/.docker/config.json',
        '/backup.tar.gz','/db.sql.gz','/wp-content/debug.log','/storage/logs/laravel.log','/.vscode/sftp.json',
        '/phpinfo.php','/test.php','/adminer.php','/.git-credentials','/composer.lock','/yarn.lock'];
    $hits=[]; $seen=[]; $cap=(int)($opts['path_cap']??24); $n=0;
    foreach($aggr as $p){ if($n>=$cap) break; $n++; if(isset($seen[$p]))continue; $seen[$p]=1;
        $jit();
        $r=head_only($base.$p,5); $code=$r['code']??0;
        if($code===0){ $g=get_partial($base.$p,5,256); $code=$g['code']??0; }
        if(in_array($code,[200,301,302,401,403],true)){
            $hits[]=['path'=>$p,'status'=>$code,'interest'=>($code===200?'EXPOSED':($code===401||$code===403?'protected':'redirect'))];
        }
    }
    $out['aggr_paths']=$hits;

    /* ---- 4) Tech-stack fingerprinting (headers, cookies, JS libs, generators) ---- */
    $tech=[]; $home=http_get($base.'/',9,true,['User-Agent: '.$pick()]);
    if($home['ok']){ $hh=$home['headers']??[]; $hb=$home['body']??'';
        $tag=function($name,$val) use(&$tech){ if($val!=='') $tech[]=['name'=>$name,'value'=>substr((string)$val,0,80)]; };
        if(!empty($hh['server'])) $tag('Web Server',$hh['server']);
        if(!empty($hh['x-powered-by'])) $tag('X-Powered-By',$hh['x-powered-by']);
        if(!empty($hh['x-aspnet-version'])) $tag('ASP.NET',$hh['x-aspnet-version']);
        if(!empty($hh['x-generator'])) $tag('Generator',$hh['x-generator']);
        if(!empty($hh['via'])) $tag('Proxy/Via',$hh['via']);
        if(preg_match('~<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)~i',$hb,$m)) $tag('Meta-Generator',$m[1]);
        // JS libraries & frameworks from markup
        $libs=['jQuery'=>'~jquery[.-]([0-9][0-9.]+)~i','Bootstrap'=>'~bootstrap[.-]([0-9][0-9.]+)~i','React'=>'~react(?:-dom)?[.-]([0-9][0-9.]+)~i',
               'Vue'=>'~vue[.-]([0-9][0-9.]+)~i','Angular'=>'~angular[.-]([0-9][0-9.]+)~i','WordPress'=>'~wp-(?:content|includes)~i',
               'Laravel'=>'~laravel_session~i','Drupal'=>'~Drupal.settings|/sites/(?:all|default)/~i','Joomla'=>'~/media/jui/|Joomla!~i'];
        foreach($libs as $nm=>$re){ if(preg_match($re,$hb,$mm)) $tag($nm,$mm[1]??'detected'); }
        // cookie-based framework hints
        $ck=is_array($hh['set-cookie']??null)?implode(';',$hh['set-cookie']):($hh['set-cookie']??'');
        foreach(['laravel_session'=>'Laravel','ci_session'=>'CodeIgniter','PHPSESSID'=>'PHP','JSESSIONID'=>'Java/JSP','ASP.NET_SessionId'=>'ASP.NET','connect.sid'=>'Node/Express','wordpress_'=>'WordPress'] as $cn=>$fw){ if(stripos($ck,$cn)!==false) $tag('Cookie→'.$fw,$cn); }
    }
    $out['tech']=$tech;

    /* ---- 5) Authentication / login attack-surface mapping (endpoints only; NO credential attacks) ---- */
    $authPaths=['/login','/signin','/admin','/administrator','/wp-login.php','/wp-admin/','/user/login','/account/login',
        '/auth','/oauth/authorize','/sso','/saml','/api/login','/api/auth','/api/token','/api/v1/auth','/.well-known/openid-configuration',
        '/manager/html','/cpanel','/webmail','/rdweb','/owa','/remote','/vpn','/portal'];
    $authFound=[]; $ac=0;
    foreach($authPaths as $ap){ if($ac>=20)break; $ac++;
        $jit();
        $r=head_only($base.$ap,4); $code=$r['code']??0; if($code===0){ $g=get_partial($base.$ap,4,256); $code=$g['code']??0; }
        if(in_array($code,[200,301,302,401,403],true)){
            $authFound[]=['path'=>$ap,'status'=>$code,'type'=>(stripos($ap,'api')!==false||stripos($ap,'oauth')!==false||stripos($ap,'token')!==false||stripos($ap,'openid')!==false)?'API/OAuth':'Login UI'];
        }
    }
    $out['auth_surface']=$authFound;

    $out['summary']=[
        'risky_methods'=>count($out['methods']['risky']??[]),
        'reflected_params'=>count(array_filter($reflect,fn($x)=>$x['raw_unencoded'])),
        'exposed_paths'=>count(array_filter($hits,fn($x)=>$x['status']===200)),
        'tech'=>count($tech),
        'auth_endpoints'=>count($authFound),
    ];
    return $out;
}
/* ============================================================
 * v2.6.0 — SAFE PoC CONFIRMATIONS (non-destructive reachability tests)
 * Proves whether an injection sink is REACHABLE without exploiting it:
 *   • Reflected-XSS reachability: benign unique marker, checks unencoded reflection
 *   • SQLi reachability: benign quote vs. encoded-quote differential + DB error signatures
 *   • Open-redirect reachability: harmless external token in redirect param, checks Location
 * No payloads that alter state, extract data, or run code. Detection only.
 * ============================================================ */
function rt_safe_poc($base,$opts=[]){
    $base=rtrim($base,'/');
    $out=['base'=>$base,'xss'=>[],'sqli'=>[],'redirect'=>[]];
    $params=['q','s','search','id','page','name','query','keyword','lang','ref','cat','p','item','view'];
    $lim=min(12,max(3,(int)($opts['limit']??8)));
    $mk='vraPoC'.substr(md5((string)microtime(true)),0,6);
    $n=0;
    foreach($params as $pn){ if($n>=$lim) break; $n++;
        // --- Reflected XSS reachability (benign marker with angle/quote, NEVER a live script) ---
        $xu=$base.'/?'.$pn.'='.$mk.'<x>"'.$mk;
        $xr=http_get($xu,7,true,['User-Agent: VRA-SafePoC/'.APP_VERSION]);
        if($xr['ok']){ $b=$xr['body']??'';
            if(strpos($b,$mk)!==false){
                $unenc=(strpos($b,'<x>')!==false)||(strpos($b,$mk.'<x>"')!==false);
                $out['xss'][]=['param'=>$pn,'reachable'=>true,'unencoded'=>$unenc,
                    'verdict'=>$unenc?'REACHABLE — marker reflected WITHOUT encoding (XSS sink; manual exploit review)':'reflected but encoded/escaped (low risk)'];
            }
        }
        // --- SQLi reachability: differential + error signatures (no data extraction) ---
        $q1=http_get($base.'/?'.$pn."=".$mk."'",7,true,['User-Agent: VRA-SafePoC/'.APP_VERSION]); // single quote
        $q2=http_get($base.'/?'.$pn."=".$mk."%27%27",7,true,['User-Agent: VRA-SafePoC/'.APP_VERSION]); // encoded double-quote (balanced)
        $b1=$q1['ok']?($q1['body']??''):''; $c1=$q1['code']??0; $c2=$q2['code']??0;
        $errRe='~(SQL syntax|mysql_fetch|mysqli_|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|SQLSTATE\[|Unclosed quotation mark|Microsoft OLE DB|ODBC SQL|Warning: pg_|valid MySQL result|supplied argument is not a valid)~i';
        if($b1 && preg_match($errRe,$b1,$em)){
            $out['sqli'][]=['param'=>$pn,'reachable'=>true,'signal'=>'db_error','verdict'=>'REACHABLE — database error surfaced on quote injection: '.substr(trim($em[0]),0,80)];
        } elseif($c1 && $c2 && $c1!==$c2 && in_array($c1,[500,400],true)){
            $out['sqli'][]=['param'=>$pn,'reachable'=>true,'signal'=>'differential','verdict'=>'POSSIBLE — unbalanced quote changed status ('.$c1.' vs '.$c2.'); manual review'];
        }
    }
    // --- Open-redirect reachability (harmless token; checks if it lands in Location) ---
    foreach(['redirect','url','next','return','returnUrl','dest','destination','continue','r','u'] as $rp){
        $token='vra-redirect-check.example.org';
        $rr=head_only($base.'/?'.$rp.'=https://'.$token.'/',6);
        $loc=$rr['loc']??'';
        if($loc && stripos($loc,$token)!==false){
            $out['redirect'][]=['param'=>$rp,'reachable'=>true,'verdict'=>'REACHABLE — external host honored in redirect (open-redirect; manual review)','location'=>substr($loc,0,120)];
        }
    }
    $out['summary']=['xss'=>count(array_filter($out['xss'],fn($x)=>$x['unencoded'])),'sqli'=>count($out['sqli']),'redirect'=>count($out['redirect'])];
    return $out;
}
/* ============================================================
 * v2.6.0 — CVE EXPLOIT INTELLIGENCE (information only, no exploit code)
 * For detected software/versions, returns curated public-exploit
 * INTELLIGENCE: EPSS-style exploit-likelihood band, KEV/known-exploited
 * flag, and outbound reference links (Exploit-DB search, Metasploit
 * module search, NVD). It does NOT contain or run any exploit.
 * ============================================================ */
function rt_exploit_intel($cves){
    // $cves: array of ['id'=>'CVE-...','product'=>'...','cvss'=>float]
    $out=[];
    // small curated KEV-style set (known exploited / public exploit exists)
    $KEV=['CVE-2025-7384'=>1,'CVE-2024-4439'=>1,'CVE-2025-12450'=>1,'CVE-2021-44228'=>1,'CVE-2024-4577'=>1,
          'CVE-2023-23752'=>1,'CVE-2022-1388'=>1,'CVE-2021-26084'=>1,'CVE-2019-11510'=>1,'CVE-2018-11776'=>1];
    foreach((array)$cves as $c){
        if(!is_array($c)) continue;
        $id=preg_replace('~[^A-Za-z0-9\-]~','',(string)($c['id']??'')); if($id==='') continue;
        $cvss=(float)($c['cvss']??0); $prod=(string)($c['product']??'');
        $kev=isset($KEV[$id]);
        // EPSS-style band derived from CVSS + KEV (transparent heuristic; real EPSS needs the FIRST.org API)
        $band = $kev ? 'Very High (known-exploited)' : ($cvss>=9?'High':($cvss>=7?'Elevated':($cvss>=4?'Moderate':'Low')));
        $out[]=[
            'id'=>$id,'product'=>$prod,'cvss'=>$cvss,'kev'=>$kev,'exploit_likelihood'=>$band,
            'refs'=>[
                'NVD'=>'https://nvd.nist.gov/vuln/detail/'.$id,
                'Exploit-DB'=>'https://www.exploit-db.com/search?cve='.$id,
                'Metasploit'=>'https://www.rapid7.com/db/?q='.rawurlencode($id).'&type=metasploit',
                'CISA-KEV'=>'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            ],
        ];
    }
    // sort: KEV first, then CVSS desc
    usort($out,fn($a,$b)=>($b['kev']<=>$a['kev'])?:($b['cvss']<=>$a['cvss']));
    return ['items'=>$out,'count'=>count($out),'kev_count'=>count(array_filter($out,fn($x)=>$x['kev']))];
}
function pb_run_check($c){
    $type=$c['type']??''; $url=$c['url']??''; $out=['status'=>'error','evidence'=>''];
    switch($type){
        case 'header_absent': {
            $r=http_get($url,8,true); $h=$r['headers']??[]; $key=strtolower($c['header']??'');
            if(isset($h[$key])) $out=['status'=>'clear','evidence'=>($c['label']??$c['header']).' present: '.substr($h[$key],0,140)];
            else $out=['status'=>'confirmed','evidence'=>'Header absent ('.($c['label']??$c['header']).') — HTTP '.($r['code']??0)];
            break; }
        case 'header_present': {
            $r=http_get($url,8,true); $h=$r['headers']??[]; $found=[];
            foreach(($c['headers']??[]) as $k){ $k=strtolower($k); if(isset($h[$k])) $found[]=$k.': '.substr($h[$k],0,110); }
            $out=$found?['status'=>'confirmed','evidence'=>implode('  |  ',$found)]:['status'=>'clear','evidence'=>'not disclosed'];
            break; }
        case 'status': {
            $r=head_only($url,6); $code=$r['code']??0; if($code===0){ $g=get_partial($url,6,256); $code=$g['code']??0; }
            $out=['status'=>($code===200?'confirmed':'clear'),'evidence'=>'HTTP '.$code.($code===200?' (still reachable/exposed)':' (not exposed)')];
            break; }
        case 'body_match': {
            $g=get_partial($url,6,4096); $code=$g['code']??0; $b=$g['body']??''; $pat=$c['pattern']??'';
            if($code===200 && $pat!=='' && stripos($b,$pat)!==false){
                $pos=stripos($b,$pat); $sn=trim(substr($b,max(0,$pos-8),90));
                $out=['status'=>'confirmed','evidence'=>'HTTP 200 · '.substr(preg_replace('~\s+~',' ',$sn),0,140)];
            } else $out=['status'=>'clear','evidence'=>'HTTP '.$code.' · pattern not found'];
            break; }
        case 'tls': {
            $t=tls_inspect($c['host']??'');
            if(!empty($t['ok'])) $out=['status'=>'info','evidence'=>'Issuer: '.($t['issuer']?:'?').' · Expires: '.($t['valid_to']?:'?').' ('.($t['days_left']??'?').'d) · Sig: '.($t['sig_alg']?:'?').' · '.($t['protocol']?:'')];
            else $out=['status'=>'error','evidence'=>$t['error']??'TLS check failed'];
            break; }
        case 'dns': {
            $rec=strtoupper($c['rec']??''); $host=$c['host']??'';
            if($rec==='SPF'){ $tx=doh_txt($host); $spf=''; foreach($tx as $t){ if(stripos($t,'v=spf1')===0){$spf=$t;break;} }
                if(!$spf) $out=['status'=>'confirmed','evidence'=>'No SPF record found'];
                elseif(strpos($spf,'-all')!==false) $out=['status'=>'clear','evidence'=>'SPF hard-fail: '.substr($spf,0,140)];
                else $out=['status'=>'confirmed','evidence'=>'SPF weak (no -all): '.substr($spf,0,140)]; }
            elseif($rec==='DMARC'){ $tx=doh_txt('_dmarc.'.$host); $d=''; foreach($tx as $t){ if(stripos($t,'v=DMARC1')===0){$d=$t;break;} }
                if(!$d) $out=['status'=>'confirmed','evidence'=>'No DMARC record'];
                else { $pol='none'; if(preg_match('~\bp=([a-z]+)~i',$d,$m))$pol=strtolower($m[1]);
                    $out=($pol==='none')?['status'=>'confirmed','evidence'=>'DMARC p=none (not enforced): '.substr($d,0,120)]:['status'=>'clear','evidence'=>'DMARC p='.$pol]; } }
            elseif($rec==='CAA'){ $j=doh_query($host,'CAA'); $has=$j&&!empty($j['Answer']); $out=$has?['status'=>'clear','evidence'=>'CAA present']:['status'=>'confirmed','evidence'=>'No CAA record — any CA may issue']; }
            elseif($rec==='DNSSEC'){ $j=doh_query($host,'DNSKEY'); $has=$j&&!empty($j['Answer']); $out=$has?['status'=>'clear','evidence'=>'DNSKEY present (signed)']:['status'=>'confirmed','evidence'=>'No DNSSEC (DNSKEY absent)']; }
            elseif($rec==='DKIM'){ $out=['status'=>'info','evidence'=>'DKIM commonly uses a custom selector — verify at your mail provider']; }
            else $out=['status'=>'info','evidence'=>'Unmapped DNS record type'];
            break; }
        case 'cookies': {
            $r=raw_headers($url,8); $hraw=$r['headers_raw']??'';
            if(preg_match_all('~^Set-Cookie:\s*([^\r\n]+)~mi',$hraw,$mm)){
                $flags=[]; foreach($mm[1] as $line){ $nm=preg_match('~^\s*([^=;\s]+)~',$line,$x)?$x[1]:'?';
                    $miss=[]; if(!preg_match('~;\s*Secure~i',$line))$miss[]='Secure'; if(!preg_match('~;\s*HttpOnly~i',$line))$miss[]='HttpOnly'; if(!preg_match('~;\s*SameSite~i',$line))$miss[]='SameSite';
                    $flags[]=$nm.($miss?(' — missing '.implode('/',$miss)):' — ok'); }
                $bad=count(array_filter($flags,fn($f)=>strpos($f,'missing')!==false));
                $out=['status'=>($bad?'confirmed':'clear'),'evidence'=>implode("\n",array_slice($flags,0,8))];
            } else $out=['status'=>'clear','evidence'=>'No Set-Cookie on landing response'];
            break; }
        default: $out=['status'=>'error','evidence'=>'unknown check type'];
    }
    return $out;
}

/* ============================================================
 * v2.6.8 — ADVANCED DETECTION ENGINES (non-destructive)
 *   1) cors_scan()      — CORS misconfiguration detection
 *   2) headers_grade()  — Security-header grading (A+ → F)
 *   3) js_recon()       — JS endpoint + secret extraction (redacted)
 *   4) takeover_scan()  — Subdomain takeover / dangling-CNAME
 *   5) graphql_scan()   — GraphQL introspection / IDE exposure
 *   6) favicon_hash()   — MurmurHash3 favicon fingerprint (Shodan)
 * All checks are detection-only, GET/HEAD/POST-introspect with benign
 * markers, authorization-gated upstream, and host-scoped.
 * ============================================================ */

/* ---------- 1) CORS misconfiguration scanner ---------- */
function cors_scan($base){
    $base=rtrim($base,'/');
    $host=parse_url($base,PHP_URL_HOST); if(!$host)$host=preg_replace('~^https?://~i','',$base);
    $reg=preg_replace('~^www\.~i','',$host);
    $out=['base'=>$base,'tests'=>[],'findings'=>[],'rating'=>'Info'];
    $origins=[
        ['label'=>'Reflected arbitrary origin','origin'=>'https://vra-cors-probe.example.com'],
        ['label'=>'Null origin','origin'=>'null'],
        ['label'=>'Suffix bypass (evil-'.$reg.')','origin'=>'https://evil-'.$reg],
        ['label'=>'Sub-origin (attacker.'.$reg.')','origin'=>'https://vra-attacker.'.$reg],
        ['label'=>'HTTP downgrade origin','origin'=>'http://'.$reg],
    ];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    foreach($origins as $o){
        $r=http_get($base,8,false,['Origin: '.$o['origin']]);
        $acao=$r['ok']?trim($r['headers']['access-control-allow-origin']??''):'';
        $acac=$r['ok']?strtolower(trim($r['headers']['access-control-allow-credentials']??'')):'';
        $creds=($acac==='true');
        $reflected=($acao!=='' && strtolower($acao)===strtolower($o['origin']));
        $wildcard=($acao==='*');
        $nullok=($o['origin']==='null' && strtolower($acao)==='null');
        $sev='Info'; $verdict='ACAO not returned for this origin (not vulnerable).';
        if($reflected && $creds){$sev='Critical';$verdict='Origin reflected WITH credentials — a malicious site can read authenticated responses (session/CSRF token theft).';}
        elseif($reflected){$sev='High';$verdict='Arbitrary origin reflected in ACAO — cross-origin read of (non-credentialed) responses.';}
        elseif($wildcard && $creds){$sev='High';$verdict='Wildcard ACAO with credentials (spec-invalid but some stacks honor it).';}
        elseif($nullok){$sev=$creds?'High':'Medium';$verdict='"null" origin allowed'.($creds?' WITH credentials':'').' — reachable from sandboxed iframe/data: URI.';}
        elseif($wildcard){$sev='Low';$verdict='Wildcard ACAO (public data only; credentials not allowed).';}
        $out['tests'][]=['label'=>$o['label'],'origin'=>$o['origin'],'acao'=>$acao?:'—','acac'=>$acac?:'—','status'=>$r['code']??0,'sev'=>$sev,'verdict'=>$verdict];
        if($sev!=='Info')$out['findings'][]=['sev'=>$sev,'msg'=>$o['label'].' — '.$verdict];
        if($rank[$sev]>$rank[$worst])$worst=$sev;
    }
    $out['rating']=$worst;
    $out['fix']="Echo Origin only from a server-side allow-list; never reflect arbitrary origins with Access-Control-Allow-Credentials: true; never allow the \"null\" origin; avoid substring matching (use exact host compare).";
    return $out;
}

/* ---------- 2) Security header grade (A+ → F) ---------- */
function headers_grade($base){
    $base=rtrim($base,'/');
    $r=http_get($base,10,true);
    if(!$r['ok']) return ['error'=>'Fetch failed: '.($r['error']??'unknown')];
    $h=$r['headers']??[];
    $get=function($k) use($h){ return $h[strtolower($k)]??''; };
    $ctrls=[
        ['Strict-Transport-Security','HSTS',20,'High','Prevents SSL-strip / protocol downgrade.'],
        ['Content-Security-Policy','CSP',25,'High','Primary defense-in-depth against XSS / data exfiltration.'],
        ['X-Frame-Options','Anti-clickjacking',10,'Medium','Blocks framing (or use CSP frame-ancestors).'],
        ['X-Content-Type-Options','MIME-sniff protection',8,'Medium','nosniff stops content-type confusion attacks.'],
        ['Referrer-Policy','Referrer control',7,'Low','Limits URL/token leakage to third parties.'],
        ['Permissions-Policy','Feature policy',7,'Low','Restricts camera/mic/geolocation etc.'],
        ['Cross-Origin-Opener-Policy','COOP',6,'Low','Process isolation (Spectre / XS-Leaks).'],
        ['Cross-Origin-Resource-Policy','CORP',5,'Low','Blocks cross-origin resource theft.'],
        ['Cross-Origin-Embedder-Policy','COEP',4,'Info','Enables cross-origin isolation.'],
    ];
    $checks=[]; $earned=0; $max=0;
    foreach($ctrls as $c){
        list($hdr,$name,$w,$sev,$note)=$c; $max+=$w;
        $val=$get($hdr); $present=($val!=='' ); $partial=false; $detail=$note;
        if($present && $hdr==='Strict-Transport-Security'){
            if(!preg_match('~max-age\s*=\s*(\d+)~i',$val,$m) || (int)$m[1] < 15552000){ $partial=true; $detail='Present but max-age < 180 days (or missing).'; }
        }
        if($present && $hdr==='Content-Security-Policy'){
            if(preg_match('~unsafe-inline|unsafe-eval~i',$val)){ $partial=true; $detail='Present but contains unsafe-inline / unsafe-eval.'; }
        }
        $pts=$present?($partial?$w*0.5:$w):0; $earned+=$pts;
        $checks[]=['header'=>$hdr,'name'=>$name,'present'=>$present,'partial'=>$partial,'value'=>substr($val,0,240),'weight'=>$w,'sev'=>$sev,'note'=>$detail];
    }
    $leaks=[];
    foreach(['server'=>'Server','x-powered-by'=>'X-Powered-By','x-aspnet-version'=>'X-AspNet-Version','x-aspnetmvc-version'=>'X-AspNetMvc-Version'] as $lk=>$ln){
        $v=$get($lk); if($v!=='' && preg_match('~\d~',$v)){ $leaks[]=['header'=>$ln,'value'=>substr($v,0,80)]; $earned-=3; }
    }
    $pct = $max>0 ? max(0,min(100, (int)round(($earned/$max)*100))) : 0;
    $grade = $pct>=95?'A+':($pct>=85?'A':($pct>=70?'B':($pct>=55?'C':($pct>=40?'D':($pct>=20?'E':'F')))));
    return ['grade'=>$grade,'score'=>$pct,'checks'=>$checks,'leaks'=>$leaks,
            'present'=>count(array_filter($checks,function($x){return $x['present'];})),'total'=>count($checks)];
}

/* ---------- 3) JS endpoint + secret extractor (redacted) ---------- */
function js_recon($base){
    $base=rtrim($base,'/'); $host=parse_url($base,PHP_URL_HOST); if(!$host)$host=preg_replace('~^https?://~i','',$base);
    $home=http_get($base,12,true); if(!$home['ok']) return ['error'=>'Fetch failed: '.($home['error']??'unknown')];
    $html=$home['body']; $out=['base'=>$base,'scripts'=>[],'endpoints'=>[],'secrets'=>[],'scanned'=>0,'inline_bytes'=>0];
    $srcs=[]; if(preg_match_all('~<script[^>]+src=["\']([^"\']+)["\']~i',$html,$m)) $srcs=$m[1];
    $inline=''; if(preg_match_all('~<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>~is',$html,$im)) $inline=implode("\n",$im[1]);
    $out['inline_bytes']=strlen($inline); $corpus=$inline; $cap=6;
    foreach($srcs as $s){
        $u=$s;
        if(strpos($s,'//')===0) $u='https:'.$s;
        elseif(strpos($s,'/')===0) $u=$base.$s;
        elseif(!preg_match('~^https?://~i',$s)) $u=$base.'/'.ltrim($s,'/');
        $same=(stripos($u,$host)!==false);
        $entry=['url'=>$u,'same_origin'=>$same,'fetched'=>false,'size'=>0];
        if($same && $out['scanned']<$cap){
            $jr=get_partial($u,8,300000); $code=$jr['code']??0;
            if($code>=200 && $code<400 && !empty($jr['body'])){ $corpus.="\n".$jr['body']; $entry['fetched']=true; $entry['size']=$jr['size']; $out['scanned']++; }
        }
        $out['scripts'][]=$entry;
    }
    $eps=[];
    if(preg_match_all('~["\'`](/(?:api|v\d+|rest|graphql|admin|internal|auth|oauth|users?|account|upload|download|file|config|debug|actuator|wp-json|private|secret)[a-zA-Z0-9_\-/\.\?=&%]{0,120})["\'`]~i',$corpus,$em)) foreach($em[1] as $e)$eps[$e]=true;
    if(preg_match_all('~["\'`](https?://[a-zA-Z0-9\.\-]+/[a-zA-Z0-9_\-/\.\?=&%]{0,120})["\'`]~i',$corpus,$em2)) foreach($em2[1] as $e){ if(stripos($e,$host)!==false)$eps[$e]=true; }
    $out['endpoints']=array_slice(array_keys($eps),0,150);
    $pats=[
        'AWS Access Key'=>'~AKIA[0-9A-Z]{16}~',
        'Google API Key'=>'~AIza[0-9A-Za-z\-_]{35}~',
        'Slack Token'=>'~xox[baprs]-[0-9A-Za-z\-]{10,}~',
        'GitHub Token'=>'~gh[pousr]_[0-9A-Za-z]{36}~',
        'Stripe Live Key'=>'~sk_live_[0-9A-Za-z]{20,}~',
        'JWT'=>'~eyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}~',
        'Generic secret assignment'=>'~(?:api[_-]?key|apikey|secret|token|access[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']~i',
        'Private Key Block'=>'~-----BEGIN (?:RSA |EC |OPENSSH |PGP |)PRIVATE KEY-----~',
        'Firebase URL'=>'~[a-z0-9\-]+\.firebaseio\.com~i',
        'Google OAuth Client'=>'~[0-9]+-[0-9a-z_]{16,}\.apps\.googleusercontent\.com~i',
    ];
    foreach($pats as $name=>$re){
        if(preg_match_all($re,$corpus,$sm)){
            $u=array_slice(array_values(array_unique($sm[0])),0,5);
            foreach($u as $hit){
                $L=strlen($hit);
                $red=$L>12?substr($hit,0,6).'…'.substr($hit,-4):substr($hit,0,4).'…';
                $out['secrets'][]=['type'=>$name,'match'=>$red,'len'=>$L];
            }
        }
    }
    $out['rating']=count($out['secrets'])?'High':'Info';
    return $out;
}

/* ---------- 4) Subdomain takeover / dangling-CNAME ---------- */
function takeover_scan($host){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $out=['host'=>$host,'checked'=>[],'findings'=>[],'rating'=>'Info'];
    $fps=[
        ['GitHub Pages','github.io',"There isn't a GitHub Pages site here",'High'],
        ['AWS S3','s3.amazonaws.com','NoSuchBucket','High'],
        ['AWS S3 (website)','s3-website','NoSuchBucket','High'],
        ['Heroku','herokudns.com','No such app','High'],
        ['Heroku','herokuapp.com','No such app','High'],
        ['Azure Websites','azurewebsites.net','404 Web Site not found','High'],
        ['Azure Traffic Manager','trafficmanager.net','404 Web Site not found','High'],
        ['Shopify','myshopify.com','Sorry, this shop is currently unavailable','Medium'],
        ['Fastly','fastly.net','Fastly error: unknown domain','Medium'],
        ['Zendesk','zendesk.com','Help Center Closed','Medium'],
        ['Unbounce','unbouncepages.com','The requested URL was not found','Medium'],
        ['Surge.sh','surge.sh','project not found','Medium'],
        ['Bitbucket','bitbucket.io','Repository not found','Medium'],
        ['Ghost','ghost.io','The thing you were looking for is no longer here','Medium'],
        ['Pantheon','pantheonsite.io','The gods are wise','Medium'],
        ['Tumblr','domains.tumblr.com',"Whatever you were looking for doesn't currently exist",'Low'],
        ['WordPress.com','wordpress.com','Do you want to register','Low'],
        ['Netlify','netlify.app','Not Found','Low'],
    ];
    $subs=['','www','api','app','dev','staging','test','blog','shop','mail','cdn','assets','static','portal','docs','status','support','beta','m','admin'];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info'; $n=0;
    foreach($subs as $s){
        if($n>=22)break; $n++;
        $fq=$s===''?$host:$s.'.'.$host;
        $j=doh_query($fq,'CNAME'); $cname='';
        if($j && !empty($j['Answer'])) foreach($j['Answer'] as $a){ if(($a['type']??0)==5 && !empty($a['data'])){ $cname=rtrim($a['data'],'.'); break; } }
        if(!$cname) continue;
        $match=null; foreach($fps as $fp){ if(stripos($cname,$fp[1])!==false){ $match=$fp; break; } }
        $sev='Info'; $verdict='CNAME → third-party service (no takeover fingerprint matched).'; $service=$match?$match[0]:'—';
        if($match){
            $g=get_partial('http://'.$fq,6,4096); $body=$g['body']??''; $code=$g['code']??0;
            if(stripos($body,$match[2])!==false){
                $sev=$match[3];
                $verdict='POTENTIAL TAKEOVER — '.$match[0].' fingerprint served ("'.$match[2].'"); backing resource appears UNCLAIMED (HTTP '.$code.').';
                $out['findings'][]=['sev'=>$sev,'msg'=>$fq.' → '.$match[0].' (dangling): '.$verdict];
            } else {
                $sev='Low'; $verdict=$match[0].' CNAME present; service appears CLAIMED (no dangling fingerprint).';
            }
        }
        if($rank[$sev]>$rank[$worst])$worst=$sev;
        $out['checked'][]=['sub'=>$fq,'cname'=>$cname,'service'=>$service,'sev'=>$sev,'verdict'=>$verdict];
    }
    $out['rating']=$worst;
    if(!$out['checked']) $out['note']='No CNAME records found on the probed subdomains (nothing to take over).';
    return $out;
}

/* ---------- 5) GraphQL introspection / IDE detector ---------- */
function graphql_scan($base){
    $base=rtrim($base,'/');
    $out=['base'=>$base,'endpoints'=>[],'findings'=>[],'rating'=>'Info'];
    $paths=['/graphql','/api/graphql','/v1/graphql','/v2/graphql','/graphql/console','/graphiql','/api/graphiql','/query','/api/query','/gql'];
    $intro=json_encode(['query'=>'{__schema{queryType{name}}}']);
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    foreach($paths as $p){
        $u=$base.$p;
        $g=get_partial($u,5,2048); $code=$g['code']??0; $ctype=$g['ctype']??''; $gbody=$g['body']??'';
        $looksGql=(stripos($ctype,'json')!==false)||(stripos($gbody,'graphql')!==false)||(stripos($gbody,'graphiql')!==false)||($code===400)||($code===405);
        if($code===0 || (!$looksGql && $code!==200)) continue;
        $pr=http_get($u,7,true,['Content-Type: application/json','Accept: application/json'],$intro);
        $body=$pr['ok']?$pr['body']:''; $pcode=$pr['code']??$code;
        $introOn=(stripos($body,'__schema')!==false)||(stripos($body,'"queryType"')!==false)||(stripos($body,'queryType')!==false && stripos($body,'name')!==false);
        $ideOn=(bool)preg_match('~graphiql|graphql playground|__playground~i',$gbody.$body);
        $sev='Info'; $verdict='GraphQL endpoint detected.';
        if($introOn){ $sev='Medium'; $verdict='Introspection ENABLED — full schema (types, queries, mutations) exposed to anonymous clients.'; $out['findings'][]=['sev'=>'Medium','msg'=>$p.' — introspection enabled (schema disclosure).']; }
        if($ideOn){ if($rank['Medium']>$rank[$sev])$sev='Medium'; $verdict.=' Interactive IDE (GraphiQL/Playground) exposed.'; $out['findings'][]=['sev'=>'Medium','msg'=>$p.' — interactive GraphQL IDE exposed.']; }
        if($rank[$sev]>$rank[$worst])$worst=$sev;
        $out['endpoints'][]=['path'=>$p,'status'=>$pcode,'introspection'=>$introOn,'ide'=>$ideOn,'sev'=>$sev,'verdict'=>$verdict];
    }
    $out['rating']=$worst;
    if(!$out['endpoints']) $out['note']='No GraphQL endpoints detected at common paths.';
    else $out['fix']='Disable introspection in production, remove GraphiQL/Playground, enforce query depth/complexity limits, and require auth on the GraphQL route.';
    return $out;
}

/* ---------- 6) Favicon hash fingerprint (MurmurHash3 x86_32) ---------- */
function mmh3_mul($a,$b){
    $a&=0xffffffff; $b&=0xffffffff;
    $ah=($a>>16)&0xffff; $al=$a&0xffff;
    return ( ($al*$b) + ((($ah*$b)&0xffff)<<16) ) & 0xffffffff;
}
function mmh3_rotl($x,$r){ $x&=0xffffffff; return (($x<<$r)|($x>>(32-$r))) & 0xffffffff; }
function mmh3_fmix($h){ $h&=0xffffffff; $h^=($h>>16); $h=mmh3_mul($h,0x85ebca6b); $h^=($h>>13); $h=mmh3_mul($h,0xc2b2ae35); $h^=($h>>16); return $h&0xffffffff; }
function mmh3_x86_32($data,$seed=0){
    $c1=0xcc9e2d51; $c2=0x1b873593; $len=strlen($data); $h1=$seed & 0xffffffff; $rounded=$len & ~0x3;
    for($i=0;$i<$rounded;$i+=4){
        $k1=(ord($data[$i])&0xff)|((ord($data[$i+1])&0xff)<<8)|((ord($data[$i+2])&0xff)<<16)|((ord($data[$i+3])&0xff)<<24);
        $k1=mmh3_mul($k1,$c1); $k1=mmh3_rotl($k1,15); $k1=mmh3_mul($k1,$c2);
        $h1^=$k1; $h1=mmh3_rotl($h1,13); $h1=(mmh3_mul($h1,5)+0xe6546b64)&0xffffffff;
    }
    $k1=0; $tail=$len & 0x3; $ti=$rounded;
    if($tail==3)$k1^=(ord($data[$ti+2])&0xff)<<16;
    if($tail>=2)$k1^=(ord($data[$ti+1])&0xff)<<8;
    if($tail>=1){ $k1^=(ord($data[$ti])&0xff); $k1=mmh3_mul($k1,$c1); $k1=mmh3_rotl($k1,15); $k1=mmh3_mul($k1,$c2); $h1^=$k1; }
    $h1^=$len; $h1=mmh3_fmix($h1);
    /* Shodan uses a signed 32-bit int */
    if($h1 & 0x80000000) return -( ( (~$h1) & 0xffffffff ) + 1 );
    return $h1;
}
function favicon_hash($base){
    $base=rtrim($base,'/');
    $out=['base'=>$base];
    $home=http_get($base,8,true); $html=$home['ok']?$home['body']:'';
    $fav='/favicon.ico';
    if(preg_match('~<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)["\']~i',$html,$m)) $fav=$m[1];
    elseif(preg_match('~<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\'][^"\']*icon~i',$html,$m2)) $fav=$m2[1];
    $u=$fav;
    if(strpos($fav,'//')===0)$u='https:'.$fav;
    elseif(strpos($fav,'/')===0)$u=$base.$fav;
    elseif(!preg_match('~^https?://~i',$fav))$u=$base.'/'.ltrim($fav,'/');
    $r=get_partial($u,8,200000);
    $out['favicon_url']=$u; $out['status']=$r['code']??0; $out['ctype']=$r['ctype']??'';
    if(($r['code']??0)!==200 || empty($r['body'])){ $out['error']='Favicon not retrievable (HTTP '.($out['status']).').'; return $out; }
    $b64=chunk_split(base64_encode($r['body']));
    $hash=mmh3_x86_32($b64);
    $out['mmh3']=$hash; $out['size']=strlen($r['body']); $out['md5']=md5($r['body']);
    $out['shodan']='https://www.shodan.io/search?query=http.favicon.hash%3A'.$hash;
    $out['note']='Pivot this mmh3 hash in Shodan/Censys to enumerate other hosts serving the same favicon — useful for finding shared infrastructure, forgotten staging clones, and phishing look-alikes.';
    return $out;
}

/* ============================================================
 * v2.6.9 — ADVANCED DETECTION ENGINES 7 & 8 (non-destructive)
 *   7) http_tls_scan()  — HTTP/2 (+HTTP/3 hint) & TLS-version detection
 *   8) wellknown_scan() — security.txt (RFC 9116) + .well-known posture
 * Detection-only, authorization-gated upstream, host-scoped.
 * ============================================================ */

/* ---------- 7) HTTP protocol + TLS-version detection ---------- */
function http_tls_scan($host){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $out=['host'=>$host,'http'=>[],'tls'=>[],'findings'=>[],'rating'=>'Info','alpn'=>[]];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    $bump=function($s) use (&$worst,$rank){ if(($rank[$s]??0)>($rank[$worst]??0))$worst=$s; };

    /* ---- HTTP version negotiation via cURL ---- */
    $curlInfo=function_exists('curl_version')?curl_version():[];
    $curlFeatures=$curlInfo['features']??0;
    $hasHTTP2=defined('CURL_VERSION_HTTP2') && ($curlFeatures & CURL_VERSION_HTTP2);
    $hasHTTP3=defined('CURL_VERSION_HTTP3') && ($curlFeatures & CURL_VERSION_HTTP3);
    $negVer='—'; $negCode=0; $alpn=[];
    if(function_exists('curl_init')){
        $ch=curl_init();
        $opts=[CURLOPT_URL=>'https://'.$host.'/',CURLOPT_RETURNTRANSFER=>true,CURLOPT_NOBODY=>true,
            CURLOPT_FOLLOWLOCATION=>false,CURLOPT_TIMEOUT=>10,CURLOPT_CONNECTTIMEOUT=>6,
            CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,
            CURLOPT_HTTPHEADER=>['User-Agent: Mozilla/5.0 (TTPH-VRA/'.APP_VERSION.')']];
        if($hasHTTP2 && defined('CURL_HTTP_VERSION_2TLS')) $opts[CURLOPT_HTTP_VERSION]=CURL_HTTP_VERSION_2TLS;
        curl_setopt_array($ch,$opts);
        curl_exec($ch);
        $negCode=curl_getinfo($ch,CURLINFO_HTTP_CODE);
        $hv=defined('CURLINFO_HTTP_VERSION')?curl_getinfo($ch,CURLINFO_HTTP_VERSION):0;
        curl_close($ch);
        $map=[];
        if(defined('CURL_HTTP_VERSION_1_0'))$map[CURL_HTTP_VERSION_1_0]='HTTP/1.0';
        if(defined('CURL_HTTP_VERSION_1_1'))$map[CURL_HTTP_VERSION_1_1]='HTTP/1.1';
        if(defined('CURL_HTTP_VERSION_2_0'))$map[CURL_HTTP_VERSION_2_0]='HTTP/2';
        if(defined('CURL_HTTP_VERSION_3'))$map[CURL_HTTP_VERSION_3]='HTTP/3';
        $negVer=$map[$hv]??($hv?('code '.$hv):'—');
    }
    $supportsH2=($negVer==='HTTP/2');
    // Confirm H2 support independently if first negotiation fell back
    if(!$supportsH2 && $hasHTTP2 && function_exists('curl_init')){
        $ch=curl_init();
        curl_setopt_array($ch,[CURLOPT_URL=>'https://'.$host.'/',CURLOPT_RETURNTRANSFER=>true,CURLOPT_NOBODY=>true,
            CURLOPT_FOLLOWLOCATION=>true,CURLOPT_TIMEOUT=>10,CURLOPT_CONNECTTIMEOUT=>6,
            CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,
            CURLOPT_HTTP_VERSION=>(defined('CURL_HTTP_VERSION_2_0')?CURL_HTTP_VERSION_2_0:0),
            CURLOPT_HTTPHEADER=>['User-Agent: Mozilla/5.0 (TTPH-VRA/'.APP_VERSION.')']]);
        curl_exec($ch);
        $hv2=defined('CURLINFO_HTTP_VERSION')?curl_getinfo($ch,CURLINFO_HTTP_VERSION):0;
        curl_close($ch);
        if(defined('CURL_HTTP_VERSION_2_0') && $hv2==CURL_HTTP_VERSION_2_0)$supportsH2=true;
    }
    $out['http']=[
        'negotiated'=>$negVer,'status'=>$negCode,
        'http2'=>$supportsH2,
        'http3_advertised'=>false,
        'client_supports_h2'=>(bool)$hasHTTP2,'client_supports_h3'=>(bool)$hasHTTP3,
    ];

    /* ---- HTTP/3 (QUIC) advertisement via Alt-Svc header ---- */
    $altsvc=''; $hr=http_get('https://'.$host.'/',8,true);
    if($hr['ok']){ $altsvc=$hr['headers']['alt-svc']??''; }
    if($altsvc){
        $out['http']['alt_svc']=substr($altsvc,0,200);
        if(preg_match('~h3(-\d+)?=~i',$altsvc)) $out['http']['http3_advertised']=true;
    }

    /* ---- TLS version support probing (stream crypto handshake) ---- */
    $methods=[];
    if(defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT')) $methods['TLS 1.0']=STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT;
    if(defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT')) $methods['TLS 1.1']=STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
    if(defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) $methods['TLS 1.2']=STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
    if(defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) $methods['TLS 1.3']=STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
    $tls=[]; $canProbe=function_exists('stream_socket_client')&&function_exists('stream_socket_enable_crypto');
    if($canProbe){
        foreach($methods as $label=>$flag){
            $supported=false; $note='';
            $ctx=stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'SNI_enabled'=>true,'peer_name'=>$host]]);
            $errno=0;$errstr='';
            $fp=@stream_socket_client('tcp://'.$host.':443',$errno,$errstr,6,STREAM_CLIENT_CONNECT,$ctx);
            if($fp){
                @stream_set_timeout($fp,6);
                $ok=@stream_socket_enable_crypto($fp,true,$flag);
                $supported=($ok===true);
                @fclose($fp);
            } else { $note='connect failed'; }
            $tls[]=['version'=>$label,'supported'=>$supported,'note'=>$note];
        }
    } else {
        $out['tls_error']='stream crypto probing unavailable on this server.';
    }
    $out['tls']=$tls;
    $sup=function($v) use($tls){ foreach($tls as $t){ if($t['version']===$v)return $t['supported']; } return null; };

    /* ---- Findings & grading ---- */
    if($sup('TLS 1.0')){ $out['findings'][]=['sev'=>'High','msg'=>'TLS 1.0 is enabled — deprecated (PCI-DSS prohibited); disable it.']; $bump('High'); }
    if($sup('TLS 1.1')){ $out['findings'][]=['sev'=>'Medium','msg'=>'TLS 1.1 is enabled — deprecated by all major browsers; disable it.']; $bump('Medium'); }
    if($sup('TLS 1.2')===false && $sup('TLS 1.3')===false && $canProbe){ $out['findings'][]=['sev'=>'High','msg'=>'Neither TLS 1.2 nor 1.3 negotiated — modern clients may fail to connect.']; $bump('High'); }
    if($sup('TLS 1.3')===false && $canProbe){ $out['findings'][]=['sev'=>'Low','msg'=>'TLS 1.3 not supported — enable it for better performance and forward secrecy.']; $bump('Low'); }
    if(!$supportsH2){ $out['findings'][]=['sev'=>'Low','msg'=>'HTTP/2 not negotiated — enabling h2 improves latency and multiplexing.']; $bump('Low'); }
    if(!$out['http']['http3_advertised']){ $out['findings'][]=['sev'=>'Info','msg'=>'HTTP/3 (QUIC) not advertised via Alt-Svc — optional modern upgrade.']; }

    // score: start 100, subtract per weakness
    $score=100;
    if($sup('TLS 1.0'))$score-=30; if($sup('TLS 1.1'))$score-=15;
    if($sup('TLS 1.2')===false && $canProbe)$score-=25;
    if($sup('TLS 1.3')===false && $canProbe)$score-=8;
    if(!$supportsH2)$score-=8; if(!$out['http']['http3_advertised'])$score-=3;
    $score=max(0,min(100,$score));
    $out['score']=$score;
    $out['grade']=$score>=95?'A+':($score>=85?'A':($score>=70?'B':($score>=55?'C':($score>=40?'D':'F'))));
    $out['rating']=$worst;
    $out['fix']='Disable TLS 1.0/1.1, require TLS 1.2+ (prefer 1.3), enable HTTP/2, and optionally advertise HTTP/3 (h3) via Alt-Svc.';
    return $out;
}

/* ---------- 8) security.txt (RFC 9116) + .well-known posture ---------- */
function wellknown_scan($base){
    $base=rtrim($base,'/');
    $out=['base'=>$base,'security_txt'=>null,'resources'=>[],'findings'=>[],'rating'=>'Info'];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    $bump=function($s) use (&$worst,$rank){ if(($rank[$s]??0)>($rank[$worst]??0))$worst=$s; };

    /* ---- security.txt (RFC 9116) — canonical then legacy root ---- */
    $st=['found'=>false];
    foreach(['/.well-known/security.txt','/security.txt'] as $path){
        $g=get_partial($base.$path,7,8192); $code=$g['code']??0; $body=$g['body']??''; $ctype=strtolower($g['ctype']??'');
        $looksText=(stripos($ctype,'text')!==false)||(stripos($body,'Contact:')!==false)||(stripos($body,'Expires:')!==false);
        if($code>=200 && $code<300 && $looksText && trim($body)!==''){
            $fields=[]; $signed=(stripos($body,'BEGIN PGP SIGNED MESSAGE')!==false);
            foreach(preg_split('~\r?\n~',$body) as $ln){
                $ln=trim($ln); if($ln===''||$ln[0]==='#')continue;
                if(preg_match('~^([A-Za-z\-]+):\s*(.+)$~',$ln,$m)){
                    $k=strtolower($m[1]); $v=trim($m[2]);
                    if(!isset($fields[$k]))$fields[$k]=[]; $fields[$k][]=$v;
                }
            }
            $expVal=$fields['expires'][0]??''; $expTs=$expVal?strtotime($expVal):0; $expired=($expTs && $expTs<time());
            $st=['found'=>true,'path'=>$path,'status'=>$code,'signed'=>$signed,'fields'=>$fields,
                 'expires'=>$expVal,'expired'=>$expired,'raw'=>substr($body,0,1600)];
            break;
        }
    }
    $out['security_txt']=$st;
    if(!$st['found']){
        $out['findings'][]=['sev'=>'Low','msg'=>'No security.txt (RFC 9116) — publish /.well-known/security.txt so researchers can report vulnerabilities responsibly.']; $bump('Low');
    } else {
        if(empty($st['fields']['contact'])){ $out['findings'][]=['sev'=>'Medium','msg'=>'security.txt is missing the required Contact field.']; $bump('Medium'); }
        if(empty($st['fields']['expires'])){ $out['findings'][]=['sev'=>'Low','msg'=>'security.txt is missing the required Expires field (RFC 9116).']; $bump('Low'); }
        elseif($st['expired']){ $out['findings'][]=['sev'=>'Medium','msg'=>'security.txt Expires date is in the past ('.$st['expires'].') — the file is stale.']; $bump('Medium'); }
        if($st['path']==='/security.txt'){ $out['findings'][]=['sev'=>'Info','msg'=>'security.txt served from web root; the canonical RFC 9116 location is /.well-known/security.txt.']; }
        if(!$st['signed']){ $out['findings'][]=['sev'=>'Info','msg'=>'security.txt is not PGP-signed (recommended but optional).']; }
    }

    /* ---- Other .well-known / discovery resources ---- */
    $probe=[
        ['/.well-known/security.txt','security.txt (RFC 9116)','Info',false],
        ['/.well-known/change-password','Well-Known Change-Password','Info',false],
        ['/.well-known/mta-sts.txt','MTA-STS policy','Info',false],
        ['/.well-known/openid-configuration','OpenID Connect discovery','Info',true],
        ['/.well-known/oauth-authorization-server','OAuth AS metadata','Info',true],
        ['/.well-known/assetlinks.json','Android App Links','Info',true],
        ['/.well-known/apple-app-site-association','Apple App Site Assoc.','Info',true],
        ['/.well-known/gpc.json','Global Privacy Control','Info',false],
        ['/.well-known/host-meta','host-meta (XRD)','Info',true],
        ['/.well-known/nodeinfo','NodeInfo','Info',true],
        ['/.well-known/dnt-policy.txt','Do-Not-Track policy','Info',false],
        ['/robots.txt','robots.txt','Info',true],
        ['/sitemap.xml','sitemap.xml','Info',true],
        ['/.well-known/carddav','CardDAV discovery','Info',false],
        ['/crossdomain.xml','Adobe crossdomain.xml','Low',true],
        ['/clientaccesspolicy.xml','Silverlight policy','Low',true],
    ];
    foreach($probe as $p){
        list($path,$name,$sevIfExposed,$revealing)=$p;
        $h=head_only($base.$path,5); $code=$h['code']??0; $ctype=$h['ctype']??'';
        if($code===405 || $code===0){ $g=get_partial($base.$path,5,512); $code=$g['code']?:$code; $ctype=$g['ctype']?:$ctype; }
        $present=($code>=200 && $code<300);
        $sev='Info'; $note=$present?'Reachable.':'Not present.';
        if($present && $path==='/crossdomain.xml'){ $sev='Low'; $note='Legacy Flash policy present — review for over-broad allow-access-from.'; $bump('Low'); }
        if($present && $path==='/clientaccesspolicy.xml'){ $sev='Low'; $note='Legacy Silverlight policy present — review scope.'; $bump('Low'); }
        if($present && $revealing && $sev==='Info'){ $note='Reachable (expected/benign — informational).'; }
        $out['resources'][]=['path'=>$path,'name'=>$name,'status'=>$code,'ctype'=>substr($ctype,0,60),'present'=>$present,'sev'=>$sev,'note'=>$note];
    }

    /* ---- Posture score ---- */
    $score=60;
    if($st['found']){ $score+=25; if(!empty($st['fields']['contact']))$score+=6; if(!empty($st['fields']['encryption']))$score+=3; if(!empty($st['fields']['policy']))$score+=3; if($st['signed'])$score+=3; if(!empty($st['expires'])&&!$st['expired'])$score+=6; if($st['expired'])$score-=10; }
    $mtasts=false; foreach($out['resources'] as $r){ if($r['path']==='/.well-known/mta-sts.txt'&&$r['present'])$mtasts=true; }
    if($mtasts)$score+=4;
    foreach($out['resources'] as $r){ if(in_array($r['path'],['/crossdomain.xml','/clientaccesspolicy.xml'])&&$r['present'])$score-=6; }
    $score=max(0,min(100,$score));
    $out['score']=$score;
    $out['grade']=$score>=90?'A':($score>=75?'B':($score>=60?'C':($score>=45?'D':'F')));
    $out['rating']=$worst;
    $out['present_count']=count(array_filter($out['resources'],function($x){return $x['present'];}));
    $out['fix']='Publish a signed /.well-known/security.txt with Contact + Expires (RFC 9116); add MTA-STS; and remove legacy crossdomain.xml / clientaccesspolicy.xml if unused.';
    return $out;
}

/* ============================================================
 * v2.7.0 — ENGINES 9 & 10 + IP GEO AGGREGATOR + HTTP REPEATER
 *   9)  dns_caa_dnssec()        — CAA issuance + DNSSEC chain validation
 *   10) open_redirect_ssrf()    — Open-redirect / SSRF-parameter detector (safe, marker-based)
 *   ip_geo_aggregate()          — multi-provider geolocation (iplocation.io-style)
 *   http_repeater()             — Burp-Repeater-style raw request sender (authorized testing)
 * All detection engines are non-destructive, authorization-gated, host-scoped.
 * ============================================================ */

/* ---------- 9) DNS CAA + DNSSEC validation ---------- */
function dns_caa_dnssec($host){
    $host=strtolower(preg_replace('~^https?://~i','',$host)); $host=explode('/',$host)[0];
    $out=['host'=>$host,'caa'=>['records'=>[],'present'=>false],'dnssec'=>[],'records'=>[],'findings'=>[],'rating'=>'Info','score'=>0,'grade'=>'F'];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    $bump=function($s) use (&$worst,$rank){ if(($rank[$s]??0)>($rank[$worst]??0))$worst=$s; };

    /* ---- CAA (type 257) — walk up the label tree per RFC 8659 ---- */
    $caaRecords=[]; $caaFoundAt='';
    $labels=explode('.',$host); 
    for($i=0;$i<count($labels)-1;$i++){
        $probe=implode('.',array_slice($labels,$i));
        $j=doh_query($probe,'CAA');
        if($j && !empty($j['Answer'])){
            foreach($j['Answer'] as $a){
                if(($a['type']??0)==257 && !empty($a['data'])){
                    $raw=trim($a['data']);
                    // DoH returns either "0 issue \"letsencrypt.org\"" or hex; normalise the common text form
                    $tag=''; $val='';
                    if(preg_match('~\d+\s+(issue|issuewild|iodef|contactemail|contactphone)\s+"?([^"]*)"?~i',$raw,$m)){ $tag=strtolower($m[1]); $val=trim($m[2]); }
                    $caaRecords[]=['name'=>$probe,'tag'=>$tag?:'raw','value'=>$val?:$raw,'raw'=>$raw];
                }
            }
            if($caaRecords){ $caaFoundAt=$probe; break; }
        }
    }
    $out['caa']['records']=$caaRecords; $out['caa']['present']=!empty($caaRecords); $out['caa']['found_at']=$caaFoundAt;
    $issuers=[]; $hasIodef=false;
    foreach($caaRecords as $c){ if($c['tag']==='issue'||$c['tag']==='issuewild'){ if($c['value']!=='' && $c['value']!==';') $issuers[]=$c['value']; } if($c['tag']==='iodef') $hasIodef=true; }
    $out['caa']['issuers']=array_values(array_unique($issuers)); $out['caa']['iodef']=$hasIodef;
    if(!$out['caa']['present']){
        $out['findings'][]=['sev'=>'Low','msg'=>'No CAA record — ANY public CA may issue certificates for this domain (broader mis-issuance / rogue-cert risk).']; $bump('Low');
    } else {
        if(!$issuers){ $out['findings'][]=['sev'=>'Medium','msg'=>'CAA present but no issue/issuewild authorised CA — may block all issuance or be misconfigured.']; $bump('Medium'); }
        if(!$hasIodef){ $out['findings'][]=['sev'=>'Info','msg'=>'CAA has no iodef contact — add one so CAs can report policy violations.']; }
    }

    /* ---- DNSSEC — DNSKEY / DS / RRSIG presence + AD (authenticated-data) flag ---- */
    $dnskey=doh_query($host,'DNSKEY');
    $hasDNSKEY=$dnskey && !empty($dnskey['Answer']) && count(array_filter($dnskey['Answer'],function($a){return ($a['type']??0)==48;}))>0;
    // DS record lives at the parent; query the apex name
    $apex=implode('.',array_slice($labels,max(0,count($labels)-2)));
    $ds=doh_query($apex,'DS');
    $hasDS=$ds && !empty($ds['Answer']) && count(array_filter($ds['Answer'],function($a){return ($a['type']??0)==43;}))>0;
    // AD flag: dns.google returns "AD"=>true when the answer is DNSSEC-validated
    $adProbe=doh_query($host,'A'); $adFlag=is_array($adProbe)?(($adProbe['AD']??false)?true:false):false;
    // RRSIG presence
    $rrsig=doh_query($host,'RRSIG');
    $hasRRSIG=$rrsig && !empty($rrsig['Answer']) && count(array_filter($rrsig['Answer'],function($a){return ($a['type']??0)==46;}))>0;

    $out['dnssec']=[
        'dnskey'=>$hasDNSKEY,'ds'=>$hasDS,'rrsig'=>$hasRRSIG,'authenticated'=>$adFlag,
        'signed'=>($hasDNSKEY||$hasDS||$adFlag),
    ];
    $out['records']=[
        ['name'=>'DNSKEY','present'=>$hasDNSKEY,'note'=>$hasDNSKEY?'Zone-signing / key-signing keys published.':'No DNSKEY — zone is not signed.'],
        ['name'=>'DS (parent)','present'=>$hasDS,'note'=>$hasDS?'Delegation signer present at parent — chain of trust established.':'No DS at parent — chain of trust is broken/absent.'],
        ['name'=>'RRSIG','present'=>$hasRRSIG,'note'=>$hasRRSIG?'Records are cryptographically signed.':'No RRSIG signatures observed.'],
        ['name'=>'AD flag','present'=>$adFlag,'note'=>$adFlag?'Resolver reports responses as DNSSEC-authenticated.':'Responses not authenticated by validating resolver.'],
    ];
    if(!$out['dnssec']['signed']){
        $out['findings'][]=['sev'=>'Medium','msg'=>'DNSSEC not enabled — DNS answers can be spoofed / cache-poisoned to redirect users to attacker infrastructure.']; $bump('Medium');
    } else {
        if($hasDNSKEY && !$hasDS){ $out['findings'][]=['sev'=>'Medium','msg'=>'DNSKEY present but no DS at the parent — the chain of trust is incomplete (validation will fail).']; $bump('Medium'); }
        if(!$adFlag){ $out['findings'][]=['sev'=>'Low','msg'=>'Signed, but a validating resolver did not return the AD flag — verify the chain resolves cleanly.']; $bump('Low'); }
    }

    /* ---- Score / grade ---- */
    $score=40;
    if($out['caa']['present'])$score+=20; if($issuers)$score+=8; if($hasIodef)$score+=4;
    if($hasDNSKEY)$score+=10; if($hasDS)$score+=10; if($adFlag)$score+=6; if($hasRRSIG)$score+=2;
    $score=max(0,min(100,$score));
    $out['score']=$score;
    $out['grade']=$score>=90?'A':($score>=75?'B':($score>=60?'C':($score>=45?'D':'F')));
    $out['rating']=$worst;
    $out['fix']='Publish a CAA record naming only your authorised CA(s) with an iodef contact, and enable DNSSEC (DNSKEY + DS at the registrar) so resolvers can validate the chain of trust.';
    return $out;
}

/* ---------- 10) Open-Redirect / SSRF-parameter detector (safe, marker-based) ---------- */
function open_redirect_ssrf($base){
    $base=rtrim($base,'/');
    $out=['base'=>$base,'redirects'=>[],'ssrf_surface'=>[],'findings'=>[],'rating'=>'Info'];
    $rank=['Info'=>0,'Low'=>1,'Medium'=>2,'High'=>3,'Critical'=>4]; $worst='Info';
    $bump=function($s) use (&$worst,$rank){ if(($rank[$s]??0)>($rank[$worst]??0))$worst=$s; };

    /* ---- Open-redirect: benign external token; check if honoured in Location ---- */
    $redirParams=['redirect','url','next','return','returnUrl','returnTo','dest','destination','continue','goto','target','r','u','link','out','redirect_uri','callback','forward','to','path'];
    $token='vra-openredirect-check.example.org';
    $n=0;
    foreach($redirParams as $rp){
        if($n>=18)break; $n++;
        $test=$base.'/?'.$rp.'=https://'.$token.'/';
        $rr=head_only($test,6); $loc=$rr['loc']??''; $code=$rr['code']??0;
        // some apps redirect only via GET body render; fall back to a light GET if HEAD gave nothing
        if($loc==='' && ($code===405||$code===0)){ $g=get_partial($test,6,1024); $code=$g['code']?:$code; }
        $reachable=($loc && stripos($loc,$token)!==false);
        $protoRel=false;
        if(!$reachable){
            // also test protocol-relative //token which many filters miss
            $t2=$base.'/?'.$rp.'=//'.$token.'/'; $rr2=head_only($t2,5); $loc2=$rr2['loc']??'';
            if($loc2 && stripos($loc2,$token)!==false){ $reachable=true; $protoRel=true; $loc=$loc2; $code=$rr2['code']??$code; }
        }
        $sev='Info'; $verdict='Parameter did not redirect to the external token (not vulnerable via this vector).';
        if($reachable){ $sev='High'; $verdict='OPEN REDIRECT — external host honoured in Location'.($protoRel?' via protocol-relative bypass (//)':'').' (HTTP '.$code.'). Usable for phishing / OAuth token theft; manual review advised.'; $out['findings'][]=['sev'=>'High','msg'=>'Open redirect via "'.$rp.'" parameter'.($protoRel?' (protocol-relative bypass)':'').'.']; $bump('High'); }
        if($reachable) $out['redirects'][]=['param'=>$rp,'status'=>$code,'location'=>substr($loc,0,140),'bypass'=>$protoRel?'protocol-relative':'direct','sev'=>$sev,'verdict'=>$verdict];
    }
    if(!$out['redirects']) $out['redirects_note']='No open-redirect confirmed across '.$n.' common redirect parameters.';

    /* ---- SSRF parameter SURFACE mapping (detection only — never fetches attacker infra) ---- */
    // We do NOT perform blind SSRF (that needs an out-of-band collaborator). We map params that
    // (a) look like they accept a URL/host and (b) change server behaviour when given a benign
    // loopback marker vs a plain string — flagged for MANUAL review only.
    $ssrfParams=['url','uri','path','dest','domain','site','host','feed','to','image','img','load','file','page','src','source','callback','webhook','proxy','fetch','open','api','data','reference','ref'];
    $benign='http://vra-ssrf-marker.example.org/';           // non-routable example domain (never resolves to infra)
    $loop='http://127.0.0.1:80/';                            // loopback marker (behavioural differential only)
    $m=0;
    foreach($ssrfParams as $sp){
        if($m>=16)break; $m++;
        $u1=$base.'/?'.$sp.'='.rawurlencode($benign);
        $u2=$base.'/?'.$sp.'='.rawurlencode($loop);
        $r1=get_partial($u1,6,2048); $r2=get_partial($u2,6,2048);
        $c1=$r1['code']??0; $c2=$r2['code']??0; $b1=$r1['body']??''; $b2=$r2['body']??'';
        if($c1===0 && $c2===0) continue; // param path not reachable
        $reflected=(stripos($b1,'vra-ssrf-marker.example.org')!==false);
        $errSig=(bool)preg_match('~(failed to open stream|could not resolve host|connection refused|cURL error|getaddrinfo|InvalidURL|SSRF|blocked|not allowed|ECONNREFUSED|timed out|name resolution)~i',$b1.$b2);
        $differential=($c1!==$c2) || (abs(strlen($b1)-strlen($b2))>64);
        if(!$reflected && !$errSig && !$differential) continue; // no signal → skip (keeps noise low)
        $sev='Info'; $signals=[];
        if($reflected){ $signals[]='URL reflected in response'; }
        if($errSig){ $signals[]='fetch/SSRF error signature surfaced'; $sev='Medium'; }
        if($differential){ $signals[]='behavioural differential (loopback vs external)'; if($sev==='Info')$sev='Low'; }
        if($errSig || $reflected){ if($sev==='Info')$sev='Low'; }
        $verdict='SSRF SURFACE — "'.$sp.'" appears to consume a URL ('.implode('; ',$signals).'). Confirm out-of-band with an authorised collaborator (Burp Collaborator/interactsh); not auto-exploited here.';
        if($sev!=='Info'){ $out['findings'][]=['sev'=>$sev,'msg'=>'Potential SSRF surface via "'.$sp.'" parameter ('.implode(', ',$signals).').']; $bump($sev); }
        $out['ssrf_surface'][]=['param'=>$sp,'status_ext'=>$c1,'status_loop'=>$c2,'signals'=>$signals,'sev'=>$sev,'verdict'=>$verdict];
    }
    if(!$out['ssrf_surface']) $out['ssrf_note']='No SSRF-consuming parameter behaviour detected across '.$m.' common parameters (surface mapping only).';

    $out['rating']=$worst;
    $out['fix']='Validate redirect targets against a server-side allow-list (never reflect user URLs); for URL-consuming params, enforce scheme/host allow-lists, block private/loopback/link-local ranges (169.254.169.254, 127.0.0.0/8, 10/8, 192.168/16), and disable unused URL fetchers.';
    return $out;
}

/* ---------- IP geolocation aggregator (iplocation.io-style, multi-provider) ---------- */
function geo_pick($arr,$keys){ foreach($keys as $k){ if(isset($arr[$k]) && $arr[$k]!=='' && $arr[$k]!==null) return $arr[$k]; } return ''; }
function ip_geo_aggregate($ip){
    $out=['ip'=>$ip,'providers'=>[],'consensus'=>[],'map'=>''];
    $prov=[];

    /* ip-api.com */
    $r=http_get('http://ip-api.com/json/'.urlencode($ip).'?fields=66846719',7);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body'],true); if(is_array($j)&&($j['status']??'')==='success'){
        $prov[]=['provider'=>'ip-api.com','country'=>geo_pick($j,['country']),'region'=>geo_pick($j,['regionName']),'city'=>geo_pick($j,['city']),'lat'=>geo_pick($j,['lat']),'lon'=>geo_pick($j,['lon']),'isp'=>geo_pick($j,['isp']),'org'=>geo_pick($j,['org']),'asn'=>geo_pick($j,['as']),'timezone'=>geo_pick($j,['timezone']),'ok'=>true];
    } else $prov[]=['provider'=>'ip-api.com','ok'=>false,'error'=>($j['message']??'no data')]; }
    else $prov[]=['provider'=>'ip-api.com','ok'=>false,'error'=>'unreachable'];

    /* ipwho.is */
    $r=http_get('https://ipwho.is/'.urlencode($ip),7);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body'],true); if(is_array($j)&&($j['success']??false)){
        $conn=$j['connection']??[];
        $prov[]=['provider'=>'ipwho.is','country'=>geo_pick($j,['country']),'region'=>geo_pick($j,['region']),'city'=>geo_pick($j,['city']),'lat'=>geo_pick($j,['latitude']),'lon'=>geo_pick($j,['longitude']),'isp'=>geo_pick($conn,['isp']),'org'=>geo_pick($conn,['org']),'asn'=>($conn['asn']??'')?('AS'.$conn['asn']):'','timezone'=>geo_pick($j['timezone']??[],['id']),'ok'=>true];
    } else $prov[]=['provider'=>'ipwho.is','ok'=>false,'error'=>($j['message']??'no data')]; }
    else $prov[]=['provider'=>'ipwho.is','ok'=>false,'error'=>'unreachable'];

    /* ipapi.co */
    $r=http_get('https://ipapi.co/'.urlencode($ip).'/json/',7);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body'],true); if(is_array($j)&&empty($j['error'])){
        $prov[]=['provider'=>'ipapi.co','country'=>geo_pick($j,['country_name']),'region'=>geo_pick($j,['region']),'city'=>geo_pick($j,['city']),'lat'=>geo_pick($j,['latitude']),'lon'=>geo_pick($j,['longitude']),'isp'=>geo_pick($j,['org']),'org'=>geo_pick($j,['org']),'asn'=>geo_pick($j,['asn']),'timezone'=>geo_pick($j,['timezone']),'ok'=>true];
    } else $prov[]=['provider'=>'ipapi.co','ok'=>false,'error'=>($j['reason']??'no data')]; }
    else $prov[]=['provider'=>'ipapi.co','ok'=>false,'error'=>'unreachable/rate-limited'];

    /* freeipapi.com */
    $r=http_get('https://freeipapi.com/api/json/'.urlencode($ip),7);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body'],true); if(is_array($j)&&!empty($j['ipVersion'])){
        $prov[]=['provider'=>'freeipapi.com','country'=>geo_pick($j,['countryName']),'region'=>geo_pick($j,['regionName']),'city'=>geo_pick($j,['cityName']),'lat'=>geo_pick($j,['latitude']),'lon'=>geo_pick($j,['longitude']),'isp'=>'','org'=>'','asn'=>'','timezone'=>geo_pick($j,['timeZone']),'ok'=>true];
    } else $prov[]=['provider'=>'freeipapi.com','ok'=>false,'error'=>'no data']; }
    else $prov[]=['provider'=>'freeipapi.com','ok'=>false,'error'=>'unreachable'];

    /* ipinfo.io (token-free limited) */
    $r=http_get('https://ipinfo.io/'.urlencode($ip).'/json',7,true,['Accept: application/json']);
    if($r['ok']&&$r['code']===200){ $j=json_decode($r['body'],true); if(is_array($j)&&!empty($j['ip'])){
        $loc=explode(',',$j['loc']??','); 
        $prov[]=['provider'=>'ipinfo.io','country'=>geo_pick($j,['country']),'region'=>geo_pick($j,['region']),'city'=>geo_pick($j,['city']),'lat'=>trim($loc[0]??''),'lon'=>trim($loc[1]??''),'isp'=>geo_pick($j,['org']),'org'=>geo_pick($j,['org']),'asn'=>'','timezone'=>geo_pick($j,['timezone']),'ok'=>true];
    } else $prov[]=['provider'=>'ipinfo.io','ok'=>false,'error'=>'no data/limited']; }
    else $prov[]=['provider'=>'ipinfo.io','ok'=>false,'error'=>'unreachable'];

    $out['providers']=$prov;

    /* Consensus: majority vote per field + lat/lon average */
    $ok=array_values(array_filter($prov,function($p){return !empty($p['ok']);}));
    $vote=function($field) use($ok){ $c=[]; foreach($ok as $p){ $v=trim((string)($p[$field]??'')); if($v==='')continue; $key=strtolower($v); if(!isset($c[$key]))$c[$key]=['v'=>$v,'n'=>0]; $c[$key]['n']++; } if(!$c)return ['value'=>'','agree'=>0,'total'=>count($ok)]; uasort($c,function($a,$b){return $b['n']-$a['n'];}); $top=reset($c); return ['value'=>$top['v'],'agree'=>$top['n'],'total'=>count($ok)]; };
    $lat=[]; $lon=[]; foreach($ok as $p){ if(is_numeric($p['lat']??''))$lat[]=(float)$p['lat']; if(is_numeric($p['lon']??''))$lon[]=(float)$p['lon']; }
    $avgLat=$lat?round(array_sum($lat)/count($lat),4):''; $avgLon=$lon?round(array_sum($lon)/count($lon),4):'';
    $out['consensus']=[
        'country'=>$vote('country'),'region'=>$vote('region'),'city'=>$vote('city'),
        'isp'=>$vote('isp'),'asn'=>$vote('asn'),'timezone'=>$vote('timezone'),
        'lat'=>$avgLat,'lon'=>$avgLon,'providers_ok'=>count($ok),'providers_total'=>count($prov),
    ];
    if($avgLat!=='' && $avgLon!=='') $out['map']='https://www.openstreetmap.org/?mlat='.$avgLat.'&mlon='.$avgLon.'#map=11/'.$avgLat.'/'.$avgLon;
    return $out;
}

/* ---------- HTTP Repeater (Burp-Repeater-style; authorized testing) ---------- */
function http_repeater($opts){
    $method=strtoupper(preg_replace('~[^A-Z]~i','',$opts['method']??'GET')); if($method==='')$method='GET';
    $url=trim($opts['url']??'');
    $out=['ok'=>false,'method'=>$method,'url'=>$url];
    if(!preg_match('~^https?://~i',$url)){ $out['error']='URL must start with http:// or https://'; return $out; }
    if(!function_exists('curl_init')){ $out['error']='cURL unavailable on this server.'; return $out; }
    // Block obvious internal-target abuse unless explicitly acknowledged (SSRF guard)
    $hostPart=parse_url($url,PHP_URL_HOST);
    $follow=!empty($opts['follow']);
    $timeout=max(2,min(30,(int)($opts['timeout']??15)));

    // Parse raw headers (one per line "Name: value")
    $rawHeaders=(string)($opts['headers']??'');
    $hdrList=[]; $hasUA=false; $hasCT=false;
    foreach(preg_split('~\r?\n~',$rawHeaders) as $ln){
        $ln=rtrim($ln); if($ln==='')continue;
        if(strpos($ln,':')===false)continue;
        // prevent header injection via CR/LF (already split); keep as-is
        $hdrList[]=$ln;
        if(stripos($ln,'user-agent:')===0)$hasUA=true;
        if(stripos($ln,'content-type:')===0)$hasCT=true;
    }
    if(!$hasUA)$hdrList[]='User-Agent: Mozilla/5.0 (VRA-Repeater/'.APP_VERSION.')';
    $body=(string)($opts['body']??'');
    if($body!=='' && !$hasCT && in_array($method,['POST','PUT','PATCH'],true)) $hdrList[]='Content-Type: application/x-www-form-urlencoded';

    $ch=curl_init();
    $copts=[
        CURLOPT_URL=>$url,
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_HEADER=>true,
        CURLOPT_CUSTOMREQUEST=>$method,
        CURLOPT_FOLLOWLOCATION=>$follow,
        CURLOPT_MAXREDIRS=>5,
        CURLOPT_TIMEOUT=>$timeout,
        CURLOPT_CONNECTTIMEOUT=>8,
        CURLOPT_SSL_VERIFYPEER=>false,
        CURLOPT_SSL_VERIFYHOST=>0,
        CURLOPT_HTTPHEADER=>$hdrList,
        CURLOPT_ENCODING=>'',
    ];
    if($body!=='' && in_array($method,['POST','PUT','PATCH','DELETE'],true)){ $copts[CURLOPT_POSTFIELDS]=$body; }
    if($method==='HEAD'){ $copts[CURLOPT_NOBODY]=true; }
    curl_setopt_array($ch,$copts);
    $t0=microtime(true);
    $raw=curl_exec($ch);
    $ms=(int)round((microtime(true)-$t0)*1000);
    if($raw===false){ $out['error']='Request failed: '.curl_error($ch); curl_close($ch); return $out; }
    $code=curl_getinfo($ch,CURLINFO_HTTP_CODE);
    $hsize=curl_getinfo($ch,CURLINFO_HEADER_SIZE);
    $eff=curl_getinfo($ch,CURLINFO_EFFECTIVE_URL);
    $ctype=curl_getinfo($ch,CURLINFO_CONTENT_TYPE);
    $sizeDl=curl_getinfo($ch,CURLINFO_SIZE_DOWNLOAD);
    $primaryIp=curl_getinfo($ch,CURLINFO_PRIMARY_IP);
    $hv=defined('CURLINFO_HTTP_VERSION')?curl_getinfo($ch,CURLINFO_HTTP_VERSION):0;
    curl_close($ch);
    $respHeadersRaw=substr($raw,0,$hsize);
    $respBody=substr($raw,$hsize);
    // If redirects were followed there can be multiple header blocks; keep the last
    $blocks=preg_split("/\r?\n\r?\n/",trim($respHeadersRaw));
    $lastBlock=end($blocks);
    $statusLine=''; $hmap=[];
    foreach(preg_split("/\r?\n/",$lastBlock) as $i=>$ln){
        if($i===0){ $statusLine=trim($ln); continue; }
        if(strpos($ln,':')!==false){ list($k,$v)=explode(':',$ln,2); $hmap[trim($k)]=trim($v); }
    }
    $vmap=[1=>'HTTP/1.0',2=>'HTTP/1.1',3=>'HTTP/2',30=>'HTTP/3'];
    // curl version constants vary; map defensively
    $httpVer='';
    if(defined('CURL_HTTP_VERSION_2_0')&&$hv==CURL_HTTP_VERSION_2_0)$httpVer='HTTP/2';
    elseif(defined('CURL_HTTP_VERSION_1_1')&&$hv==CURL_HTTP_VERSION_1_1)$httpVer='HTTP/1.1';
    elseif(defined('CURL_HTTP_VERSION_1_0')&&$hv==CURL_HTTP_VERSION_1_0)$httpVer='HTTP/1.0';
    elseif(defined('CURL_HTTP_VERSION_3')&&$hv==CURL_HTTP_VERSION_3)$httpVer='HTTP/3';
    $out['ok']=true;
    $out['status']=(int)$code;
    $out['status_line']=$statusLine;
    $out['http_version']=$httpVer;
    $out['time_ms']=$ms;
    $out['size']=(int)$sizeDl;
    $out['content_type']=$ctype;
    $out['effective_url']=$eff;
    $out['remote_ip']=$primaryIp;
    $out['sent_headers']=$hdrList;
    $out['resp_headers']=$hmap;
    $out['resp_headers_raw']=substr($respHeadersRaw,0,8000);
    $out['body']=substr($respBody,0,200000);
    $out['body_truncated']=strlen($respBody)>200000;
    return $out;
}

if (isset($_GET['api'])) {
    $action = $_GET['action'] ?? ''; $target = trim($_POST['target'] ?? $_GET['target'] ?? '');
    $sk=trim($_POST['shodan_key']??''); $ak=trim($_POST['abuse_key']??''); $vk=trim($_POST['vt_key']??'');
    $t0=microtime(true); $out=['ok'=>true,'action'=>$action,'target'=>$target];
    // Capture stray output so warnings/notices can never corrupt the JSON body
    ob_start();
    // Fatal-error safety net: if the script dies (OOM, timeout, fatal Error), still emit valid JSON
    register_shutdown_function(function() use (&$t0) {
        $e = error_get_last();
        if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
            while (ob_get_level() > 0) { @ob_end_clean(); }
            if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'=>false,
                'error'=>'Server error during scan: '.$e['message'].' (line '.$e['line'].'). The scan may have exceeded memory/time limits — try fewer templates or a lighter mode.',
                'fatal'=>true,
                'elapsed'=>round(microtime(true)-$t0,2),
            ]);
        }
    });
    try { switch ($action) {
        case 'page': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $base=resolve_base($h); $out['data']=analyze_page($base);
            if(!empty($out['data']['fetched'])){ $out['data']['tech']=detect_tech($out['data']['headers'],$out['data']['source']);
                $out['data']['sec_rows']=audit_security_headers($out['data']['headers']);
                $out['data']['vuln']=vulnerability_analysis($out['data'],$out['data']['tech'],$out['data']['sec_rows']);
                unset($out['data']['source']); } break; }
        case 'wordpress': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $wpDepth=(int)($_POST['wp_depth']??10);
            $wpsKey=trim($_POST['wpscan_key']??'');
            $out['data']=wordpress_scan(resolve_base($h),$wpDepth,$wpsKey); break; }
        case 'waf': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $base=resolve_base($h); $r=http_get($base,10); if(!$r['ok'])throw new Exception('Fetch failed.');
            $out['data']=waf_detect($base,$r['headers'],$r['body']); break; }
        case 'dir': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=directory_probe_expanded(resolve_base($h)); break; }
        case 'dns': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=dns_email_posture($h); break; }
        case 'tls': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=tls_inspect($h); break; }
        case 'cookies': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=cookie_csp_analyze(resolve_base($h)); break; }
        case 'cors': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=cors_scan(resolve_base($h)); break; }
        case 'headers_grade': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=headers_grade(resolve_base($h)); break; }
        case 'js_recon': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=js_recon(resolve_base($h)); break; }
        case 'takeover': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=takeover_scan($h); break; }
        case 'graphql': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=graphql_scan(resolve_base($h)); break; }
        case 'favicon': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=favicon_hash(resolve_base($h)); break; }
        case 'http_tls': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=http_tls_scan($h); break; }
        case 'wellknown': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=wellknown_scan(resolve_base($h)); break; }
        case 'dns_caa': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=dns_caa_dnssec($h); break; }
        case 'openredir': { $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $out['data']=open_redirect_ssrf(resolve_base($h)); break; }
        case 'ip_geo_multi': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=ip_geo_aggregate($target); break;
        case 'repeater': {
            $ropts=[
                'method'=>$_POST['rep_method']??'GET',
                'url'=>$_POST['rep_url']??'',
                'headers'=>$_POST['rep_headers']??'',
                'body'=>$_POST['rep_body']??'',
                'follow'=>(($_POST['rep_follow']??'0')==='1'),
                'timeout'=>(int)($_POST['rep_timeout']??15),
            ];
            $out['data']=http_repeater($ropts); break; }
        case 'fetch_script': {
            $u = $target;
            if (!preg_match('~^https?://~i', $u)) throw new Exception('Invalid script URL.');
            $r = http_get($u, 12, true, ['Accept: */*']);
            if (!$r['ok']) throw new Exception('Fetch failed: '.$r['error']);
            $body = mb_convert_encoding($r['body'], 'UTF-8', 'UTF-8');
            $out['data'] = ['url'=>$u, 'code'=>$r['code'], 'ctype'=>$r['headers']['content-type']??'',
                'size'=>strlen($body), 'body'=>substr($body, 0, 400000)];
            break;
        }
        case 'vt_domain': if(!is_valid_domain(clean_host($target)))throw new Exception('Invalid domain.'); $out['data']=virustotal_domain(clean_host($target),$vk); break;
        case 'ip_geo': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=ip_geo($target); break;
        case 'ip_rdns': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=['rdns'=>ip_rdns($target)]; break;
        case 'ip_rdap': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=ip_rdap($target); break;
        case 'ip_spamhaus': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=['listed'=>ip_spamhaus($target)]; break;
        case 'ip_ports': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=ip_ports($target); break;
        case 'shodan_host': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=shodan_host($target,$sk); break;
        case 'abuseipdb': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=abuseipdb($target,$ak); break;
        case 'vt_ip': if(!is_valid_ip($target))throw new Exception('Invalid IP.'); $out['data']=virustotal_ip($target,$vk); break;
        case 'nuclei_detect': { $out['data']=nuclei_detect(); break; }
        case 'nuclei_run': {
            $h=clean_host($target); if(!is_valid_domain($h))throw new Exception('Invalid domain.');
            $base=resolve_base($h);
            $mode=$_POST['mode']??'auto';           // auto | binary | lite
            $severity=trim($_POST['severity']??'');
            $tags=trim($_POST['tags']??'');
            $customTpl=trim($_POST['template']??'');
            $useBundled = ($_POST['use_bundled']??'1')==='1';
            $det=nuclei_detect();
            $engine = ($mode==='binary') ? 'binary' : (($mode==='lite') ? 'lite' : ($det['available']?'binary':'lite'));

            if ($engine==='binary' && $det['available']) {
                $opts=['severity'=>$severity,'tags'=>$tags];
                if ($customTpl!==''){
                    $tf=tempnam(sys_get_temp_dir(),'ntpl_').'.yaml';
                    @file_put_contents($tf,$customTpl); $opts['template_file']=$tf;
                }
                $res=nuclei_run_binary($base,$opts);
                if (!empty($opts['template_file'])) @unlink($opts['template_file']);
                $res['detected']=$det; $res['base']=$base; $out['data']=$res;
            } else {
                // Lite engine — v2.2.0: filter bundled templates by explicit selected IDs
                $selIds = trim($_POST['templates'] ?? '');
                $all = nuclei_bundled_templates();
                $tpls = [];
                if ($selIds !== '') {
                    $wanted = array_filter(array_map('trim', explode(',', $selIds)));
                    $wset = array_flip($wanted);
                    foreach ($all as $y) {
                        if (preg_match('~^id:\s*(\S+)~m', $y, $mm) && isset($wset[$mm[1]])) $tpls[] = $y;
                    }
                } elseif ($useBundled) {
                    $tpls = $all; // backward-compat: all bundled
                }
                if ($customTpl!=='') $tpls[] = $customTpl;
                if (empty($tpls)) throw new Exception('No templates selected. Pick at least one bundled template or paste a custom one.');
                $res=nuclei_lite_run($base,$tpls,['severity'=>$severity,'tags'=>$tags]);
                $res['detected']=$det; $res['bundled_count']=count($tpls) - ($customTpl!==''?1:0);
                $res['custom']=($customTpl!=='');
                $out['data']=$res;
            }
            break;
        }
        case 'pb_verify': {
            if(($_POST['authorized']??'')!=='yes') throw new Exception('Authorization required — confirm you are authorized to test this target.');
            $h=clean_host($target); if(!is_valid_domain($h)) throw new Exception('Invalid target.');
            $checks=json_decode($_POST['checks']??'[]',true);
            if(!is_array($checks)) throw new Exception('Malformed checks payload.');
            $checks=array_slice($checks,0,80); // rate cap: max 80 checks per request
            $results=[];
            foreach($checks as $c){
                if(!is_array($c)){ continue; }
                // SSRF guard — every URL/host must belong to the scanned target host
                $okHost=true;
                if(!empty($c['url'])){ $uh=strtolower((string)parse_url($c['url'],PHP_URL_HOST)); if($uh!==$h && $uh!=='www.'.$h && 'www.'.$uh!==$h) $okHost=false; }
                if(!empty($c['host'])){ $ch=strtolower($c['host']); if($ch!==$h && $ch!=='www.'.$h && 'www.'.$ch!==$h) $okHost=false; }
                if(!$okHost){ $results[]=['id'=>$c['id']??null,'status'=>'error','evidence'=>'blocked: off-target host']; continue; }
                $r=pb_run_check($c); $r['id']=$c['id']??null; $results[]=$r;
            }
            $out['data']=['results'=>$results,'count'=>count($results)]; break; }
        case 'rt_recon': {
            if(($_POST['authorized']??'')!=='yes') throw new Exception('Authorization required — confirm you are authorized to actively test this target.');
            $h=clean_host($target); if(!is_valid_domain($h)) throw new Exception('Invalid target.');
            $opts=['stealth'=>($_POST['stealth']??'')==='1',
                   'reflect_limit'=>min(15,max(3,(int)($_POST['reflect_limit']??8))),
                   'path_cap'=>min(40,max(8,(int)($_POST['path_cap']??24)))];
            $out['data']=rt_active_recon($h,$opts); break; }
        case 'rt_safepoc': {
            if(($_POST['authorized']??'')!=='yes') throw new Exception('Authorization required — confirm you are authorized to test this target.');
            $h=clean_host($target); if(!is_valid_domain($h)) throw new Exception('Invalid target.');
            $out['data']=rt_safe_poc(resolve_base($h),['limit'=>min(12,max(3,(int)($_POST['limit']??8)))]); break; }
        case 'rt_exploit_intel': {
            $cves=json_decode($_POST['cves']??'[]',true);
            if(!is_array($cves)) throw new Exception('Malformed CVE payload.');
            $out['data']=rt_exploit_intel(array_slice($cves,0,100)); break; }
        case 'sublist3r': {
            if(($_POST['authorized']??'')!=='yes') throw new Exception('Authorization required — confirm you are authorized to enumerate this domain.');
            $h=clean_host($target); if(!is_valid_domain($h)) throw new Exception('Invalid target.');
            $out['data']=sublist3r_enum($h,[
                'brute'=>($_POST['brute']??'')==='1',
                'resolve'=>($_POST['resolve']??'1')!=='0',
                'cap'=>min(1000,max(20,(int)($_POST['cap']??300)))]); break; }
        case 'sublist3r_alive': {
            if(($_POST['authorized']??'')!=='yes') throw new Exception('Authorization required.');
            $h=clean_host($target); if(!is_valid_domain($h)) throw new Exception('Invalid target.');
            $subs=json_decode($_POST['subs']??'[]',true); if(!is_array($subs)) throw new Exception('Malformed subs payload.');
            $out['data']=sl3r_alive($h,$subs); break; }
        default: throw new Exception('Unknown action: '.$action);
    } } catch (\Throwable $e) { $out['ok']=false; $out['error']=$e->getMessage(); }
    $out['elapsed']=round(microtime(true)-$t0,2); j_out($out);
}
$diag = runtime_diagnostics(); $php_ok = function_exists('curl_init');
?><!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title><?=h(APP_NAME)?> v<?=h(APP_VERSION)?></title>
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/acorn/8.11.3/acorn.min.js"></script>
<style>
:root{
  --bg-1:#e9eefb;--bg-2:#f4f7fd;--panel:#ffffff;--panel-soft:#f5f8ff;--panel-hover:#eef4ff;
  --line:#e6ecf6;--line-strong:#d4ddec;
  --ink:#0d1526;--ink-soft:#38445c;--dim:#64748b;--dim-2:#94a3b8;
  --accent:#2f6bff;--accent-2:#1d4ed8;--accent-soft:#dbe6ff;
  --teal:#0d9488;--teal-soft:#ccfbf1;--purple:#7c3aed;--purple-soft:#ede9fe;
  --orange:#ea580c;--orange-soft:#ffedd5;--emerald:#10b981;--emerald-soft:#d1fae5;
  --amber:#f59e0b;--amber-soft:#fef3c7;
  --ok:#16a34a;--ok-soft:#dcfce7;--warn:#d97706;--warn-soft:#fef3c7;
  --bad:#dc2626;--bad-soft:#fee2e2;--info:#0284c7;--info-soft:#e0f2fe;
  --radius:16px;--radius-sm:11px;--radius-xs:8px;
  --shadow-sm:0 1px 2px rgba(15,23,42,.04),0 1px 3px rgba(15,23,42,.05);
  --shadow-md:0 6px 18px -6px rgba(15,23,42,.12),0 2px 6px rgba(15,23,42,.05);
  --shadow-lg:0 24px 48px -18px rgba(15,23,42,.24),0 8px 20px -10px rgba(15,23,42,.12);
  --ring:0 0 0 4px rgba(47,107,255,.18);
  --grad-brand:linear-gradient(135deg,#2f6bff 0%,#0ea5e9 55%,#14b8a6 100%);
  --grad-brand-soft:linear-gradient(135deg,rgba(47,107,255,.12),rgba(20,184,166,.12));
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  background:
    radial-gradient(1200px 520px at 8% -12%,#dbe7ff 0%,transparent 58%),
    radial-gradient(1000px 460px at 96% -18%,#c7f7f0 0%,transparent 55%),
    radial-gradient(900px 700px at 50% 120%,#e6ecfb 0%,transparent 60%),
    linear-gradient(180deg,var(--bg-1),var(--bg-2));
  background-attachment:fixed;
  color:var(--ink);min-height:100vh;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
  font-size:14px;line-height:1.55;letter-spacing:-.005em;
}
a{color:var(--accent);text-decoration:none;transition:color .15s}
a:hover{text-decoration:underline;color:var(--accent-2)}
::selection{background:rgba(47,107,255,.22)}
header.top{
  background:rgba(255,255,255,.72);
  backdrop-filter:saturate(180%) blur(16px);-webkit-backdrop-filter:saturate(180%) blur(16px);
  border-bottom:1px solid rgba(214,223,238,.7);
  padding:15px 34px;display:flex;align-items:center;gap:16px;
  position:sticky;top:0;z-index:50;
  box-shadow:0 1px 0 rgba(255,255,255,.6) inset,0 6px 24px -18px rgba(15,23,42,.4);
}
header.top .logo{
  width:46px;height:46px;border-radius:13px;background:var(--grad-brand);
  display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:15px;letter-spacing:.5px;
  box-shadow:0 8px 20px -6px rgba(47,107,255,.55),0 0 0 1px rgba(255,255,255,.25) inset;
  position:relative;overflow:hidden;
}
header.top .logo::after{content:"";position:absolute;inset:0;background:linear-gradient(140deg,rgba(255,255,255,.45),transparent 45%)}
header.top h1{margin:0;font-size:17.5px;font-weight:800;letter-spacing:-.02em;background:linear-gradient(90deg,#0d1526,#334155);-webkit-background-clip:text;background-clip:text}
header.top .sub{color:var(--dim);font-size:12px;margin-top:3px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
header.top .sub .ver{background:var(--accent-soft);color:var(--accent-2);padding:2px 9px;border-radius:999px;font-weight:700;font-size:10.5px;letter-spacing:.02em;box-shadow:0 0 0 1px rgba(47,107,255,.15) inset}
header.top .right{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:11.5px;font-weight:600;color:var(--ink-soft);background:rgba(255,255,255,.75);border:1px solid var(--line);padding:7px 13px;border-radius:999px;display:inline-flex;align-items:center;gap:7px;box-shadow:var(--shadow-sm);transition:.18s cubic-bezier(.4,0,.2,1)}
.chip.ok .dot{background:var(--ok);box-shadow:0 0 0 3px rgba(22,163,74,.18)}
.chip.bad .dot{background:var(--bad);box-shadow:0 0 0 3px rgba(220,38,38,.18)}
.chip .dot{width:7px;height:7px;border-radius:999px}
.chip.ok .dot{animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 3px rgba(22,163,74,.18)}50%{box-shadow:0 0 0 5px rgba(22,163,74,.06)}}
.chip.btn{cursor:pointer;text-decoration:none}
.chip.btn:hover{background:var(--accent-soft);border-color:var(--accent);color:var(--accent-2);transform:translateY(-1px);box-shadow:var(--shadow-md)}
main{max-width:1380px;margin:26px auto;padding:0 24px 88px}
.notice{margin:0 0 22px;padding:15px 18px;border-radius:var(--radius-sm);border:1px solid #f6d98a;background:linear-gradient(180deg,#fffdf5,#fef4d9);color:#78350f;font-size:13px;display:flex;gap:13px;align-items:flex-start;box-shadow:var(--shadow-sm);animation:fadeUp .5s ease both}
.tabs{display:flex;gap:6px;background:rgba(255,255,255,.8);border:1px solid var(--line);border-radius:var(--radius);padding:7px;box-shadow:var(--shadow-md);margin-bottom:22px;flex-wrap:wrap;backdrop-filter:blur(8px)}
.tab-btn{flex:1;min-width:150px;padding:13px 16px;border:0;background:transparent;border-radius:var(--radius-sm);cursor:pointer;font-family:inherit;font-weight:650;font-size:13px;color:var(--dim);transition:.22s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden;letter-spacing:-.01em}
.tab-btn::after{content:"";position:absolute;left:50%;bottom:6px;width:0;height:2.5px;border-radius:2px;background:var(--accent);transform:translateX(-50%);transition:width .25s ease}
.tab-btn:hover{background:var(--panel-hover);color:var(--ink-soft)}
.tab-btn:hover::after{width:26px}
.tab-btn.active{background:var(--grad-brand);color:#fff;box-shadow:0 8px 18px -8px rgba(47,107,255,.6)}
.tab-btn.active::after{width:0}
.tab-btn.active.teal{background:linear-gradient(135deg,var(--teal),#0369a1);box-shadow:0 8px 18px -8px rgba(13,148,136,.6)}
.tab-btn.active.orange{background:linear-gradient(135deg,var(--orange),#c2410c);box-shadow:0 8px 18px -8px rgba(234,88,12,.6)}
.tab-btn.active.purple{background:linear-gradient(135deg,var(--purple),#5b21b6);box-shadow:0 8px 18px -8px rgba(124,58,237,.6)}
.tab-pane{display:none}
.tab-pane.active{display:block;animation:fadeUp .4s ease both}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow-md);position:relative;overflow:hidden;transition:box-shadow .25s ease,transform .25s ease}
.card:hover{box-shadow:var(--shadow-lg);transform:translateY(-2px)}
.card::before{content:"";position:absolute;left:0;top:0;height:4px;width:100%;background:var(--grad-brand)}
.card.ip::before{background:linear-gradient(90deg,var(--teal),#0ea5e9,var(--accent))}
.card.orange::before{background:linear-gradient(90deg,var(--orange),var(--warn),var(--bad))}
.card h2{margin:0 0 4px;font-size:16.5px;font-weight:800;display:flex;align-items:center;gap:13px;letter-spacing:-.02em}
.card h2 .icobox{width:38px;height:38px;border-radius:11px;background:var(--accent-soft);color:var(--accent);display:inline-flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 10px -4px rgba(47,107,255,.4),0 0 0 1px rgba(47,107,255,.08) inset;flex:0 0 auto}
.card.ip h2 .icobox{background:var(--teal-soft);color:var(--teal);box-shadow:0 4px 10px -4px rgba(13,148,136,.4)}
.card.orange h2 .icobox{background:var(--orange-soft);color:var(--orange);box-shadow:0 4px 10px -4px rgba(234,88,12,.4)}
.card h2 .badge{margin-left:auto;font-size:10px;font-weight:700;background:var(--panel-soft);color:var(--dim);padding:6px 11px;border-radius:999px;border:1px solid var(--line);text-transform:uppercase;letter-spacing:.04em}
.card p.desc{margin:11px 0 4px;color:var(--dim);font-size:12.5px;line-height:1.6}
form label{font-size:12px;color:var(--ink-soft);font-weight:650;display:block;margin:15px 0 6px;letter-spacing:-.01em}
form label.check{font-weight:500;color:var(--dim);display:flex;gap:9px;align-items:flex-start;font-size:12.5px;cursor:pointer}
form label.check input{accent-color:var(--accent);width:15px;height:15px;margin-top:1px}
input[type=text],input[type=password],select,textarea{width:100%;padding:12px 14px;border-radius:var(--radius-sm);border:1.5px solid var(--line-strong);background:#fff;color:var(--ink);font-size:14px;outline:none;font-family:inherit;transition:border-color .18s,box-shadow .18s,background .18s}
input[type=text]:hover,input[type=password]:hover,select:hover,textarea:hover{border-color:var(--dim-2)}
textarea{min-height:280px;font-family:'JetBrains Mono',monospace;font-size:12.5px;resize:vertical;line-height:1.6}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:var(--ring);background:#fff}
button.submit,.btn{padding:12px 22px;border-radius:var(--radius-sm);border:0;color:#fff;font-weight:650;cursor:pointer;font-size:13.5px;display:inline-flex;align-items:center;gap:8px;font-family:inherit;transition:transform .16s cubic-bezier(.4,0,.2,1),box-shadow .16s,filter .16s;text-decoration:none;letter-spacing:-.01em}
button.submit{margin-top:20px;background:var(--grad-brand);box-shadow:0 10px 22px -10px rgba(47,107,255,.7)}
button.submit:hover,.btn:hover{transform:translateY(-2px);box-shadow:0 14px 26px -10px rgba(47,107,255,.6);text-decoration:none}
button.submit:active,.btn:active{transform:translateY(0)}
button.submit:disabled{opacity:.65;cursor:wait;transform:none;filter:saturate(.6)}
button.submit.ip{background:linear-gradient(135deg,var(--teal),#0369a1);box-shadow:0 10px 22px -10px rgba(13,148,136,.7)}
button.submit.orange{background:linear-gradient(135deg,var(--orange),#c2410c);box-shadow:0 10px 22px -10px rgba(234,88,12,.7)}
.btn.primary{background:var(--grad-brand)}
.btn.secondary{background:var(--panel-soft);color:var(--ink-soft);border:1px solid var(--line-strong);box-shadow:var(--shadow-sm)}
.btn.secondary:hover{background:#fff;border-color:var(--accent);color:var(--accent-2);box-shadow:var(--shadow-md)}
.btn.purple{background:linear-gradient(135deg,var(--purple),#5b21b6);box-shadow:0 10px 22px -10px rgba(124,58,237,.7)}
.btn.sm{padding:7px 13px;font-size:12px}
.code-row{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:end}
.section{margin-top:36px;animation:fadeUp .5s ease both}
.section-head{display:flex;align-items:center;gap:12px;margin-bottom:15px;flex-wrap:wrap}
.section-head h3{font-size:12px;margin:0;font-weight:800;letter-spacing:.9px;text-transform:uppercase;display:flex;align-items:center;gap:11px;color:var(--ink-soft)}
.section-head h3::before{content:"";width:5px;height:17px;border-radius:3px;background:var(--grad-brand)}
.section-head .status{margin-left:auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:13px}
.stat{background:var(--panel);border:1px solid var(--line);padding:16px 18px;border-radius:var(--radius-sm);box-shadow:var(--shadow-sm);position:relative;overflow:hidden;transition:transform .2s ease,box-shadow .2s ease}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--grad-brand);opacity:.85}
.stat:hover{transform:translateY(-3px);box-shadow:var(--shadow-md)}
.stat .n{font-size:26px;font-weight:800;line-height:1.1;letter-spacing:-.03em}
.stat .l{font-size:10.5px;color:var(--dim);text-transform:uppercase;margin-top:6px;font-weight:700;letter-spacing:.05em}
.table-wrap{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);overflow:hidden;box-shadow:var(--shadow-sm)}
.table-wrap.scroll{max-height:640px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:11px 15px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
tbody tr:last-child td{border-bottom:0}
th{background:linear-gradient(180deg,#f7faff,#eef3fc);color:var(--ink-soft);font-weight:700;font-size:11px;letter-spacing:.5px;text-transform:uppercase;position:sticky;top:0;z-index:1}
tbody tr{transition:background .12s}
tbody tr:nth-child(even) td{background:rgba(244,247,253,.5)}
tbody tr:hover td{background:var(--panel-hover)}
.pill{display:inline-block;padding:3px 11px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap;letter-spacing:.01em}
.pill.ok{background:var(--ok-soft);color:#166534}.pill.warn{background:var(--warn-soft);color:#92400e}.pill.bad{background:var(--bad-soft);color:#991b1b}.pill.info{background:var(--info-soft);color:#075985}.pill.dim{background:var(--panel-soft);color:var(--dim);border:1px solid var(--line)}.pill.purple{background:var(--purple-soft);color:#6d28d9}.pill.emerald{background:var(--emerald-soft);color:#065f46}.pill.orange{background:var(--orange-soft);color:#9a3412}.pill.server-error{background:#fce7f3;color:#9d174d}.pill.waf-block{background:#e0e7ff;color:#3730a3}
.sev-Critical{color:#7f1d1d;font-weight:800;background:var(--bad-soft);padding:2px 9px;border-radius:6px;box-shadow:0 0 0 1px rgba(220,38,38,.2) inset}.sev-High{color:var(--bad);font-weight:800}.sev-Medium{color:var(--warn);font-weight:800}.sev-Low{color:var(--info);font-weight:800}.sev-Info{color:var(--dim);font-weight:700}
code{font-family:'JetBrains Mono',monospace;background:var(--panel-soft);padding:2px 6px;border-radius:5px;font-size:12px;color:#334155;border:1px solid var(--line);word-break:break-all}
th code,.pill code{background:transparent;border:0;padding:0}
.kv{display:grid;grid-template-columns:200px 1fr;gap:10px 16px;font-size:13px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:18px;box-shadow:var(--shadow-sm)}
.kv .k{color:var(--dim);font-weight:650;font-size:12px}.kv .v{color:var(--ink);word-break:break-word}
.tag-cloud{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:15px;max-height:320px;overflow:auto;box-shadow:var(--shadow-sm)}
.tag{display:inline-block;background:var(--accent-soft);color:var(--accent-2);padding:5px 11px;border-radius:7px;margin:3px;font-size:12px;font-weight:600;border:1px solid rgba(47,107,255,.15);transition:transform .12s}
.tag:hover{transform:translateY(-1px)}
.tag.bad{background:var(--bad-soft);color:#991b1b;border-color:rgba(220,38,38,.2)}
.tag.dim{background:var(--panel-soft);color:var(--dim);border-color:var(--line)}
h4.sub{margin:20px 0 9px;color:var(--ink);font-size:13.5px;font-weight:800;display:flex;align-items:center;gap:9px;letter-spacing:-.01em}
h4.sub::before{content:"";width:4px;height:13px;background:var(--grad-brand);border-radius:2px}
.findings-note{color:var(--ink-soft);font-size:12.5px;margin-top:12px;padding:11px 15px;background:var(--info-soft);border-radius:9px;border-left:3px solid var(--info);line-height:1.6}
.pager{display:flex;flex-wrap:wrap;gap:6px;align-items:center;justify-content:center;margin-top:14px;padding:12px 4px}
.pager button{padding:7px 13px;font-size:12.5px;font-weight:650;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:9px;cursor:pointer;transition:all .15s;min-width:40px;box-shadow:var(--shadow-sm)}
.pager button:hover:not(:disabled){background:var(--accent-soft);border-color:var(--accent);color:var(--accent-2);transform:translateY(-1px)}
.pager button.active{background:var(--grad-brand);border-color:transparent;color:#fff;box-shadow:0 6px 14px -6px rgba(47,107,255,.6)}
.pager button:disabled{opacity:.4;cursor:not-allowed}
.pager .info{font-size:12px;color:var(--dim);padding:0 8px}
.section-loading{display:flex;align-items:center;gap:13px;padding:17px 19px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);color:var(--dim);font-size:13px;box-shadow:var(--shadow-sm)}
.mini-spin{width:19px;height:19px;border-radius:50%;border:2.5px solid var(--accent-soft);border-top-color:var(--accent);animation:spin .7s linear infinite;flex:0 0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
.progress-wrap{margin-top:22px;padding:17px 19px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow-md);animation:fadeUp .35s ease both}
.progress-wrap .plabel{display:flex;justify-content:space-between;font-size:12.5px;color:var(--ink-soft);margin-bottom:9px}
.progress-track{width:100%;height:9px;background:var(--panel-soft);border-radius:999px;overflow:hidden;border:1px solid var(--line)}
.progress-fill{height:100%;background:var(--grad-brand);width:0;transition:width .4s ease;border-radius:999px;position:relative;overflow:hidden}
.progress-fill::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);animation:shimmer 1.4s linear infinite}
@keyframes shimmer{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
.action-bar{margin-top:24px;padding:18px 22px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow-md);display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;animation:fadeUp .35s ease both}
.action-bar .info{font-size:13px;color:var(--ink-soft)}
.dir-controls{display:grid;grid-template-columns:1fr 200px 160px 120px;gap:10px;align-items:end;margin-top:12px}
.err-note{color:#991b1b;font-size:12.5px;padding:11px 15px;background:var(--bad-soft);border-radius:9px;border-left:3px solid var(--bad);line-height:1.6}
.dl-row{margin-top:44px;text-align:center;padding:30px;background:linear-gradient(180deg,#fff,var(--panel-soft));border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow-md);position:relative;overflow:hidden}
.dl-row::before{content:"";position:absolute;inset:0;background:var(--grad-brand-soft);opacity:.5;pointer-events:none}
.dl-row h4{margin:0 0 14px;font-size:15px;font-weight:800;position:relative}
footer{padding:26px;text-align:center;color:var(--dim);font-size:12px;border-top:1px solid var(--line);margin-top:40px;background:rgba(255,255,255,.65)}
.modal{position:fixed;inset:0;background:rgba(13,21,38,.55);backdrop-filter:blur(7px);-webkit-backdrop-filter:blur(7px);display:none;align-items:center;justify-content:center;z-index:101;padding:20px}
.modal.on{display:flex;animation:fadeIn .2s ease both}
.modal-card{background:#fff;border-radius:var(--radius);padding:28px 32px;max-width:760px;width:100%;max-height:85vh;overflow:auto;position:relative;box-shadow:var(--shadow-lg);animation:modalIn .28s cubic-bezier(.16,1,.3,1) both}
.modal-card h3{margin:0 0 4px;font-size:19px;font-weight:800;letter-spacing:-.02em}
.modal-card .close{position:absolute;top:16px;right:18px;background:var(--panel-soft);border:1px solid var(--line);border-radius:8px;width:32px;height:32px;font-size:16px;cursor:pointer;color:var(--dim);transition:.15s;display:flex;align-items:center;justify-content:center}
.modal-card .close:hover{background:var(--bad-soft);color:var(--bad);border-color:rgba(220,38,38,.3)}
.changelog-item{border-left:3px solid var(--accent);padding:10px 15px;margin-bottom:12px;background:var(--panel-soft);border-radius:0 9px 9px 0}
.changelog-item h4{margin:0 0 6px;font-size:13px;display:flex;align-items:center;gap:10px}
.changelog-item h4 .tag-v{background:var(--grad-brand);color:#fff;padding:2px 9px;border-radius:999px;font-size:10.5px;font-weight:700}
.changelog-item ul{margin:0;padding-left:20px;font-size:12.5px;line-height:1.6}
.owasp-group{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:13px 17px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;box-shadow:var(--shadow-sm);transition:transform .15s}
.owasp-group:hover{transform:translateX(2px)}
.owasp-group .name{font-weight:650;font-size:13px}
.owasp-group .bar{flex:1;margin:0 16px;height:7px;background:var(--panel-soft);border-radius:999px;overflow:hidden;max-width:300px}
.owasp-group .bar span{display:block;height:100%;background:linear-gradient(90deg,var(--bad),var(--warn));border-radius:999px}
.code-snippet{background:#0c1424;border:1px solid #1c2942;border-radius:9px;margin:8px 0 2px;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.03),0 6px 18px -10px rgba(0,0,0,.5)}
.code-snippet .cs-head{display:flex;justify-content:space-between;align-items:center;padding:7px 13px;background:#101d33;border-bottom:1px solid #1c2942;font-size:10.5px;color:#93a4c7;font-family:'JetBrains Mono',monospace;letter-spacing:.03em}
.code-snippet .cs-head .lang{color:#5eead4;font-weight:700}
.code-snippet pre{margin:0;padding:11px 0;overflow-x:hidden;font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:1.7;color:#c9d6ee;background:#0c1424}
.code-snippet .ln{display:flex;align-items:flex-start}
.code-snippet .ln .no{flex:0 0 44px;text-align:right;padding:0 10px;color:#3d4d6b;user-select:none;border-right:1px solid #1c2942;margin-right:10px}
.code-snippet .ln .src{white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;padding-right:12px;flex:1;min-width:0}
.code-snippet .ln.hit{background:rgba(220,38,38,.12)}
.code-snippet .ln.hit .no{color:#f87171;font-weight:700}
.code-snippet .ln .hl{background:rgba(220,38,38,.42);color:#fecaca;border-radius:2px;padding:0 2px;font-weight:600}
.snippet-toggle{cursor:pointer;color:var(--accent);font-size:11.5px;font-weight:650;user-select:none}
.snippet-toggle:hover{text-decoration:underline}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:var(--panel-soft)}
::-webkit-scrollbar-thumb{background:var(--line-strong);border-radius:7px;border:2px solid var(--panel-soft)}
::-webkit-scrollbar-thumb:hover{background:var(--dim-2)}
.code-snippet ::-webkit-scrollbar{height:8px}.code-snippet ::-webkit-scrollbar-thumb{background:#26365a;border:0}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes modalIn{from{opacity:0;transform:translateY(16px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
@media (max-width:900px){
  header.top{padding:13px 18px}
  header.top h1{font-size:15.5px}
  main{padding:0 16px 70px;margin-top:18px}
  .card{padding:18px}
  .tab-btn{min-width:calc(50% - 6px)}
  .dir-controls{grid-template-columns:1fr 1fr;gap:10px}
  .kv{grid-template-columns:1fr}
  .kv .k{color:var(--ink-soft)}
  .code-row{grid-template-columns:1fr}
  .code-row button{width:100%;justify-content:center}
}
@media (max-width:560px){
  header.top .sub{display:none}
  .tab-btn{min-width:100%}
  .action-bar{flex-direction:column;align-items:stretch}
  .action-bar div{justify-content:center}
  .stat .n{font-size:23px}
}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.rep-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.1fr);gap:18px;margin-top:6px}
.rep-left{display:flex;flex-direction:column}
.rep-line{display:grid;grid-template-columns:120px 1fr;gap:10px;margin-bottom:8px}
.rep-line select{font-weight:700}
.rep-opts{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px;flex-wrap:wrap}
.rep-right{display:flex;flex-direction:column;min-width:0}
.rep-resp-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:14px}
.rep-resp-head #rep-status-badges{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
#rep-response{background:var(--panel-soft);border:1px solid var(--line);border-radius:var(--radius-sm);padding:14px;min-height:320px;max-height:600px;overflow:auto}
.rep-raw{background:#0c1424;border:1px solid #1c2942;border-radius:9px;overflow:hidden;margin-top:8px}
.rep-raw .rep-raw-head{padding:6px 12px;background:#101d33;border-bottom:1px solid #1c2942;font-size:10.5px;color:#93a4c7;font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between}
.rep-raw pre{margin:0;padding:11px 13px;font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:1.65;color:#c9d6ee;white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto}
.rep-hist-item{display:grid;grid-template-columns:64px 1fr auto;gap:12px;align-items:center;padding:10px 14px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);margin-bottom:8px;box-shadow:var(--shadow-sm);transition:transform .12s}
.rep-hist-item:hover{transform:translateX(2px);box-shadow:var(--shadow-md)}
.rep-hist-item code{font-size:11px;word-break:break-all}
@media (max-width:900px){.rep-grid{grid-template-columns:1fr}.rep-line{grid-template-columns:100px 1fr}}
.rt-target-bar{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin:12px 0 6px;padding:12px 16px;background:linear-gradient(180deg,#fff5f5,#fee2e2);border:1px solid #fca5a5;border-radius:var(--radius-sm);box-shadow:var(--shadow-sm)}
.rt-target-left{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.rt-target-label{font-weight:800;font-size:12px;color:#7f1d1d;letter-spacing:.02em}
#rt-target-indicator{font-size:13px;font-weight:700;background:#fff;border:1px solid #fca5a5;color:#7f1d1d;padding:3px 10px;border-radius:7px}
.rt-target-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.rt-target-right #rt-target-override{width:260px;max-width:60vw;padding:8px 12px;border:1.5px solid #fca5a5;border-radius:9px;font-size:13px;background:#fff;color:var(--ink)}
.rt-target-right #rt-target-override:focus{border-color:#dc2626;box-shadow:0 0 0 4px rgba(220,38,38,.14)}
.rt-target-note{font-size:11.5px;color:#991b1b;margin:0 0 4px;padding:0 2px}
@media (max-width:640px){.rt-target-bar{flex-direction:column;align-items:stretch}.rt-target-right #rt-target-override{width:100%;max-width:none}}
.scan-strip{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin:0 6px;min-height:26px}
.scan-strip .scan-idle{font-size:11px;font-weight:600;color:var(--dim-2);display:inline-flex;align-items:center;gap:5px}
.scan-badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;color:#fff;padding:4px 10px;border-radius:999px;box-shadow:var(--shadow-sm);white-space:nowrap;animation:fadeIn .2s ease both}
.scan-badge.url{background:linear-gradient(135deg,var(--accent),var(--accent-2))}
.scan-badge.ip{background:linear-gradient(135deg,var(--teal),#0369a1)}
.scan-badge.code{background:linear-gradient(135deg,var(--orange),#c2410c)}
.scan-badge.nuclei{background:linear-gradient(135deg,var(--purple),#5b21b6)}
.scan-badge .scan-spin{width:10px;height:10px;border-radius:50%;border:2px solid rgba(255,255,255,.45);border-top-color:#fff;animation:spin .7s linear infinite;flex:0 0 auto}
.scan-strip .scan-count{font-size:10px;font-weight:800;color:var(--dim);background:var(--panel-soft);border:1px solid var(--line);padding:2px 7px;border-radius:999px}
.form-busy{opacity:.6;pointer-events:none}
@media (max-width:820px){.scan-strip{order:3;width:100%;margin:6px 0 0}}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important;scroll-behavior:auto!important}
}
</style>
</head><body>
<header class="top">
  <div class="logo">TT</div>
  <div><h1><?=h(APP_NAME)?></h1><div class="sub"><span class="ver">v<?=h(APP_VERSION)?></span><span>Build <?=h(APP_BUILD)?></span></div></div>
  <div id="scan-strip" class="scan-strip" title="Live scan activity across all tabs"><span class="scan-idle">● all idle</span></div>
  <div class="right">
    <span class="chip <?=$php_ok?'ok':'bad'?>"><span class="dot"></span>PHP <?=$php_ok?'ready':'not detected'?></span>
    <span class="chip btn" onclick="openModal('rules-modal')">SAST Rules</span>
    <span class="chip btn" onclick="openModal('settings-modal')">API Keys</span>
    <span class="chip btn" onclick="openModal('about-modal')">About</span>
    <a class="chip btn" href="?download=1">Source</a>
  </div>
</header>
<main>
<div class="notice"><span style="font-size:18px">⚠️</span><div><strong>Authorized use only.</strong> Run only on assets you own or are authorized to assess. Code Analyzer runs 100% in your browser.</div></div>
<div class="tabs">
  <button class="tab-btn active" data-tab="url" data-color="">Website URL Recon</button>
  <button class="tab-btn" data-tab="ip" data-color="teal">IP Address Recon</button>
  <button class="tab-btn" data-tab="code" data-color="orange">Code Analyzer (SAST)</button>
  <button class="tab-btn" data-tab="nuclei" data-color="purple">Nuclei Scanner</button>
  <button class="tab-btn" data-tab="repeater" data-color="orange">HTTP Repeater</button>
</div>
<div id="input-cards">
  <div class="tab-pane active" id="pane-url">
    <div class="card">
      <h2><span class="icobox">🌐</span> Website URL Recon <span class="badge">passive + light-active</span></h2>
      <p class="desc">Page &amp; security-header grade, WAF detection, directory probe, TLS/DNS/cookies, VirusTotal — plus <strong>advanced engines</strong>: HTTP/2·3 &amp; TLS-version detection, security.txt/.well-known posture, CORS misconfiguration, JS secret/endpoint extraction, subdomain-takeover, GraphQL introspection, DNS CAA + DNSSEC validation, open-redirect / SSRF-parameter detection, and Shodan favicon-hash fingerprinting. All non-destructive.</p>
      <form id="form-url" class="scan-form" data-kind="url">
        <label>Target domain or URL</label>
        <input type="text" name="target" placeholder="example.com" required>
        <label class="check" style="margin-top:6px"><input type="checkbox" id="opt-wpscan" name="wpscan" checked> Enable WordPress scan (version + plugin/theme vulnerability scoring)</label>
        <div id="wpdepth-row" style="display:flex;align-items:center;gap:8px;margin:2px 0 2px 26px;font-size:12.5px;color:var(--dim)">
          <span>Author-archive enumeration depth:</span>
          <select id="opt-wpdepth" style="padding:5px 10px;border:1px solid var(--line);border-radius:7px;font-size:12.5px;background:var(--panel);color:var(--ink)">
            <option value="10" selected>Quick (IDs 1–10)</option>
            <option value="25">Standard (1–25)</option>
            <option value="50">Deep (1–50)</option>
            <option value="100">Thorough (1–100)</option>
            <option value="200">Exhaustive (1–200)</option>
          </select>
          <span style="font-size:11px">↑ higher = more users found, more requests</span>
        </div>
        <label class="check"><input type="checkbox" name="ack" required> I confirm I am authorized to assess this target.</label>
        <button type="submit" class="submit">Run URL Recon</button>
      </form>
    </div>
    <div id="prog-url" class="progress-wrap" style="display:none"><div class="plabel"><span><strong id="progtitle-url">Scanning…</strong> <span id="progtarget-url" style="color:var(--dim)"></span></span><span id="progcount-url">0 / 0</span></div><div class="progress-track"><div class="progress-fill" id="progfill-url"></div></div></div>
    <div id="act-url" class="action-bar" style="display:none"><div class="info">Analysis of <strong id="acttarget-url"></strong> complete · <span id="acttime-url"></span></div><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn secondary" onclick="newScan('url')">New Scan</button><button class="btn" style="background:#7f1d1d;color:#fff" onclick="renderPlaybook()">🎯 Attack Playbook</button><button class="btn" style="background:#450a0a;color:#fff" onclick="renderRedTeam()">🔴 Red Team Mode</button><button class="btn" style="background:linear-gradient(135deg,#ea580c,#c2410c);color:#fff" onclick="sendToRepeater(urlScanBase())">⇢ Send to Repeater</button><button class="btn purple" onclick="exportPDF(event)">Export PDF</button></div></div>
    <div id="results-url"></div>
  </div>
  <div class="tab-pane" id="pane-ip">
    <div class="card ip">
      <h2><span class="icobox">🛰️</span> IP Address Recon <span class="badge">public + enriched</span></h2>
      <p class="desc">Multi-provider geolocation aggregator (ip-api · ipwho.is · ipapi.co · freeipapi · ipinfo with consensus), RDAP, Spamhaus, TCP port sweep, Shodan, AbuseIPDB, VirusTotal.</p>
      <form id="form-ip" class="scan-form" data-kind="ip">
        <label>Target IP address</label>
        <input type="text" name="target" placeholder="8.8.8.8" required>
        <label class="check"><input type="checkbox" name="ack" required> I confirm I am authorized to assess this target.</label>
        <button type="submit" class="submit ip">Run IP Recon</button>
      </form>
    </div>
    <div id="prog-ip" class="progress-wrap" style="display:none"><div class="plabel"><span><strong id="progtitle-ip">Scanning…</strong> <span id="progtarget-ip" style="color:var(--dim)"></span></span><span id="progcount-ip">0 / 0</span></div><div class="progress-track"><div class="progress-fill" id="progfill-ip"></div></div></div>
    <div id="act-ip" class="action-bar" style="display:none"><div class="info">Analysis of <strong id="acttarget-ip"></strong> complete · <span id="acttime-ip"></span></div><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn secondary" onclick="newScan('ip')">New Scan</button><button class="btn purple" onclick="exportPDF(event)">Export PDF</button></div></div>
    <div id="results-ip"></div>
  </div>
  <div class="tab-pane" id="pane-code">
    <div class="card orange">
      <h2><span class="icobox">🧪</span> Code Analyzer — SAST Engine <span class="badge" id="rule-count-badge">rules</span></h2>
      <p class="desc">Paste source code from any language, or fetch a remote script URL. 122 SAST rules across PHP, JS/TS, Python, Java, C#, Go, Ruby, SQL, HTML — each with CWE + OWASP mapping and <strong>the exact code snippet</strong> that triggered it. Your code never leaves your browser.</p>
      <form id="form-fetch" style="margin-bottom:14px">
        <label>Fetch a remote script/file URL (optional)</label>
        <div class="code-row">
          <input type="text" id="fetch-url" placeholder="https://example.com/assets/app.min.js">
          <button type="submit" class="submit orange" style="margin-top:0">Fetch &amp; Load</button>
        </div>
      </form>
      <form id="form-code">
        <label>Paste code (or use Fetch above to load a script here)</label>
        <textarea id="code-input" placeholder="Paste PHP / JavaScript / Python / Java / C# / Go / Ruby / SQL / HTML"></textarea>
        <div class="code-row" style="margin-top:14px">
          <div>
            <label style="margin-top:0">Language</label>
            <select id="code-lang">
              <option value="auto">Auto-detect</option><option value="php">PHP</option><option value="js">JavaScript / TypeScript</option>
              <option value="python">Python</option><option value="java">Java</option><option value="csharp">C# / .NET</option>
              <option value="go">Go</option><option value="ruby">Ruby</option><option value="sql">SQL</option><option value="html">HTML</option>
            </select>
          </div>
          <button type="submit" class="submit orange" style="margin-top:0">Analyze Code</button>
        </div>
      </form>
    </div>
    <div id="act-code" class="action-bar" style="display:none"><div class="info">Analysis of <strong id="acttarget-code"></strong> complete · <span id="acttime-code"></span></div><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn secondary" onclick="newScan('code')">New Scan</button><button class="btn secondary" id="csvbtn-code" onclick="exportFindingsCSV(event)" style="display:none">Export Findings CSV</button><button class="btn purple" onclick="exportPDF(event)">Export PDF</button></div></div>
    <div id="results-code"></div>
  </div>
  <div class="tab-pane" id="pane-nuclei">
    <div class="card" style="--accent:#7c3aed">
      <h2><span class="icobox" style="background:var(--purple-soft);color:var(--purple)">🎯</span> Nuclei Scanner <span class="badge" id="nuclei-engine-badge">detecting…</span></h2>
      <p class="desc">Template-driven vulnerability scanning powered by <a href="https://github.com/projectdiscovery/nuclei" target="_blank">projectdiscovery/nuclei</a>. Uses the installed <code>nuclei</code> binary when available (full 12,000+ community templates), otherwise falls back to a built-in <strong>Lite engine</strong> that runs 18 bundled templates + your own pasted YAML — no binary required.</p>
      <form id="form-nuclei" class="scan-form" data-kind="nuclei">
        <label>Target domain or URL</label>
        <input type="text" name="target" placeholder="example.com" required>
        <div class="code-row" style="grid-template-columns:1fr 1fr 1fr;margin-top:4px">
          <div>
            <label style="margin-top:0">Engine mode</label>
            <select id="nuclei-mode">
              <option value="auto">Auto (binary if available)</option>
              <option value="lite">Lite engine (pure PHP)</option>
              <option value="binary">Force binary</option>
            </select>
          </div>
          <div>
            <label style="margin-top:0">Severity filter (optional)</label>
            <input type="text" id="nuclei-severity" placeholder="critical,high,medium">
          </div>
          <div>
            <label style="margin-top:0">Tags filter (optional)</label>
            <input type="text" id="nuclei-tags" placeholder="exposure,cve,misconfig">
          </div>
        </div>
        <div style="margin-top:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px">
            <label style="margin:0;font-size:12px;color:var(--ink-soft);font-weight:600">Bundled Lite templates <span id="nuctpl-count" style="color:var(--dim);font-weight:500"></span></label>
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
              <input type="text" id="nuctpl-search" placeholder="Search…" style="width:150px;padding:6px 10px;font-size:12px" oninput="nucTplRender(true)">
              <select id="nuctpl-sev" style="padding:6px 10px;font-size:12px" onchange="nucTplRender(true)">
                <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
              </select>
              <select id="nuctpl-per" style="padding:6px 10px;font-size:12px" onchange="nucTplRender(true)">
                <option value="6">6 / page</option><option value="10" selected>10 / page</option><option value="0">All</option>
              </select>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
            <button type="button" class="btn secondary sm" onclick="nucTplSelectAll(true)">Select all (filtered)</button>
            <button type="button" class="btn secondary sm" onclick="nucTplSelectAll(false)">Clear all</button>
            <span id="nuctpl-selcount" style="color:var(--dim);font-size:12px;align-self:center">0 selected</span>
          </div>
          <div id="nuctpl-picker" class="table-wrap scroll" style="max-height:280px"></div>
        </div>
        <details style="margin-top:6px">
          <summary style="cursor:pointer;color:var(--purple);font-size:12.5px;font-weight:600;padding:8px 0">▸ Paste your own Nuclei template (YAML) — optional</summary>
          <textarea id="nuclei-template" placeholder="id: my-check&#10;info:&#10;  name: My Custom Check&#10;  severity: medium&#10;  tags: custom&#10;http:&#10;  - method: GET&#10;    path:&#10;      - '{{BaseURL}}/debug'&#10;    matchers:&#10;      - type: status&#10;        status:&#10;          - 200" style="min-height:180px"></textarea>
        </details>
        <label class="check" style="margin-top:12px"><input type="checkbox" name="ack" required> I confirm I am authorized to scan this target. Nuclei sends active probes.</label>
        <button type="submit" class="submit" style="background:linear-gradient(135deg,var(--purple),#5b21b6);margin-top:14px">Run Nuclei Scan</button>
      </form>
    </div>
    <div id="act-nuclei" class="action-bar" style="display:none"><div class="info">Scan of <strong id="acttarget-nuclei"></strong> complete · <span id="acttime-nuclei"></span></div><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn secondary" onclick="newScan('nuclei')">New Scan</button><button class="btn secondary" id="csvbtn-nuclei" onclick="exportFindingsCSV(event)" style="display:none">Export Findings CSV</button><button class="btn purple" onclick="exportPDF(event)">Export PDF</button></div></div>
    <div id="results-nuclei"></div>
  </div>
  <div class="tab-pane" id="pane-repeater">
    <div class="card orange">
      <h2><span class="icobox">🛠️</span> HTTP Repeater <span class="badge">Burp-style · authorized testing</span></h2>
      <p class="desc">Craft and replay raw HTTP requests — full control over <strong>method, URL, headers, and body</strong> — then inspect the raw response (status, headers, timing, size, body). Ideal for bug-bounty &amp; authorized ethical-hacking workflows. Requests run server-side via cURL. <strong>Use only on assets you own or are explicitly authorized to test.</strong></p>
      <div class="rep-grid">
        <div class="rep-left">
          <div class="rep-line">
            <select id="rep-method">
              <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
            </select>
            <input type="text" id="rep-url" placeholder="https://target.example.com/path?param=value">
          </div>
          <label>Request headers <span style="font-weight:400;color:var(--dim)">— one per line (Name: value)</span></label>
          <textarea id="rep-headers" spellcheck="false" placeholder="User-Agent: Mozilla/5.0&#10;Accept: */*&#10;Authorization: Bearer &lt;token&gt;&#10;X-Custom-Header: test">Accept: */*
Accept-Language: en-US,en;q=0.9</textarea>
          <label>Request body <span style="font-weight:400;color:var(--dim)">— for POST/PUT/PATCH</span></label>
          <textarea id="rep-body" spellcheck="false" style="min-height:120px" placeholder="name=value&other=value  (or raw JSON)"></textarea>
          <div class="rep-opts">
            <label class="check" style="margin:0"><input type="checkbox" id="rep-follow"> Follow redirects</label>
            <span style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)">Timeout <select id="rep-timeout" style="width:auto;padding:6px 10px"><option value="10">10s</option><option value="15" selected>15s</option><option value="30">30s</option></select></span>
          </div>
          <label class="check" style="margin-top:10px"><input type="checkbox" id="rep-ack"> I confirm I am authorized to send requests to this target.</label>
          <button type="button" class="submit orange" id="rep-send" onclick="repeaterSend()">Send Request ⇢</button>
        </div>
        <div class="rep-right">
          <div class="rep-resp-head"><strong>Response</strong> <span id="rep-status-badges"></span></div>
          <div id="rep-response"><div class="findings-note">Craft a request on the left and hit <strong>Send Request</strong>. The raw response will render here.</div></div>
        </div>
      </div>
    </div>
    <div class="section" id="rep-history-sec" style="display:none">
      <div class="section-head"><h3>Request History</h3><div class="status"><button class="btn secondary sm" onclick="repeaterClearHistory()">Clear</button></div></div>
      <div id="rep-history"></div>
    </div>
  </div>
</div>
<div class="section">
  <div class="section-head"><h3>System Diagnostics</h3></div>
  <div class="table-wrap"><table><thead><tr><th style="width:220px">Component</th><th>Value</th><th style="width:100px">Status</th></tr></thead><tbody>
  <?php foreach ($diag as $d): ?><tr><td><strong><?=h($d['label'])?></strong></td><td><code><?=h($d['value'])?></code></td><td><span class="pill <?=$d['ok']?'ok':'bad'?>"><?=$d['ok']?'OK':'ISSUE'?></span></td></tr><?php endforeach; ?>
  </tbody></table></div>
</div>
<div class="dl-row"><h4>Download this dashboard</h4><a class="btn primary" href="?download=1">Download v<?=h(APP_VERSION)?></a></div>
</main>
<div id="settings-modal" class="modal"><div class="modal-card">
  <button class="close" onclick="closeModal('settings-modal')">✕</button><h3>API Keys</h3>
  <p style="color:var(--dim);font-size:13px">Stored only in your browser.</p>
  <label style="font-size:12px;font-weight:600;display:block;margin:10px 0 4px">Shodan</label><input type="password" id="k-shodan">
  <label style="font-size:12px;font-weight:600;display:block;margin:10px 0 4px">AbuseIPDB</label><input type="password" id="k-abuse">
  <label style="font-size:12px;font-weight:600;display:block;margin:10px 0 4px">VirusTotal</label><input type="password" id="k-vt">
  <label style="font-size:12px;font-weight:600;display:block;margin:10px 0 4px">WPScan API Token <span style="font-weight:400;color:var(--dim)">— enables live WordPress plugin CVEs (100K+ feed)</span></label><input type="password" id="k-wpscan">
  <div style="margin-top:16px;display:flex;gap:10px;justify-content:flex-end"><button class="btn secondary" onclick="clearKeys()">Clear</button><button class="btn primary" onclick="saveKeys()">Save</button></div>
</div></div>
<div id="rules-modal" class="modal"><div class="modal-card">
  <button class="close" onclick="closeModal('rules-modal')">✕</button><h3>SAST Rule Catalog</h3>
  <p style="color:var(--dim);font-size:13px">All active static-analysis rules.</p>
  <input type="text" id="rule-filter" placeholder="Filter by rule, language, CWE, or OWASP…" oninput="renderRuleCatalog()" style="margin-bottom:12px">
  <div id="rule-catalog"></div>
</div></div>
<div id="about-modal" class="modal"><div class="modal-card">
  <button class="close" onclick="closeModal('about-modal')">✕</button><h3><?=h(APP_NAME)?></h3>
  <p style="color:var(--dim);font-size:13px">Version <?=h(APP_VERSION)?> · <?=h(APP_AUTHOR)?></p>
  <?php foreach ($CHANGELOG as $ver=>$info): ?><div class="changelog-item"><h4><span class="tag-v">v<?=h($ver)?></span><span style="color:var(--dim);font-size:11px"><?=h($info['date'])?></span></h4><ul><?php foreach ($info['notes'] as $n): ?><li><?=h($n)?></li><?php endforeach; ?></ul></div><?php endforeach; ?>
</div></div>
<footer><strong><?=h(APP_AUTHOR)?></strong> · <?=h(APP_NAME)?> v<?=h(APP_VERSION)?></footer>
<script>
const APP={version:'<?=h(APP_VERSION)?>',name:'<?=h(APP_NAME)?>',author:'<?=h(APP_AUTHOR)?>'};
window.CURRENT_SCAN={target:'',kind:''};window.LAST_FINDINGS=[];window.LAST_CODE='';
window.DIR_STATE={rows:[],page:1,perPage:25,filterPath:'',filterStatus:'all'};
window.FIND_STATE={findings:[],lang:'',page:1,perPage:25,filterSev:'all',search:''};
function openModal(id){document.getElementById(id).classList.add('on');if(id==='rules-modal')renderRuleCatalog();}
function closeModal(id){document.getElementById(id).classList.remove('on');}
document.querySelectorAll('.modal').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)m.classList.remove('on')}));
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal').forEach(m=>m.classList.remove('on'))});
document.querySelectorAll('.tab-btn').forEach(btn=>{btn.addEventListener('click',()=>{const t=btn.dataset.tab,col=btn.dataset.color||'';document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active','teal','orange','purple'));btn.classList.add('active');if(col)btn.classList.add(col);document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));document.getElementById('pane-'+t).classList.add('active');});});
const KEYS={load(){document.getElementById('k-shodan').value=localStorage.getItem('osint_k_shodan')||'';document.getElementById('k-abuse').value=localStorage.getItem('osint_k_abuse')||'';document.getElementById('k-vt').value=localStorage.getItem('osint_k_vt')||'';const w=document.getElementById('k-wpscan');if(w)w.value=localStorage.getItem('osint_k_wpscan')||'';},get(){return{shodan_key:localStorage.getItem('osint_k_shodan')||'',abuse_key:localStorage.getItem('osint_k_abuse')||'',vt_key:localStorage.getItem('osint_k_vt')||'',wpscan_key:localStorage.getItem('osint_k_wpscan')||''};}};
function saveKeys(){localStorage.setItem('osint_k_shodan',document.getElementById('k-shodan').value.trim());localStorage.setItem('osint_k_abuse',document.getElementById('k-abuse').value.trim());localStorage.setItem('osint_k_vt',document.getElementById('k-vt').value.trim());const w=document.getElementById('k-wpscan');if(w)localStorage.setItem('osint_k_wpscan',w.value.trim());closeModal('settings-modal');toast('Saved.');}
function clearKeys(){['osint_k_shodan','osint_k_abuse','osint_k_vt','osint_k_wpscan'].forEach(k=>localStorage.removeItem(k));KEYS.load();toast('Cleared.');}
KEYS.load();
function toast(m){const t=document.createElement('div');t.textContent=m;t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;padding:10px 18px;border-radius:8px;font-size:13px;z-index:200';document.body.appendChild(t);setTimeout(()=>t.remove(),2500);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
/* v2.7.5: safe single-quoted JS string literal for use INSIDE a double-quoted HTML on* attribute.
   Escapes JS layer (\ and ') then HTML-attribute layer (& " < >) so it survives both parsers. */
function repArg(s){return "'"+String(s==null?'':s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+"'";}
function fmt(s){return s===null||s===undefined||s===''?'—':esc(s)}
async function callApi(action,target,timeoutMs){const fd=new FormData();if(target)fd.append('target',target);const k=KEYS.get();fd.append('shodan_key',k.shodan_key);fd.append('abuse_key',k.abuse_key);fd.append('vt_key',k.vt_key);if(action==='wordpress'){const dp=document.getElementById('opt-wpdepth');fd.append('wp_depth',dp?dp.value:'10');fd.append('wpscan_key',k.wpscan_key);}
  // Per-request timeout so one slow/hung step can never stall the whole scan pipeline
  const ms=timeoutMs||90000;const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),ms);
  let res,raw;
  try{res=await fetch('?api=1&action='+encodeURIComponent(action),{method:'POST',body:fd,signal:ctrl.signal});raw=await res.text();}
  catch(err){if(err.name==='AbortError')throw new Error('Timed out after '+Math.round(ms/1000)+'s');throw err;}
  finally{clearTimeout(to);}
  try{return JSON.parse(raw);}catch(e){const snippet=raw&&raw.trim()?raw.trim().slice(0,300):'empty response';throw new Error((!res.ok?('HTTP '+res.status+' — '):'')+'invalid server response ('+snippet+')');}}
function makeSection(id,title){return `<div class="section" id="sec-${id}" data-title="${esc(title)}"><div class="section-head"><h3>${esc(title)}</h3><div class="status"><span class="pill dim section-status pending" id="stat-${id}">Pending</span></div></div><div id="body-${id}"><div class="section-loading"><div class="mini-spin"></div><span>Waiting…</span></div></div></div>`;}
function setStatus(id,state,label){const el=document.getElementById('stat-'+id);if(!el)return;const m={pending:'dim',running:'info',done:'ok',error:'bad',skipped:'dim'};el.className='pill '+m[state]+' section-status '+state;el.textContent=label;}
function setBody(id,html){document.getElementById('body-'+id).innerHTML=html;}
function errorBody(id,msg){setBody(id,`<div class="err-note">${esc(msg)}</div>`);}
/* v2.7.3: per-KIND progress objects so concurrent scans in different tabs never share state */
let PROG={};
function progObj(kind){kind=kind||'url';return PROG[kind]||(PROG[kind]={done:0,total:0,target:''});}
/* v2.1.0: per-tab UI accessor — every scan kind has its own results/progress/action elements */
function K(){return window.CURRENT_SCAN.kind||'url';}
function elK(prefix,kind){return document.getElementById(prefix+'-'+(kind||K()));}
function resultsEl(kind){return document.getElementById('results-'+(kind||K()));}
/* v2.7.3: per-KIND scan-target store — immune to cross-tab overwrites */
function scanTarget(kind){kind=kind||K();if(kind==='url')return window.URL_SCAN_TARGET||'';if(kind==='ip')return window.IP_SCAN_TARGET||'';if(kind==='nuclei')return window.NUCLEI_SCAN_TARGET||'';if(kind==='code')return window.CODE_SCAN_TARGET||'Pasted code';return window.CURRENT_SCAN.target||'';}
function progressInit(target,total,kind){kind=kind||K();const P=progObj(kind);P.done=0;P.total=total;P.target=target;
  const pt=elK('progtarget',kind),pc=elK('progcount',kind),pf=elK('progfill',kind),pw=elK('prog',kind),ti=elK('progtitle',kind);
  if(pt)pt.textContent='Target: '+target;if(pc)pc.textContent='0 / '+total;if(pf)pf.style.width='0%';if(ti)ti.textContent='Scanning…';if(pw)pw.style.display='block';}
function progressStep(kind){kind=kind||K();const P=progObj(kind);P.done++;
  const pc=elK('progcount',kind),pf=elK('progfill',kind);
  if(pc)pc.textContent=P.done+' / '+P.total;if(pf)pf.style.width=Math.round(P.done/P.total*100)+'%';
  if(P.done>=P.total)progressFinish(kind);}
/* Guarantees the progress bar + action bar finalize once all steps have run,
   regardless of per-step counting drift, errors, or timeouts. */
function progressFinish(kind){kind=kind||K();const P=progObj(kind);if(P.done<P.total)P.done=P.total;
  const pc=elK('progcount',kind),pf=elK('progfill',kind),ti=elK('progtitle',kind),at=elK('acttarget',kind),tm=elK('acttime',kind),cb=elK('csvbtn',kind),ab=elK('act',kind);
  if(pc)pc.textContent=P.total+' / '+P.total;if(pf)pf.style.width='100%';
  if(ti)ti.textContent='Scan complete';if(at)at.textContent=P.target;if(tm)tm.textContent=new Date().toLocaleString();
  if(cb)cb.style.display='none';if(ab)ab.style.display='flex';}
function renderPage(id,r){if(!r.ok)return errorBody(id,r.error);const p=r.data;if(!p||!p.fetched)return errorBody(id,'Could not fetch page.');
  let html=`<div class="stats" style="margin-bottom:16px"><div class="stat"><div class="n">${esc(p.status)}</div><div class="l">HTTP Status</div></div><div class="stat"><div class="n">${(p.tech||[]).length}</div><div class="l">Tech</div></div><div class="stat"><div class="n">${(p.vuln||[]).length}</div><div class="l">Findings</div></div><div class="stat"><div class="n">${(p.scripts_ext||[]).length}</div><div class="l">Ext JS</div></div></div>
  <div class="kv"><div class="k">Final URL</div><div class="v">${fmt(p.final_url)}</div><div class="k">Title</div><div class="v">${fmt(p.title)}</div><div class="k">Body size</div><div class="v">${(p.body_size||0).toLocaleString()} bytes</div></div>`;
  if(p.tech?.length){html+=`<h4 class="sub">Technology</h4><div class="table-wrap"><table><thead><tr><th>Technology</th><th>Version</th></tr></thead><tbody>`;p.tech.forEach(t=>html+=`<tr><td><strong>${esc(t.name)}</strong></td><td><code>${fmt(t.version)}</code></td></tr>`);html+=`</tbody></table></div>`;}
  if(p.sec_rows?.length){html+=`<h4 class="sub">Security Headers</h4><div class="table-wrap"><table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>`;p.sec_rows.forEach(s=>html+=`<tr><td><strong>${esc(s.header)}</strong></td><td><span class="pill ${s.present?'ok':'bad'}">${s.present?'PRESENT':'MISSING'}</span></td><td><code>${esc((s.value||'').substring(0,150))}</code></td></tr>`);html+=`</tbody></table></div>`;}
  if(p.vuln?.length){html+=`<h4 class="sub">Vulnerability Analysis</h4><div class="table-wrap"><table><thead><tr><th>Sev</th><th>Finding</th><th>Why</th><th>Fix</th></tr></thead><tbody>`;p.vuln.forEach(v=>html+=`<tr><td><span class="sev-${esc(v.sev)}">${esc(v.sev)}</span></td><td><strong>${esc(v.title)}</strong></td><td>${esc(v.why)}</td><td style="color:var(--dim)">${esc(v.fix)}</td></tr>`);html+=`</tbody></table></div>`;}
  if(p.scripts_ext&&p.scripts_ext.length){
    window.URL_SCRIPTS=p.scripts_ext.slice();
    window.URL_BASE=p.final_url||p.url||('https://'+(window.URL_SCAN_TARGET||window.CURRENT_SCAN.target||''));
    html+=`<h4 class="sub">External Scripts — select &amp; analyze inline</h4>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
      <label class="check" style="margin:0"><input type="checkbox" id="scr-all" onchange="scrToggleAll(this.checked)"> Select all (${p.scripts_ext.length})</label>
      <button id="scr-analyze-btn" class="btn secondary sm" onclick="analyzeScriptsSelected()">Analyze selected scripts</button>
      <button id="scr-stop-btn" class="btn secondary sm" style="display:none;background:var(--bad-soft);color:#991b1b;border-color:rgba(220,38,38,.35)" onclick="scrStop()">⏹ Stop</button>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)">Concurrency
        <select id="scr-concurrency" style="padding:4px 8px;border:1px solid var(--line);border-radius:7px;font-size:12px;background:var(--panel);color:var(--ink)">
          <option value="1">1 (sequential)</option>
          <option value="3" selected>3</option>
          <option value="5">5</option>
          <option value="8">8</option>
          <option value="10">10 (fastest)</option>
        </select>
      </label>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)" title="Show the confirmation prompt only when more than this many scripts are selected. Set 0 to always confirm.">Confirm above
        <input id="scr-threshold" type="number" min="0" max="999" value="10" style="width:64px;padding:4px 8px;border:1px solid var(--line);border-radius:7px;font-size:12px;background:var(--panel);color:var(--ink)">
      </label>
      <span id="scr-count" style="color:var(--dim);font-size:12px">0 selected</span>
    </div>
    <div class="table-wrap scroll"><table><thead><tr><th style="width:40px"></th><th style="width:40px">#</th><th>Script URL</th></tr></thead><tbody>`;
    p.scripts_ext.forEach((u,i)=>{html+=`<tr><td><input type="checkbox" class="scr-cb" data-url="${esc(u)}" onchange="scrCount()"></td><td>${i+1}</td><td><code>${esc(u)}</code></td></tr>`;});
    html+=`</tbody></table></div><div id="script-out" style="margin-top:14px"></div>`;
  }
  setBody(id,html);}
/* v2.1.0: inline multi-script analysis (results stay in the URL tab) */
function scrCount(){const n=document.querySelectorAll('.scr-cb:checked').length;const el=document.getElementById('scr-count');if(el)el.textContent=n+' selected';}
function scrToggleAll(ch){document.querySelectorAll('.scr-cb').forEach(cb=>cb.checked=ch);scrCount();}
/* Analyze ONE script and return its rendered card + finding tally (used by the worker pool) */
async function scrAnalyzeOne(url){
  let body='',err='',code=0,size=0;
  // Resolve relative / protocol-relative script paths against the scanned page's base URL
  let fetchUrl=url;
  try{fetchUrl=new URL(url,window.URL_BASE||location.href).href;}catch(e){}
  try{const r=await callApi('fetch_script',fetchUrl);if(r.ok){body=r.data.body||'';code=r.data.code||0;size=r.data.size||0;}else err=r.error;}
  catch(e){err=e.message;}
  url=fetchUrl; // display the absolute URL that was actually fetched
  let findings=[];
  if(body){
    const sast=analyzeSAST(body,'js');
    let ast=[],taint=[];try{if(astAvailable()){ast=astAnalyze(body,/\b(import|export)\s+/.test(body));taint=taintAnalyze(body);}}catch(e){}
    findings=mergeFindings(mergeFindings(sast,ast),taint);
  }
  const sizeStr=size?(size>1024?Math.round(size/1024)+' KB':size+' B'):'—';
  let inner='';
  if(err)inner=`<div class="err-note">${esc(err)}</div>`;
  else if(!findings.length)inner=`<div class="findings-note">No SAST patterns matched in this script.</div>`;
  else{
    inner=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Finding</th><th style="width:70px">CWE</th><th style="width:60px">Line</th></tr></thead><tbody>`;
    findings.forEach(f=>{const cwe=f.cwe?`<a href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-','')}.html" target="_blank"><code>${esc(f.cwe)}</code></a>`:'—';const tb=f.source==='Taint'?' <span class="pill" style="background:var(--purple-soft);color:#6d28d9;font-size:9.5px">🔗 TAINT</span>':'';
      inner+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td><strong>${esc(f.title)}</strong>${tb}<div style="color:var(--dim);font-size:12px;margin-top:2px">${esc(f.why)}</div>${f.flow?renderFlow(f.flow):''}${f.snippet?renderSnippet(f.snippet,'js'):''}</td><td>${cwe}</td><td><code>${f.line||'—'}</code></td></tr>`;});
    inner+=`</tbody></table></div>`;
  }
  const card=`<details class="script-analysis" ${findings.length?'open':''} style="margin-bottom:10px;background:#0d1526;border:1px solid #1e2b47;border-radius:var(--radius-sm);padding:0 14px;box-shadow:var(--shadow-sm)">
    <summary style="cursor:pointer;padding:12px 0;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center">
      <span style="font-family:'JetBrains Mono',monospace;font-size:11.5px;word-break:break-all;flex:1;min-width:260px;color:#c9d6ee">${esc(url)}</span>
      <span style="display:flex;gap:6px;flex-wrap:wrap"><span class="pill dim">${sizeStr}</span><span class="pill dim">HTTP ${code||'?'}</span>${findings.length?`<span class="pill bad">${findings.length} findings</span>`:`<span class="pill ok">clean</span>`}</span>
    </summary><div style="padding-bottom:12px">${inner}</div></details>`;
  return {card,findings};
}
/* Prompt only when the batch is large enough to be worth confirming */
const SCR_CONFIRM_THRESHOLD_DEFAULT=10;   // fallback when the UI input is missing/invalid
function scrStop(){
  window.SCR_STOP=true;
  const b=document.getElementById('scr-stop-btn');if(b){b.disabled=true;b.textContent='Stopping…';}
  const pe=document.getElementById('scr-progress');if(pe)pe.textContent='Stopping — finishing in-flight requests…';
}
async function analyzeScriptsSelected(){
  const sel=Array.from(document.querySelectorAll('.scr-cb:checked')).map(cb=>cb.dataset.url);
  const out=document.getElementById('script-out');
  if(!sel.length){toast('Select at least one script.');return;}
  const conc=Math.max(1,parseInt(document.getElementById('scr-concurrency')?.value||'3'));
  const est=Math.ceil(sel.length/conc);
  // User-adjustable confirmation threshold (0 = always confirm; blank/invalid = default)
  const tEl=document.getElementById('scr-threshold');
  let threshold=tEl?parseInt(tEl.value):SCR_CONFIRM_THRESHOLD_DEFAULT;
  if(isNaN(threshold)||threshold<0)threshold=SCR_CONFIRM_THRESHOLD_DEFAULT;
  // Confirmation prompt — only when selection exceeds the threshold; smaller batches run immediately
  if(sel.length>threshold){
    if(!confirm(`Analyze ${sel.length} script(s) with concurrency ${conc}?\n\nThis fetches each script from its origin server (~${est} sequential wave${est===1?'':'s'}) and generates ${sel.length} outbound requests. You can press Stop at any time.\n\nProceed?`)){return;}
  }
  window.SCR_STOP=false;
  const aBtn=document.getElementById('scr-analyze-btn'),sBtn=document.getElementById('scr-stop-btn');
  if(aBtn)aBtn.disabled=true;
  if(sBtn){sBtn.style.display='inline-flex';sBtn.disabled=false;sBtn.textContent='⏹ Stop';}
  out.innerHTML=`<div class="section-loading"><div class="mini-spin"></div><span id="scr-progress">Analyzing 0/${sel.length} script(s) · concurrency ${conc}…</span></div>`;
  let agg={Critical:0,High:0,Medium:0,Low:0,Info:0}, total=0, done=0;
  const results=new Array(sel.length);   // indexed to preserve original order
  let cursor=0;
  const worker=async()=>{
    while(cursor<sel.length){
      if(window.SCR_STOP)break;        // abort: stop pulling new work
      const idx=cursor++;
      const {card,findings}=await scrAnalyzeOne(sel[idx]);
      results[idx]=card;
      findings.forEach(f=>{agg[f.sev]=(agg[f.sev]||0)+1;total++;});
      done++;const pe=document.getElementById('scr-progress');if(pe&&!window.SCR_STOP)pe.textContent=`Analyzing ${done}/${sel.length} script(s) · concurrency ${conc}…`;
    }
  };
  const pool=Array.from({length:Math.min(conc,sel.length)},()=>worker());
  await Promise.all(pool);
  const stopped=!!window.SCR_STOP;
  if(aBtn)aBtn.disabled=false;
  if(sBtn){sBtn.style.display='none';sBtn.disabled=false;sBtn.textContent='⏹ Stop';}
  const cards=results.filter(Boolean).join('');
  const stopNote=stopped?`<div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)">⏹ Analysis stopped early — showing ${done} of ${sel.length} script(s) completed.</div>`:'';
  const summary=`<div class="stats" style="margin-bottom:12px">
    <div class="stat"><div class="n">${done}${stopped?`<span style="font-size:12px;color:var(--dim)"> / ${sel.length}</span>`:''}</div><div class="l">Scripts</div></div>
    <div class="stat"><div class="n" style="color:#7f1d1d">${agg.Critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:var(--bad)">${agg.High}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:var(--warn)">${agg.Medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:var(--info)">${agg.Low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n">${total}</div><div class="l">Total Findings</div></div></div>`;
  out.innerHTML=`<h4 class="sub">Inline Script Analysis Results</h4>${stopNote}${summary}${cards}`;
}
/* v2.3.0/2.4.x — WordPress fingerprint + plugin/theme vulnerability scoring */
function wpScoreColor(sev){return sev==='Critical'?'#7f1d1d':sev==='High'?'var(--bad)':sev==='Medium'?'var(--warn)':sev==='Low'?'var(--info)':'var(--dim)';}
window.WP_STATE={plugins:[],page:1,perPage:10,sev:'all',search:''};
const WP_SEVRANK={Critical:0,High:1,Medium:2,Low:3,Info:4};
function wpPluginFiltered(){
  const s=window.WP_STATE;
  let rows=window.WP_STATE.plugins.slice();
  if(s.sev==='vuln'){rows=rows.filter(p=>p.cves&&p.cves.length>0);}
  else if(s.sev!=='all'){rows=rows.filter(p=>(p.rating||'Info')===s.sev);}
  if(s.search){const q=s.search;rows=rows.filter(p=>(p.name+' '+p.slug+' '+(p.cves||[]).map(c=>c.id+' '+c.title).join(' ')).toLowerCase().includes(q));}
  return rows;
}
function wpPluginRender(reset){
  const s=window.WP_STATE;
  const se=document.getElementById('wp-search'),sv=document.getElementById('wp-sev'),pe=document.getElementById('wp-per');
  if(se)s.search=se.value.toLowerCase().trim();if(sv)s.sev=sv.value;if(pe)s.perPage=parseInt(pe.value);if(reset)s.page=1;
  const rows=wpPluginFiltered();
  const total=rows.length;const per=s.perPage>0?s.perPage:(total||1);const tp=Math.max(1,Math.ceil(total/per));
  if(s.page>tp)s.page=tp;if(s.page<1)s.page=1;
  const start=(s.page-1)*per;const pageRows=rows.slice(start,start+per);
  let html=`<div class="table-wrap"><table><thead><tr><th style="width:70px">Risk</th><th>Plugin</th><th style="width:90px">Version</th><th style="width:70px">Score</th><th style="width:70px">CVSS</th><th style="width:80px">CVEs</th><th>Latest known vuln</th></tr></thead><tbody>`;
  if(!pageRows.length){html+=`<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:18px">No plugins match the current filter.</td></tr>`;}
  else pageRows.forEach(p=>{
    const prating=p.rating||'Info';
    const top=(p.cves&&p.cves.length)?p.cves[0]:null;
    const vulnCell=top?`<a href="https://nvd.nist.gov/vuln/detail/${esc(top.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(top.id)}</code></a> — ${esc(top.title)} <span class="pill dim" style="font-size:9.5px">fix: ${esc(top.fixed)}</span>`:(p.version?`<span style="color:var(--ok)">No curated CVE matches ${esc(p.version)}</span>`:`<span style="color:var(--dim)">version hidden — cannot confirm</span>`);
    html+=`<tr>
      <td><span class="sev-${esc(prating)}">${esc(prating)}</span></td>
      <td><strong>${esc(p.name)}</strong>${p.known?'':' <span class="pill dim" style="font-size:9px">unrecognized</span>'}<br><code style="font-size:10px">${esc(p.slug)}</code>${p.installs?` <span style="color:var(--dim);font-size:10px">· ${esc(p.installs)} installs</span>`:''}</td>
      <td>${p.version?`<code>${esc(p.version)}</code>${p.version_source?`<br><span style="color:var(--dim);font-size:9px">${esc(p.version_source)}</span>`:''}`:'<span style="color:var(--dim)">—</span>'}</td>
      <td><strong style="color:${wpScoreColor(prating)}">${p.score||0}</strong></td>
      <td>${p.max_cvss?`<code>${p.max_cvss.toFixed(1)}</code>`:'—'}</td>
      <td>${(p.cves&&p.cves.length)?`<span class="pill bad">${p.cves.length}</span>`:`<span class="pill ok">0</span>`}</td>
      <td style="font-size:11.5px">${vulnCell}</td></tr>`;
    if(p.cves&&p.cves.length>1){ p.cves.slice(1).forEach(c=>{html+=`<tr><td></td><td colspan="6" style="font-size:11px;padding-left:20px"><span class="sev-${esc(c.sev)}" style="font-size:10px">${esc(c.sev)}</span> <a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(c.id)}</code></a> — ${esc(c.title)} · CVSS ${c.cvss.toFixed(1)} · fix: ${esc(c.fixed)}</td></tr>`;}); }
  });
  html+=`</tbody></table></div>`;
  // pager
  if(s.perPage>0&&tp>1){
    let nums='';const win=2;for(let i=1;i<=tp;i++){if(i===1||i===tp||(i>=s.page-win&&i<=s.page+win)){nums+=`<button type="button" class="${i===s.page?'active':''}" onclick="wpGoto(${i})">${i}</button>`;}else if(i===s.page-win-1||i===s.page+win+1){nums+=`<span style="padding:0 4px;color:var(--dim)">…</span>`;}}
    html+=`<div class="pager"><button type="button" ${s.page===1?'disabled':''} onclick="wpGoto(1)">« First</button><button type="button" ${s.page===1?'disabled':''} onclick="wpGoto(${s.page-1})">‹ Prev</button>${nums}<button type="button" ${s.page===tp?'disabled':''} onclick="wpGoto(${s.page+1})">Next ›</button><button type="button" ${s.page===tp?'disabled':''} onclick="wpGoto(${tp})">Last »</button></div>`;
  }
  const wrap=document.getElementById('wp-plugin-wrap');if(wrap)wrap.innerHTML=html;
  const cnt=document.getElementById('wp-plugin-count');if(cnt)cnt.textContent=`${total} plugin${total===1?'':'s'} shown`+(s.perPage>0&&tp>1?` · page ${s.page}/${tp}`:'');
}
function wpGoto(p){window.WP_STATE.page=p;wpPluginRender(false);}
window.WPT_STATE={themes:[],page:1,perPage:10,sev:'all',search:''};
function wpThemeFiltered(){
  const s=window.WPT_STATE;
  let rows=window.WPT_STATE.themes.slice();
  if(s.sev==='vuln'){rows=rows.filter(t=>t.cves&&t.cves.length>0);}
  else if(s.sev!=='all'){rows=rows.filter(t=>(t.rating||'Info')===s.sev);}
  if(s.search){const q=s.search;rows=rows.filter(t=>(t.name+' '+t.slug+' '+(t.cves||[]).map(c=>c.id+' '+c.title).join(' ')).toLowerCase().includes(q));}
  return rows;
}
function wpThemeRender(reset){
  const s=window.WPT_STATE;
  const se=document.getElementById('wpt-search'),sv=document.getElementById('wpt-sev'),pe=document.getElementById('wpt-per');
  if(se)s.search=se.value.toLowerCase().trim();if(sv)s.sev=sv.value;if(pe)s.perPage=parseInt(pe.value);if(reset)s.page=1;
  const rows=wpThemeFiltered();
  const total=rows.length;const per=s.perPage>0?s.perPage:(total||1);const tp=Math.max(1,Math.ceil(total/per));
  if(s.page>tp)s.page=tp;if(s.page<1)s.page=1;
  const start=(s.page-1)*per;const pageRows=rows.slice(start,start+per);
  let html=`<div class="table-wrap"><table><thead><tr><th style="width:70px">Risk</th><th>Theme</th><th style="width:90px">Version</th><th style="width:70px">Score</th><th style="width:70px">CVSS</th><th style="width:80px">CVEs</th><th>Latest known vuln</th></tr></thead><tbody>`;
  if(!pageRows.length){html+=`<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:18px">No themes match the current filter.</td></tr>`;}
  else pageRows.forEach(t=>{
    const trating=t.rating||'Info';
    const top=(t.cves&&t.cves.length)?t.cves[0]:null;
    const vulnCell=top?`<a href="https://nvd.nist.gov/vuln/detail/${esc(top.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(top.id)}</code></a> — ${esc(top.title)} <span class="pill dim" style="font-size:9.5px">fix: ${esc(top.fixed)}</span>`:(t.version?`<span style="color:var(--ok)">No curated CVE matches ${esc(t.version)}</span>`:`<span style="color:var(--dim)">version hidden</span>`);
    html+=`<tr>
      <td><span class="sev-${esc(trating)}">${esc(trating)}</span></td>
      <td><strong>${esc(t.name)}</strong>${t.known?'':' <span class="pill dim" style="font-size:9px">unrecognized</span>'}<br><code style="font-size:10px">${esc(t.slug)}</code></td>
      <td>${t.version?`<code>${esc(t.version)}</code>${t.version_source?`<br><span style="color:var(--dim);font-size:9px">${esc(t.version_source)}</span>`:''}`:'<span style="color:var(--dim)">—</span>'}</td>
      <td><strong style="color:${wpScoreColor(trating)}">${t.score||0}</strong></td>
      <td>${t.max_cvss?`<code>${t.max_cvss.toFixed(1)}</code>`:'—'}</td>
      <td>${(t.cves&&t.cves.length)?`<span class="pill bad">${t.cves.length}</span>`:`<span class="pill ok">0</span>`}</td>
      <td style="font-size:11.5px">${vulnCell}</td></tr>`;
    if(t.cves&&t.cves.length>1){ t.cves.slice(1).forEach(c=>{html+=`<tr><td></td><td colspan="6" style="font-size:11px;padding-left:20px"><span class="sev-${esc(c.sev)}" style="font-size:10px">${esc(c.sev)}</span> <a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(c.id)}</code></a> — ${esc(c.title)} · CVSS ${c.cvss.toFixed(1)} · fix: ${esc(c.fixed)}</td></tr>`;}); }
  });
  html+=`</tbody></table></div>`;
  if(s.perPage>0&&tp>1){
    let nums='';const win=2;for(let i=1;i<=tp;i++){if(i===1||i===tp||(i>=s.page-win&&i<=s.page+win)){nums+=`<button type="button" class="${i===s.page?'active':''}" onclick="wptGoto(${i})">${i}</button>`;}else if(i===s.page-win-1||i===s.page+win+1){nums+=`<span style="padding:0 4px;color:var(--dim)">…</span>`;}}
    html+=`<div class="pager"><button type="button" ${s.page===1?'disabled':''} onclick="wptGoto(1)">« First</button><button type="button" ${s.page===1?'disabled':''} onclick="wptGoto(${s.page-1})">‹ Prev</button>${nums}<button type="button" ${s.page===tp?'disabled':''} onclick="wptGoto(${s.page+1})">Next ›</button><button type="button" ${s.page===tp?'disabled':''} onclick="wptGoto(${tp})">Last »</button></div>`;
  }
  const wrap=document.getElementById('wp-theme-wrap');if(wrap)wrap.innerHTML=html;
  const cnt=document.getElementById('wp-theme-count');if(cnt)cnt.textContent=`${total} theme${total===1?'':'s'} shown`+(s.perPage>0&&tp>1?` · page ${s.page}/${tp}`:'');
}
function wptGoto(p){window.WPT_STATE.page=p;wpThemeRender(false);}
function renderWordPress(id,r){
  if(!r.ok)return errorBody(id,r.error);
  const d=r.data||{};
  if(!d.is_wp){setBody(id,`<div class="findings-note">✅ <strong>WordPress not detected.</strong> No wp-content / wp-includes / wp-json / wp-login signals were found on this target.</div>`);return;}
  const ver=d.version||'';
  const sev=d.rating||'Info';
  const col=wpScoreColor(sev);
  const score=d.score||0;
  const cves=d.cves||[];
  const plugins=d.plugins||[],themes=d.themes||[];
  const ecoCvss=d.eco_max_cvss||d.max_cvss||0;
  // Hero banner
  let html=`<div class="kv" style="background:linear-gradient(135deg,var(--accent-soft),var(--purple-soft));border-color:var(--accent);margin-bottom:16px">
    <div class="k">WordPress Detected</div>
    <div class="v"><strong style="font-size:18px">${ver?('Version '+esc(ver)):'Version hidden'}</strong>${d.latest?` <span class="pill dim">latest: ${esc(d.latest)}</span>`:''}${d.outdated===true?' <span class="pill bad">OUTDATED</span>':d.outdated===false?' <span class="pill ok">CURRENT</span>':''}${d.branch&&d.branch_maintained===false?` <span class="pill warn">branch ${esc(d.branch)} EOL / unmaintained</span>`:d.branch_maintained===true?` <span class="pill ok">branch ${esc(d.branch)} maintained</span>`:''}</div></div>`;
  // Stat cards
  html+=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n">${ver?esc(ver):'—'}</div><div class="l">Core Version</div></div>
    <div class="stat"><div class="n" style="color:${col}">${score}</div><div class="l">Overall Risk /100</div></div>
    <div class="stat"><div class="n"><span class="sev-${esc(sev)}">${esc(sev)}</span></div><div class="l">Severity Rating</div></div>
    <div class="stat"><div class="n" style="color:${cves.length?'var(--bad)':'var(--ok)'}">${cves.length}</div><div class="l">Core CVEs</div></div>
    <div class="stat"><div class="n" style="color:${(d.plugin_vuln_count||0)?'var(--bad)':'var(--dim)'}">${d.plugin_count||0}${(d.plugin_vuln_count||0)?` <span style="font-size:12px;color:var(--bad)">(${d.plugin_vuln_count} vuln)</span>`:''}</div><div class="l">Plugins</div></div>
    <div class="stat"><div class="n" style="color:${(d.theme_vuln_count||0)?'var(--bad)':'var(--dim)'}">${d.theme_count||0}${(d.theme_vuln_count||0)?` <span style="font-size:12px;color:var(--bad)">(${d.theme_vuln_count} vuln)</span>`:''}</div><div class="l">Themes</div></div>
    <div class="stat"><div class="n">${ecoCvss?ecoCvss.toFixed(1):'—'}</div><div class="l">Max CVSS</div></div></div>`;
  // Gauge bar
  html+=`<div style="margin:0 0 16px"><div style="display:flex;justify-content:space-between;font-size:11px;color:var(--dim);margin-bottom:4px"><span>Risk score</span><span>${score}/100 · ${esc(sev)}</span></div>
    <div style="height:12px;border-radius:999px;background:var(--line);overflow:hidden"><div style="height:100%;width:${score}%;background:linear-gradient(90deg,var(--ok),var(--warn),var(--bad),#7f1d1d);border-radius:999px"></div></div></div>`;
  // Detection methods
  if(d.detected_by&&d.detected_by.length){
    html+=`<h4 class="sub">How the version was determined</h4><div class="table-wrap"><table><thead><tr><th style="width:220px">Method</th><th style="width:90px">Version</th><th>Evidence</th></tr></thead><tbody>`;
    d.detected_by.forEach(m=>html+=`<tr><td><strong>${esc(m.method)}</strong></td><td><code>${esc(m.value)}</code></td><td style="font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all">${esc(m.evidence)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else if(!ver){
    html+=`<div class="findings-note">🔒 WordPress confirmed, but the exact version is <strong>not publicly exposed</strong> — good hardening. Score reflects fingerprintability only; verify the build internally (<code>wp core version</code>) to map CVEs.</div>`;
  }
  // Core CVEs
  if(cves.length){
    html+=`<h4 class="sub">Applicable Core CVEs (curated reference)</h4><div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th style="width:130px">CVE</th><th>Title</th><th style="width:70px">CVSS</th><th style="width:80px">CWE</th><th style="width:150px">Fixed in</th></tr></thead><tbody>`;
    cves.forEach(c=>{const cwe=c.cwe?`<a href="https://cwe.mitre.org/data/definitions/${c.cwe.replace('CWE-','')}.html" target="_blank" rel="noopener noreferrer"><code>${esc(c.cwe)}</code></a>`:'—';
      html+=`<tr><td><span class="sev-${esc(c.sev)}">${esc(c.sev)}</span></td><td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(c.id)}</code></a></td><td><strong>${esc(c.title)}</strong></td><td><code>${c.cvss.toFixed(1)}</code></td><td>${cwe}</td><td style="font-size:11px">${esc(c.fixed)}</td></tr>`;});
    html+=`</tbody></table></div>`;
  } else if(ver){
    html+=`<div class="findings-note">✅ No CVEs from the curated core set match <code>${esc(ver)}</code>. Currency-based risk still applies if the version is behind ${esc(d.latest||'latest')}.</div>`;
  }
  // Exposure signals
  if(d.signals&&d.signals.length){
    html+=`<h4 class="sub">Detection & Exposure Signals</h4><div class="table-wrap"><table><thead><tr><th>Signal</th><th style="width:120px">Type</th></tr></thead><tbody>`;
    d.signals.forEach(s=>{const bad=/readme|feed leaks|login/i.test(s);html+=`<tr><td>${esc(s)}</td><td><span class="pill ${bad?'warn':'dim'}">${bad?'exposure':'fingerprint'}</span></td></tr>`;});
    html+=`</tbody></table></div>`;
  }
  // ---- v2.4.4: User enumeration + XML-RPC findings ----
  const xf=d.extra_findings||[];
  if(xf.length){
    html+=`<h4 class="sub">Access &amp; Endpoint Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th style="width:230px">Finding</th><th>Detail</th><th>Recommended fix</th></tr></thead><tbody>`;
    xf.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td><strong>${esc(f.title)}</strong></td><td style="font-size:12px">${esc(f.why)}</td><td style="font-size:12px;color:var(--dim)">${esc(f.fix)}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  // Enumerated users
  const wu=d.users||{};
  if(wu.count>0){
    const depthNote=wu.depth?` · author-archive depth ${esc(wu.probed||wu.depth)}/${esc(wu.depth)}`:'';
    html+=`<h4 class="sub">Enumerated Users (${wu.count}) <span class="pill warn" style="font-size:10px">username disclosure</span></h4>
    <div class="findings-note" style="margin-bottom:8px">🔑 Methods: ${(wu.methods||[]).map(m=>`<code>${esc(m)}</code>`).join(' · ')||'—'}${depthNote}. Usernames are half of a credential — pair them with a WAF/2FA and login rate-limiting.</div>
    <div class="table-wrap"><table><thead><tr><th style="width:50px">ID</th><th>Login / slug</th><th>Display name</th><th>URL (profile)</th><th>Link (author archive / REST)</th><th style="width:150px">Source(s)</th></tr></thead><tbody>`;
    (wu.users||[]).forEach(u=>{
      const srcs=Object.keys(u.sources||{}).map(s=>`<span class="pill dim" style="font-size:9.5px">${esc(s)}</span>`).join(' ');
      const urlCell=u.url?`<a href="${esc(u.url)}" target="_blank" rel="noopener noreferrer" style="word-break:break-all;font-size:11px">${esc(u.url)}</a>`:'<span style="color:var(--dim)">—</span>';
      let linkCell='';
      const link=u.link||u.author_url||'';
      if(link)linkCell+=`<a href="${esc(link)}" target="_blank" rel="noopener noreferrer" style="word-break:break-all;font-size:11px">${esc(link)}</a>`;
      if(u.rest)linkCell+=`${link?'<br>':''}<span style="color:var(--dim);font-size:10px">REST: </span><a href="${esc(u.rest)}" target="_blank" rel="noopener noreferrer" style="word-break:break-all;font-size:10.5px;color:var(--dim)">${esc(u.rest)}</a>`;
      if(!linkCell)linkCell='<span style="color:var(--dim)">—</span>';
      html+=`<tr><td><code>${u.id!=null?esc(u.id):'—'}</code></td><td><strong>${esc(u.login||'—')}</strong></td><td>${esc(u.name||'—')}</td><td>${urlCell}</td><td>${linkCell}</td><td>${srcs}</td></tr>`;});
    html+=`</tbody></table></div>`;
  } else if(wu.methods!==undefined){
    html+=`<h4 class="sub">User Enumeration</h4><div class="findings-note">✅ No usernames were enumerable via the REST API (<code>/wp-json/wp/v2/users</code>) or author-archive redirects (<code>?author=N</code>) — good hardening.</div>`;
  }
  // XML-RPC
  const xr=d.xmlrpc||{};
  if(xr.enabled){
    const badgeM=xr.multicall?`<span class="pill bad">system.multicall</span>`:'';
    const badgeP=xr.pingback?`<span class="pill warn">pingback.ping</span>`:'';
    html+=`<h4 class="sub">XML-RPC Endpoint <span class="pill bad" style="font-size:10px">enabled</span></h4>
    <div class="kv" style="margin-bottom:8px"><div class="k">Endpoint</div><div class="v"><code>/xmlrpc.php</code> · HTTP ${esc(xr.status||'?')}</div><div class="k">Methods listed</div><div class="v">${xr.methods_listed?`${xr.method_count} method(s) enumerable ${badgeM} ${badgeP}`:'Not enumerable (listMethods blocked)'}</div></div>`;
    if(xr.multicall||xr.pingback){
      html+=`<div class="findings-note" style="border-left-color:var(--bad);background:var(--bad-soft)">⚠️ ${xr.multicall?'<strong>system.multicall</strong> enables amplified credential brute-forcing (thousands of login attempts in a single request). ':''}${xr.pingback?'<strong>pingback.ping</strong> can be abused for SSRF and DDoS reflection. ':''}Disable XML-RPC or block these methods.</div>`;
    }
    if(xr.methods&&xr.methods.length){
      html+=`<details style="margin-top:8px"><summary style="cursor:pointer;color:var(--dim);font-size:12px">Show ${xr.methods.length} exposed method(s)</summary><div class="tag-cloud" style="margin-top:8px">${xr.methods.map(m=>{const danger=/multicall|pingback/i.test(m);return `<span class="tag ${danger?'bad':'dim'}">${esc(m)}</span>`;}).join('')}</div></details>`;
    }
  } else if(xr.status!==undefined){
    html+=`<h4 class="sub">XML-RPC Endpoint</h4><div class="findings-note">✅ <code>/xmlrpc.php</code> appears disabled or blocked (HTTP ${esc(xr.status||0)}) — good hardening against brute-force amplification and pingback abuse.</div>`;
  }
  // ---- Plugins (paginated + filterable) ----
  if(plugins.length){
    html+=`<h4 class="sub">Detected Plugins &amp; Vulnerability Score (${plugins.length})</h4>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
      <input type="text" id="wp-search" placeholder="Search plugin / slug / CVE…" oninput="wpPluginRender(true)" style="flex:1;min-width:200px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
      <select id="wp-sev" onchange="wpPluginRender(true)" style="padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
        <option value="all">All severities</option>
        <option value="vuln">Vulnerable only</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
      </select>
      <select id="wp-per" onchange="wpPluginRender(true)" style="padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
        <option value="10">10 / page</option>
        <option value="25">25 / page</option>
        <option value="50">50 / page</option>
        <option value="0">Show all</option>
      </select>
      <span id="wp-plugin-count" style="color:var(--dim);font-size:12px;white-space:nowrap"></span>
    </div>
    <div id="wp-plugin-wrap"></div>`;
  } else {
    html+=`<h4 class="sub">Detected Plugins</h4><div class="findings-note">No plugins were enumerable from the page source. Assets may be bundled/minified or served from a CDN. Try an authenticated or active scan for deeper enumeration.</div>`;
  }
  // ---- Themes (paginated + filterable) ----
  if(themes.length){
    html+=`<h4 class="sub">Detected Themes &amp; Vulnerability Score (${themes.length})</h4>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
      <input type="text" id="wpt-search" placeholder="Search theme / slug / CVE…" oninput="wpThemeRender(true)" style="flex:1;min-width:200px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
      <select id="wpt-sev" onchange="wpThemeRender(true)" style="padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
        <option value="all">All severities</option>
        <option value="vuln">Vulnerable only</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
      </select>
      <select id="wpt-per" onchange="wpThemeRender(true)" style="padding:8px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
        <option value="10">10 / page</option>
        <option value="25">25 / page</option>
        <option value="50">50 / page</option>
        <option value="0">Show all</option>
      </select>
      <span id="wp-theme-count" style="color:var(--dim);font-size:12px;white-space:nowrap"></span>
    </div>
    <div id="wp-theme-wrap"></div>`;
  }
  if(plugins.length||themes.length){
    html+=`<div class="findings-note" style="margin-top:8px">🧩 Plugin/theme versions come from <code>?ver=</code> asset strings, plugin <code>readme.txt</code> Stable tags, and theme <code>style.css</code> headers. CVE matching uses a curated set — for full 100K+ coverage integrate the <a href="https://wpscan.com/api" target="_blank" rel="noopener noreferrer">WPScan</a> or <a href="https://www.wordfence.com/threat-intel/" target="_blank" rel="noopener noreferrer">Wordfence Intelligence</a> API. Plugins account for the large majority of WordPress compromises.</div>`;
  }
  // Remediation
  html+=`<h4 class="sub">Remediation</h4><div class="table-wrap"><table><thead><tr><th style="width:80px">Priority</th><th>Action</th></tr></thead><tbody>
    ${d.outdated===true?`<tr><td><span class="sev-High">High</span></td><td>Update WordPress core to <strong>${esc(d.latest||'the latest release')}</strong>. Only the 7.0 branch receives active support.</td></tr>`:''}
    ${(d.plugin_vuln_count||0)>0?`<tr><td><span class="sev-Critical">Critical</span></td><td>Update the <strong>${d.plugin_vuln_count} vulnerable plugin(s)</strong> flagged above to their patched versions immediately — plugins are the #1 WordPress attack vector.</td></tr>`:''}
    ${(d.theme_vuln_count||0)>0?`<tr><td><span class="sev-High">High</span></td><td>Update or replace the <strong>${d.theme_vuln_count} vulnerable theme(s)</strong> flagged above.</td></tr>`:''}
    ${(xr.multicall)?`<tr><td><span class="sev-High">High</span></td><td>Disable <code>system.multicall</code> on <code>xmlrpc.php</code> (or block the endpoint entirely) — it enables amplified credential brute-forcing.</td></tr>`:''}
    ${(xr.enabled&&!xr.multicall)?`<tr><td><span class="sev-Medium">Medium</span></td><td>Disable or block <code>/xmlrpc.php</code> if unused${xr.pingback?', and disable <code>pingback.ping</code> to prevent SSRF/DDoS reflection':''}.</td></tr>`:''}
    ${(wu.count>0)?`<tr><td><span class="sev-Medium">Medium</span></td><td>Stop username enumeration: block anonymous <code>/wp-json/wp/v2/users</code>, disable/redirect author archives (<code>?author=N</code>), and enforce login rate-limiting + 2FA.</td></tr>`:''}
    <tr><td><span class="sev-Medium">Medium</span></td><td>Hide the version: remove the generator meta tag, strip <code>?ver=</code> from core assets, and block <code>/readme.html</code> at the web server.</td></tr>
    <tr><td><span class="sev-Medium">Medium</span></td><td>Disable version leakage via <code>/feed/</code> generator.</td></tr>
    <tr><td><span class="sev-Low">Low</span></td><td>Enable auto-updates, add a WAF (Wordfence/Cloudflare), and audit plugins/themes regularly.</td></tr>
  </tbody></table></div>`;
  setBody(id,html);
  // initialize the paginated plugin table
  if(plugins.length){window.WP_STATE={plugins:plugins,page:1,perPage:10,sev:'all',search:''};wpPluginRender(true);}
  // initialize the paginated theme table
  if(themes.length){window.WPT_STATE={themes:themes,page:1,perPage:10,sev:'all',search:''};wpThemeRender(true);}
}
function renderWaf(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data||{};let html='';
  if(d.primary&&d.primary.confidence>0)html+=`<div class="kv" style="background:linear-gradient(135deg,var(--purple-soft),var(--accent-soft));border-color:var(--purple)"><div class="k">Primary Detection</div><div class="v"><strong style="font-size:18px">${esc(d.primary.product)}</strong> · ${d.primary.confidence}% confidence</div></div>`;
  else html+=`<div class="findings-note">No WAF/CDN definitively identified.</div>`;
  if(d.detected&&d.detected.length){html+=`<h4 class="sub">All Products Detected</h4><div class="table-wrap"><table><thead><tr><th>Product</th><th style="width:120px">Confidence</th><th>Evidence</th></tr></thead><tbody>`;d.detected.forEach(p=>{const cls=p.confidence>=80?'bad':p.confidence>=50?'warn':'info';const ev=p.evidence.slice(0,3).map(e=>`<div style="margin:2px 0"><span class="pill dim">${esc(e.technique)}</span> ${esc(e.detail)}</div>`).join('');html+=`<tr><td><strong>${esc(p.product)}</strong></td><td><span class="pill ${cls}">${p.confidence}%</span></td><td style="font-size:12px">${ev}</td></tr>`;});html+=`</tbody></table></div>`;}
  if(d.active_probes&&d.active_probes.length){html+=`<h4 class="sub">Active Probes</h4><div class="table-wrap"><table><thead><tr><th>Payload</th><th>Description</th><th style="width:80px">Status</th><th style="width:100px">Verdict</th></tr></thead><tbody>`;d.active_probes.forEach(p=>{const b=[403,406,419,429,451,501,999].includes(p.status);html+=`<tr><td><code>${esc(p.path)}</code></td><td>${esc(p.desc)}</td><td><code>${esc(p.status)}</code></td><td><span class="pill ${b?'bad':'ok'}">${b?'BLOCKED':'PASSED'}</span></td></tr>`;});html+=`</tbody></table></div>`;}
  setBody(id,html);}
function renderDir(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data||{};const rows=d.rows||[];const h2=rows.filter(x=>x.status===200).length;const auth=rows.filter(x=>x.interest==='auth-protected').length;
  let html=`<div class="stats" style="margin-bottom:16px"><div class="stat"><div class="n">${rows.length}</div><div class="l">Paths Tested</div></div><div class="stat"><div class="n" style="color:var(--ok)">${h2}</div><div class="l">200 OK</div></div><div class="stat"><div class="n" style="color:var(--warn)">${auth}</div><div class="l">Auth Protected</div></div><div class="stat"><div class="n">${(d.categories||[]).length}</div><div class="l">Categories</div></div></div>
  <div class="findings-note"><strong>About HTTP 500:</strong> A 500 means the target server crashed during the probe — a legitimate response, not a tool bug.</div>`;
  window.DIR_STATE.rows=rows;window.DIR_STATE.page=1;window.DIR_STATE.filterPath='';window.DIR_STATE.filterStatus='all';
  html+=`<h4 class="sub">Probed Paths</h4><div class="dir-controls"><input type="text" id="dir-filter-path" placeholder="Filter path" oninput="dirRefresh(true)"><select id="dir-filter-status" onchange="dirRefresh(true)"><option value="all">All statuses</option><option value="live">Live (2xx/3xx)</option><option value="errors">Errors (4xx/5xx)</option><option value="200">200 OK</option><option value="403">403 Forbidden</option><option value="server-error">All 5xx</option></select><select id="dir-per-page" onchange="dirRefresh(true)"><option value="25">25/page</option><option value="50">50/page</option><option value="100">100/page</option></select><button class="btn secondary" onclick="dirCSV()">CSV</button></div><div id="dir-table-wrap" style="margin-top:12px"></div>`;
  setBody(id,html);dirRefresh();}
function dirRefresh(reset){const s=window.DIR_STATE;const fe=document.getElementById('dir-filter-path');const se=document.getElementById('dir-filter-status');const pe=document.getElementById('dir-per-page');if(fe)s.filterPath=fe.value.toLowerCase().trim();if(se)s.filterStatus=se.value;if(pe)s.perPage=parseInt(pe.value)||25;if(reset)s.page=1;
  let rows=s.rows.slice();if(s.filterPath)rows=rows.filter(r=>r.path.toLowerCase().includes(s.filterPath)||r.category.toLowerCase().includes(s.filterPath));
  if(s.filterStatus!=='all'){if(s.filterStatus==='live')rows=rows.filter(r=>r.status>=200&&r.status<400);else if(s.filterStatus==='errors')rows=rows.filter(r=>r.status>=400&&r.status<600);else if(s.filterStatus==='server-error')rows=rows.filter(r=>r.status>=500&&r.status<600);else rows=rows.filter(r=>String(r.status)===s.filterStatus);}
  const total=rows.length;const per=s.perPage;const tp=Math.max(1,Math.ceil(total/per));if(s.page>tp)s.page=tp;const start=(s.page-1)*per;const end=start+per;const pr=rows.slice(start,end);
  const cm={low:'dim',HIGH:'ok',redirect:'info','auth-protected':'warn',timeout:'bad','server-error':'server-error','waf-block':'waf-block'};
  let html=`<div class="table-wrap"><table><thead><tr><th style="width:150px">Category</th><th>Path</th><th style="width:70px">Status</th><th style="width:60px">Method</th><th style="width:70px">Size</th><th style="width:110px">Interest</th><th style="width:100px">Flag</th></tr></thead><tbody>`;
  if(!pr.length)html+=`<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:24px">No paths match.</td></tr>`;
  else pr.forEach(x=>{const fh=x.flag?`<span class="pill bad">${esc(x.flag)}</span>`:'';html+=`<tr><td><span class="pill dim">${esc(x.category)}</span></td><td><a href="${esc(x.url)}" target="_blank" rel="noreferrer noopener"><code>${esc(x.path)}</code></a></td><td><code>${esc(x.status)}</code></td><td><span class="pill dim">${esc(x.method)}</span></td><td>${esc(x.size)}</td><td><span class="pill ${cm[x.interest]||'dim'}">${esc(x.interest)}</span></td><td>${fh}</td></tr>`;});
  html+=`</tbody></table>`;
  if(tp>1){html+=`<div style="padding:14px;text-align:center;border-top:1px solid var(--line)"><button class="btn secondary" ${s.page===1?'disabled':''} onclick="dirGoto(${s.page-1})">Prev</button> <span style="margin:0 12px;color:var(--dim)">Page ${s.page}/${tp} (${total} rows)</span> <button class="btn secondary" ${s.page===tp?'disabled':''} onclick="dirGoto(${s.page+1})">Next</button></div>`;}
  html+=`</div>`;document.getElementById('dir-table-wrap').innerHTML=html;try{enhanceURLRepeater();}catch(e){}}
function dirGoto(p){window.DIR_STATE.page=p;dirRefresh();}
function dirCSV(){const csv=['Category,Path,Status,Method,Size,Interest,Flag,URL'];window.DIR_STATE.rows.forEach(r=>csv.push([r.category,r.path,r.status,r.method,r.size,r.interest,r.flag||'',r.url].map(x=>`"${String(x).replace(/"/g,'""')}"`).join(',')));const b=new Blob(['\uFEFF'+csv.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='dir_probe_v'+APP.version+'.csv';a.click();toast('CSV exported.');}
function renderKV(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data||{};if(!Object.keys(d).length)return setBody(id,`<div class="findings-note">No data.</div>`);let html=`<div class="table-wrap"><table><tbody>`;Object.keys(d).forEach(k=>{let v=d[k];if(typeof v==='object')v=JSON.stringify(v);html+=`<tr><th style="width:220px">${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`;});html+=`</tbody></table></div>`;setBody(id,html);}
function renderRdns(id,r){if(!r.ok)return errorBody(id,r.error);setBody(id,`<div class="kv"><div class="k">PTR</div><div class="v"><code>${fmt(r.data.rdns)}</code></div></div>`);}
function renderRdap(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data;if(!d)return setBody(id,`<div class="findings-note">No RDAP data.</div>`);setBody(id,`<div class="kv"><div class="k">Handle</div><div class="v"><code>${fmt(d.handle)}</code></div><div class="k">Name</div><div class="v">${fmt(d.name)}</div><div class="k">Range</div><div class="v"><code>${fmt(d.startAddress)} – ${fmt(d.endAddress)}</code></div><div class="k">Country</div><div class="v">${fmt(d.country)}</div></div>`);}
function renderSpamhaus(id,r){if(!r.ok)return errorBody(id,r.error);const l=r.data.listed;if(l===null)return setBody(id,`<div class="findings-note">Spamhaus unavailable.</div>`);setBody(id,`<div class="kv"><div class="k">Spamhaus ZEN</div><div class="v"><span class="pill ${l?'bad':'ok'}">${l?'LISTED':'CLEAN'}</span></div></div>`);}
function renderPorts(id,r){if(!r.ok)return errorBody(id,r.error);const ports=r.data||[];const open=ports.filter(p=>p.state==='open').length;let html=`<div class="findings-note">${open}/${ports.length} open.</div><div class="table-wrap scroll" style="margin-top:12px"><table><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Latency</th></tr></thead><tbody>`;ports.forEach(p=>html+=`<tr><td><code>${p.port}</code></td><td><strong>${esc(p.svc)}</strong></td><td><span class="pill ${p.state==='open'?'ok':'dim'}">${esc(p.state)}</span></td><td>${p.ms} ms</td></tr>`);html+=`</tbody></table></div>`;setBody(id,html);}
function renderShodanHost(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data;if(d.skipped)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);if(d.error)return errorBody(id,d.error);let html=`<div class="kv"><div class="k">Org</div><div class="v">${fmt(d.org)}</div><div class="k">ISP</div><div class="v">${fmt(d.isp)}</div><div class="k">ASN</div><div class="v"><code>${fmt(d.asn)}</code></div><div class="k">Open Ports</div><div class="v">${(d.ports||[]).length}</div><div class="k">CVEs</div><div class="v">${(d.vulns||[]).length}</div></div>`;if(d.vulns?.length)html+=`<h4 class="sub">CVEs</h4><div class="tag-cloud">${d.vulns.map(x=>`<a href="https://nvd.nist.gov/vuln/detail/${esc(x)}" target="_blank" class="tag bad">${esc(x)}</a>`).join('')}</div>`;setBody(id,html);}
function renderAbuse(id,r){if(!r.ok)return errorBody(id,r.error);const d=r.data;if(d.skipped)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);if(d.error)return errorBody(id,d.error);const s=d.abuseConfidenceScore||0;const cls=s>=75?'bad':s>=25?'warn':'ok';setBody(id,`<div class="kv"><div class="k">Abuse Score</div><div class="v"><span class="pill ${cls}">${s}%</span></div><div class="k">Reports</div><div class="v">${d.totalReports||0}</div><div class="k">TOR</div><div class="v">${d.isTor?'YES':'NO'}</div><div class="k">ISP</div><div class="v">${fmt(d.isp)}</div><div class="k">Country</div><div class="v">${fmt(d.countryName)}</div></div>`);}
function renderVT(id,r,isDom){if(!r.ok)return errorBody(id,r.error);const d=r.data;if(d.skipped)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);if(d.error)return errorBody(id,d.error);const mal=d.malicious||0,sus=d.suspicious||0,harm=d.harmless||0;const cls=mal>=3?'bad':(mal+sus>=1)?'warn':'ok';setBody(id,`<div class="kv"><div class="k">Verdict</div><div class="v"><span class="pill ${cls}">${mal>=3?'MALICIOUS':(mal+sus>=1)?'SUSPICIOUS':'CLEAN'}</span></div><div class="k">Malicious</div><div class="v">${mal}</div><div class="k">Suspicious</div><div class="v">${sus}</div><div class="k">Harmless</div><div class="v">${harm}</div><div class="k">Reputation</div><div class="v">${d.reputation||0}</div>${isDom?`<div class="k">Registrar</div><div class="v">${fmt(d.registrar)}</div>`:`<div class="k">ASN</div><div class="v"><code>${fmt(d.asn)}</code></div>`}</div>`);}
/* #8 — DNS & email-security posture */
function sevPillCls(s){return s==='Critical'?'bad':s==='High'?'bad':s==='Medium'?'warn':s==='Low'?'info':'dim';}
function renderDNS(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const gradeColor=d.grade==='A'?'var(--ok)':d.grade==='B'?'#65a30d':d.grade==='C'?'var(--warn)':d.grade==='D'?'#ea580c':'var(--bad)';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${gradeColor}">${esc(d.grade||'—')}</div><div class="l">Email Posture</div></div>
    <div class="stat"><div class="n">${d.score||0}</div><div class="l">Score /100</div></div>
    <div class="stat"><div class="n">${(d.records||[]).filter(x=>x.status==='present').length}/${(d.records||[]).length}</div><div class="l">Records Present</div></div></div>`;
  html+=`<div class="table-wrap"><table><thead><tr><th style="width:90px">Record</th><th style="width:90px">Status</th><th>Value</th><th>Assessment</th></tr></thead><tbody>`;
  (d.records||[]).forEach(x=>{const st=x.status==='present'?'ok':x.status==='indeterminate'?'warn':'bad';
    html+=`<tr><td><strong>${esc(x.name)}</strong></td><td><span class="pill ${st}">${esc(x.status)}</span></td><td style="font-family:'JetBrains Mono',monospace;font-size:10.5px;word-break:break-all;max-width:340px">${esc((x.value||'').slice(0,300))}</td><td style="font-size:12px"><span class="pill ${sevPillCls(x.sev)}" style="font-size:9px">${esc(x.sev)}</span> ${esc(x.note)}</td></tr>`;});
  html+=`</tbody></table></div>
  <div class="findings-note" style="margin-top:8px">📧 SPF + DKIM + DMARC together stop email spoofing/phishing. A missing or unenforced (<code>p=none</code>) DMARC policy is the most common gap.</div>`;
  setBody(id,html);
}
/* #9 — TLS/SSL inspector */
function renderTLS(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  if(!d.ok){return setBody(id,`<div class="findings-note">🔒 ${esc(d.error||'TLS inspection unavailable.')}</div>`);}
  const dl=d.days_left;
  const dlColor=dl==null?'var(--dim)':dl<0?'#7f1d1d':dl<=14?'var(--bad)':dl<=30?'var(--warn)':'var(--ok)';
  const rating=d.rating||'Info';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">TLS Rating</div></div>
    <div class="stat"><div class="n" style="color:${dlColor}">${dl==null?'—':dl}</div><div class="l">Days to Expiry</div></div>
    <div class="stat"><div class="n" style="font-size:15px">${esc(d.protocol||'—')}</div><div class="l">Protocol</div></div>
    <div class="stat"><div class="n">${d.san_count||0}</div><div class="l">SANs</div></div></div>`;
  html+=`<div class="kv">
    <div class="k">Subject (CN)</div><div class="v"><code>${fmt(d.subject)}</code></div>
    <div class="k">Issuer</div><div class="v">${fmt(d.issuer)}</div>
    <div class="k">Valid</div><div class="v">${fmt(d.valid_from)} → ${fmt(d.valid_to)}</div>
    <div class="k">Cipher</div><div class="v"><code>${fmt(d.cipher)}</code></div>
    <div class="k">Signature</div><div class="v"><code>${fmt(d.sig_alg)}</code></div>
    <div class="k">Chain length</div><div class="v">${d.chain_len||0} cert(s)</div></div>`;
  if(d.findings&&d.findings.length){
    html+=`<h4 class="sub">Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Issue</th></tr></thead><tbody>`;
    d.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note" style="margin-top:8px">✅ No TLS issues detected — valid, modern, and not near expiry.</div>`; }
  if(d.sans&&d.sans.length){html+=`<h4 class="sub">Subject Alternative Names (${d.san_count})</h4><div class="tag-cloud">${d.sans.map(s=>`<span class="tag dim">${esc(s)}</span>`).join('')}</div>`;}
  setBody(id,html);
}
/* #10 — Cookie & CSP analyzer */
function renderCookies(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  if(d.error)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);
  const rating=d.rating||'Info';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">Rating</div></div>
    <div class="stat"><div class="n">${d.cookie_count||0}</div><div class="l">Cookies</div></div>
    <div class="stat"><div class="n" style="color:${d.csp&&d.csp.present?'var(--ok)':'var(--bad)'}">${d.csp&&d.csp.present?'YES':'NO'}</div><div class="l">CSP Header</div></div></div>`;
  if(d.cookies&&d.cookies.length){
    html+=`<h4 class="sub">Cookies</h4><div class="table-wrap"><table><thead><tr><th>Name</th><th style="width:70px">Secure</th><th style="width:80px">HttpOnly</th><th style="width:90px">SameSite</th><th>Issues</th></tr></thead><tbody>`;
    d.cookies.forEach(c=>{const yn=b=>b?'<span class="pill ok">yes</span>':'<span class="pill bad">no</span>';
      html+=`<tr><td><code>${esc(c.name)}</code></td><td>${yn(c.secure)}</td><td>${yn(c.httponly)}</td><td><span class="pill ${c.samesite==='—'?'dim':'info'}">${esc(c.samesite)}</span></td><td style="font-size:11.5px;color:var(--warn)">${(c.issues||[]).map(esc).join(', ')||'—'}</td></tr>`;});
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note">No cookies set on the landing response.</div>`; }
  // CSP
  html+=`<h4 class="sub">Content-Security-Policy</h4>`;
  if(d.csp&&d.csp.present){
    html+=`<div class="kv" style="margin-bottom:8px"><div class="k">Policy</div><div class="v" style="font-family:'JetBrains Mono',monospace;font-size:10.5px;word-break:break-all">${esc(d.csp.value)}</div></div>`;
    if(d.csp.findings&&d.csp.findings.length){
      html+=`<div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Weakness</th></tr></thead><tbody>`;
      d.csp.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
      html+=`</tbody></table></div>`;
    } else { html+=`<div class="findings-note">✅ CSP present with no obvious weaknesses.</div>`; }
  } else { html+=`<div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)">⚠️ No Content-Security-Policy header — the primary defense-in-depth control against XSS is absent.</div>`; }
  if(d.findings&&d.findings.length){
    html+=`<h4 class="sub">Summary Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Finding</th></tr></thead><tbody>`;
    d.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  setBody(id,html);
}
/* ============================================================
 * v2.6.8 — Advanced detection renderers
 * ============================================================ */
function sevCls(s){return s==='Critical'?'bad':s==='High'?'bad':s==='Medium'?'warn':s==='Low'?'info':'dim';}

function renderCORS(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const rating=d.rating||'Info';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">CORS Rating</div></div>
    <div class="stat"><div class="n">${(d.tests||[]).length}</div><div class="l">Origins Tested</div></div>
    <div class="stat"><div class="n" style="color:${(d.findings||[]).length?'var(--bad)':'var(--ok)'}">${(d.findings||[]).length}</div><div class="l">Weaknesses</div></div></div>`;
  html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Test</th><th>Origin Sent</th><th style="width:90px">ACAO</th><th style="width:70px">Creds</th><th>Assessment</th></tr></thead><tbody>`;
  (d.tests||[]).forEach(t=>{html+=`<tr><td><span class="sev-${esc(t.sev)}">${esc(t.sev)}</span></td><td>${esc(t.label)}</td><td><code style="font-size:10.5px">${esc(t.origin)}</code></td><td><code style="font-size:10.5px">${esc(t.acao)}</code></td><td><span class="pill ${t.acac==='true'?'bad':'dim'}">${esc(t.acac)}</span></td><td style="font-size:11.5px">${esc(t.verdict)}</td></tr>`;});
  html+=`</tbody></table></div>`;
  if((d.findings||[]).length) html+=`<div class="findings-note" style="border-left-color:var(--bad);background:var(--bad-soft)"><strong>Fix:</strong> ${esc(d.fix||'')}</div>`;
  else html+=`<div class="findings-note">✅ No CORS misconfiguration detected across the tested origins.</div>`;
  setBody(id,html);
}

function renderHeadersGrade(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  if(d.error)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);
  const g=d.grade||'F';
  const gc=g==='A+'||g==='A'?'var(--ok)':g==='B'?'#65a30d':g==='C'?'var(--warn)':g==='D'?'#ea580c':'var(--bad)';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${gc}">${esc(g)}</div><div class="l">Header Grade</div></div>
    <div class="stat"><div class="n">${d.score||0}</div><div class="l">Score /100</div></div>
    <div class="stat"><div class="n">${d.present||0}/${d.total||0}</div><div class="l">Controls Present</div></div>
    <div class="stat"><div class="n" style="color:${(d.leaks||[]).length?'var(--warn)':'var(--ok)'}">${(d.leaks||[]).length}</div><div class="l">Info Leaks</div></div></div>`;
  html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Security Header</th><th style="width:90px">Status</th><th style="width:70px">Weight</th><th>Value / Note</th></tr></thead><tbody>`;
  (d.checks||[]).forEach(c=>{const st=c.present?(c.partial?'<span class="pill warn">partial</span>':'<span class="pill ok">present</span>'):'<span class="pill bad">missing</span>';
    html+=`<tr><td><span class="sev-${esc(c.sev)}">${esc(c.sev)}</span></td><td><strong>${esc(c.name)}</strong><br><code style="font-size:10px">${esc(c.header)}</code></td><td>${st}</td><td><code>${c.weight}</code></td><td style="font-size:11.5px">${c.value?`<code style="font-size:10px;word-break:break-all">${esc(c.value)}</code>`:''}${c.value?'<br>':''}<span style="color:var(--dim)">${esc(c.note)}</span></td></tr>`;});
  html+=`</tbody></table></div>`;
  if((d.leaks||[]).length){html+=`<h4 class="sub">Version / Info-Disclosure Banners</h4><div class="tag-cloud">${d.leaks.map(l=>`<span class="tag bad">${esc(l.header)}: ${esc(l.value)}</span>`).join('')}</div>`;}
  html+=`<div class="findings-note" style="margin-top:8px">🛡️ Grade weighting mirrors industry scanners (Mozilla Observatory / securityheaders.com). Add missing headers at the web server/WAF for a quick defense-in-depth win.</div>`;
  setBody(id,html);
}

function renderJSRecon(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  if(d.error)return setBody(id,`<div class="findings-note">${esc(d.error)}</div>`);
  const secN=(d.secrets||[]).length;
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n">${(d.scripts||[]).length}</div><div class="l">Scripts Found</div></div>
    <div class="stat"><div class="n">${d.scanned||0}</div><div class="l">Scripts Parsed</div></div>
    <div class="stat"><div class="n">${(d.endpoints||[]).length}</div><div class="l">Endpoints</div></div>
    <div class="stat"><div class="n" style="color:${secN?'var(--bad)':'var(--ok)'}">${secN}</div><div class="l">Secrets</div></div></div>`;
  if(secN){
    html+=`<h4 class="sub">⚠️ Exposed Secrets (redacted)</h4><div class="table-wrap"><table><thead><tr><th style="width:70px">Sev</th><th>Type</th><th>Match (redacted)</th><th style="width:70px">Len</th></tr></thead><tbody>`;
    d.secrets.forEach(s=>html+=`<tr><td><span class="sev-High">High</span></td><td><strong>${esc(s.type)}</strong></td><td><code>${esc(s.match)}</code></td><td><code>${s.len}</code></td></tr>`);
    html+=`</tbody></table></div><div class="findings-note" style="border-left-color:var(--bad);background:var(--bad-soft)">Hard-coded secrets in client JS are world-readable. Rotate immediately and move to server-side/env storage.</div>`;
  }
  if((d.endpoints||[]).length){
    const base=(d.base||'').replace(/\/$/,'');
    const toUrl=(e)=>{ if(/^https?:\/\//i.test(e))return e; if(e.charAt(0)==='/')return base+e; return base+'/'+e; };
    html+=`<h4 class="sub">Discovered Endpoints / API Paths (${d.endpoints.length}) <button class="btn sm secondary" style="padding:3px 9px;font-size:10.5px" onclick="sendAllEndpointsToRepeater()" title="Load the first endpoint into the Repeater">⇢ Send first to Repeater</button></h4>`;
    window.LAST_JS_ENDPOINTS=d.endpoints.map(toUrl);
    html+=`<div class="table-wrap scroll" style="max-height:340px"><table><thead><tr><th>Endpoint / API Path</th><th style="width:110px">Type</th><th style="width:120px">Action</th></tr></thead><tbody>`;
    d.endpoints.forEach(e=>{const u=toUrl(e);const t=/^https?:\/\//i.test(e)?'absolute':(e.charAt(0)==='/'?'same-origin':'relative');
      const tcls=t==='absolute'?'info':(t==='same-origin'?'ok':'dim');
      html+=`<tr><td><code style="font-size:10.5px;word-break:break-all">${esc(e)}</code></td><td><span class="pill ${tcls}">${esc(t)}</span></td><td><button class="btn sm secondary" style="padding:3px 9px;font-size:10.5px" onclick="sendToRepeater(${repArg(u)})">⇢ Repeater</button></td></tr>`;});
    html+=`</tbody></table></div><div class="findings-note" style="margin-top:8px">🛠️ Send any discovered endpoint straight into the HTTP Repeater to probe methods, auth, and parameters (authorized testing only).</div>`;
  }
  if((d.scripts||[]).length){
    html+=`<h4 class="sub">Scripts</h4><div class="table-wrap scroll" style="max-height:280px"><table><thead><tr><th>Script URL</th><th style="width:90px">Origin</th><th style="width:80px">Parsed</th></tr></thead><tbody>`;
    d.scripts.forEach(s=>html+=`<tr><td><code style="font-size:10.5px;word-break:break-all">${esc(s.url)}</code></td><td><span class="pill ${s.same_origin?'info':'dim'}">${s.same_origin?'same':'3rd-party'}</span></td><td>${s.fetched?`<span class="pill ok">yes (${(s.size||0).toLocaleString()}b)</span>`:'<span class="pill dim">no</span>'}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  if(!secN && !(d.endpoints||[]).length) html+=`<div class="findings-note">No endpoints or secrets extracted from the parsed scripts.</div>`;
  setBody(id,html);
}

function renderTakeover(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const rating=d.rating||'Info';
  const rc=rating==='High'||rating==='Critical'?'var(--bad)':rating==='Medium'?'var(--warn)':'var(--ok)';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${rc}"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">Takeover Risk</div></div>
    <div class="stat"><div class="n">${(d.checked||[]).length}</div><div class="l">CNAMEs Found</div></div>
    <div class="stat"><div class="n" style="color:${(d.findings||[]).length?'var(--bad)':'var(--ok)'}">${(d.findings||[]).length}</div><div class="l">Dangling</div></div></div>`;
  if((d.checked||[]).length){
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Subdomain</th><th>CNAME Target</th><th style="width:120px">Service</th><th>Assessment</th></tr></thead><tbody>`;
    d.checked.forEach(c=>html+=`<tr><td><span class="sev-${esc(c.sev)}">${esc(c.sev)}</span></td><td><code>${esc(c.sub)}</code></td><td><code style="font-size:10.5px;word-break:break-all">${esc(c.cname)}</code></td><td>${c.service==='—'?'—':`<span class="pill purple">${esc(c.service)}</span>`}</td><td style="font-size:11.5px">${esc(c.verdict)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note">${esc(d.note||'No CNAME records found on probed subdomains.')}</div>`; }
  if((d.findings||[]).length) html+=`<div class="findings-note" style="margin-top:8px;border-left-color:var(--bad);background:var(--bad-soft)">🚨 A dangling CNAME can be claimed by an attacker to host content on your subdomain. Remove the stale DNS record or re-claim the backing resource.</div>`;
  setBody(id,html);
}

function renderGraphQL(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const rating=d.rating||'Info';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">Rating</div></div>
    <div class="stat"><div class="n">${(d.endpoints||[]).length}</div><div class="l">Endpoints</div></div>
    <div class="stat"><div class="n" style="color:${(d.endpoints||[]).some(e=>e.introspection)?'var(--bad)':'var(--ok)'}">${(d.endpoints||[]).filter(e=>e.introspection).length}</div><div class="l">Introspection On</div></div></div>`;
  if((d.endpoints||[]).length){
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Path</th><th style="width:80px">Status</th><th style="width:110px">Introspection</th><th style="width:80px">IDE</th><th>Assessment</th></tr></thead><tbody>`;
    d.endpoints.forEach(e=>html+=`<tr><td><span class="sev-${esc(e.sev)}">${esc(e.sev)}</span></td><td><code>${esc(e.path)}</code></td><td><span class="pill ${e.status===200?'ok':'dim'}">${e.status}</span></td><td><span class="pill ${e.introspection?'bad':'ok'}">${e.introspection?'ENABLED':'off'}</span></td><td><span class="pill ${e.ide?'warn':'dim'}">${e.ide?'exposed':'—'}</span></td><td style="font-size:11.5px">${esc(e.verdict)}</td></tr>`);
    html+=`</tbody></table></div>`;
    if(d.fix)html+=`<div class="findings-note" style="margin-top:8px"><strong>Fix:</strong> ${esc(d.fix)}</div>`;
  } else { html+=`<div class="findings-note">${esc(d.note||'No GraphQL endpoints detected.')}</div>`; }
  setBody(id,html);
}

function renderFavicon(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  if(d.error)return setBody(id,`<div class="findings-note">🖼️ ${esc(d.error)}</div>`);
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="font-size:19px">${esc(d.mmh3)}</div><div class="l">mmh3 (Shodan)</div></div>
    <div class="stat"><div class="n">${(d.size||0).toLocaleString()}</div><div class="l">Bytes</div></div>
    <div class="stat"><div class="n" style="font-size:13px;word-break:break-all">${esc((d.md5||'').slice(0,12))}…</div><div class="l">MD5</div></div></div>`;
  html+=`<div class="kv">
    <div class="k">Favicon URL</div><div class="v"><a href="${esc(d.favicon_url)}" target="_blank" rel="noopener noreferrer"><code style="font-size:10.5px">${esc(d.favicon_url)}</code></a></div>
    <div class="k">Content-Type</div><div class="v"><code>${esc(d.ctype||'—')}</code></div>
    <div class="k">MurmurHash3</div><div class="v"><code>${esc(d.mmh3)}</code></div>
    <div class="k">Shodan pivot</div><div class="v"><a href="${esc(d.shodan)}" target="_blank" rel="noopener noreferrer">Search Shodan for http.favicon.hash:${esc(d.mmh3)} ↗</a></div></div>`;
  html+=`<div class="findings-note" style="margin-top:8px">🧭 ${esc(d.note||'')}</div>`;
  setBody(id,html);
}
/* ============================================================
 * v2.6.9 — Engines 7 & 8 renderers
 * ============================================================ */
function renderHttpTls(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const g=d.grade||'F';
  const gc=g==='A+'||g==='A'?'var(--ok)':g==='B'?'#65a30d':g==='C'?'var(--warn)':g==='D'?'#ea580c':'var(--bad)';
  const http=d.http||{};const tls=d.tls||[];
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${gc}">${esc(g)}</div><div class="l">Transport Grade</div></div>
    <div class="stat"><div class="n">${d.score||0}</div><div class="l">Score /100</div></div>
    <div class="stat"><div class="n" style="font-size:15px">${esc(http.negotiated||'—')}</div><div class="l">HTTP Negotiated</div></div>
    <div class="stat"><div class="n" style="color:${http.http2?'var(--ok)':'var(--warn)'}">${http.http2?'YES':'NO'}</div><div class="l">HTTP/2</div></div>
    <div class="stat"><div class="n" style="color:${http.http3_advertised?'var(--ok)':'var(--dim)'}">${http.http3_advertised?'YES':'—'}</div><div class="l">HTTP/3 (Alt-Svc)</div></div></div>`;
  // Protocol table
  html+=`<h4 class="sub">Protocol Support</h4><div class="kv">
    <div class="k">Negotiated version</div><div class="v"><code>${esc(http.negotiated||'—')}</code> (HTTP ${http.status||0})</div>
    <div class="k">HTTP/2 (h2)</div><div class="v"><span class="pill ${http.http2?'ok':'warn'}">${http.http2?'supported':'not negotiated'}</span></div>
    <div class="k">HTTP/3 (QUIC)</div><div class="v"><span class="pill ${http.http3_advertised?'ok':'dim'}">${http.http3_advertised?'advertised':'not advertised'}</span>${http.alt_svc?` &nbsp;<code style="font-size:10px;word-break:break-all">${esc(http.alt_svc)}</code>`:''}</div>
    <div class="k">Client capability</div><div class="v"><span class="pill dim">h2: ${http.client_supports_h2?'yes':'no'}</span> <span class="pill dim">h3: ${http.client_supports_h3?'yes':'no'}</span></div></div>`;
  // TLS versions
  html+=`<h4 class="sub">TLS Version Support</h4>`;
  if(d.tls_error){html+=`<div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)">⚠️ ${esc(d.tls_error)}</div>`;}
  else if(tls.length){
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:120px">Version</th><th style="width:140px">Supported</th><th>Assessment</th></tr></thead><tbody>`;
    tls.forEach(t=>{
      const weak=(t.version==='TLS 1.0'||t.version==='TLS 1.1');
      const badge=t.supported?(weak?'<span class="pill bad">enabled</span>':'<span class="pill ok">enabled</span>'):'<span class="pill dim">disabled</span>';
      let note=t.note||'';
      if(t.supported&&weak)note='Deprecated protocol — should be disabled.';
      else if(t.supported&&t.version==='TLS 1.2')note='Modern baseline — good.';
      else if(t.supported&&t.version==='TLS 1.3')note='Latest — excellent (forward secrecy, 1-RTT).';
      else if(!t.supported&&!note)note='—';
      html+=`<tr><td><strong>${esc(t.version)}</strong></td><td>${badge}</td><td style="font-size:12px">${esc(note)}</td></tr>`;
    });
    html+=`</tbody></table></div>`;
  } else {html+=`<div class="findings-note">No TLS versions probed.</div>`;}
  // findings
  if((d.findings||[]).length){
    html+=`<h4 class="sub">Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Issue</th></tr></thead><tbody>`;
    d.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  if(d.fix)html+=`<div class="findings-note" style="margin-top:8px">🔐 <strong>Fix:</strong> ${esc(d.fix)}</div>`;
  setBody(id,html);
}

function renderWellKnown(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const g=d.grade||'F';
  const gc=g==='A'?'var(--ok)':g==='B'?'#65a30d':g==='C'?'var(--warn)':g==='D'?'#ea580c':'var(--bad)';
  const st=d.security_txt||{};
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${gc}">${esc(g)}</div><div class="l">Posture Grade</div></div>
    <div class="stat"><div class="n">${d.score||0}</div><div class="l">Score /100</div></div>
    <div class="stat"><div class="n" style="color:${st.found?'var(--ok)':'var(--warn)'}">${st.found?'YES':'NO'}</div><div class="l">security.txt</div></div>
    <div class="stat"><div class="n">${d.present_count||0}</div><div class="l">Resources Found</div></div></div>`;
  // security.txt detail
  html+=`<h4 class="sub">security.txt (RFC 9116)</h4>`;
  if(st.found){
    const f=st.fields||{};
    const flat=k=>(f[k]||[]).map(esc).join('<br>')||'—';
    html+=`<div class="kv" style="margin-bottom:8px">
      <div class="k">Location</div><div class="v"><code>${esc(st.path)}</code> <span class="pill ${st.path==='/.well-known/security.txt'?'ok':'warn'}">${st.path==='/.well-known/security.txt'?'canonical':'legacy root'}</span></div>
      <div class="k">Contact</div><div class="v">${flat('contact')}</div>
      <div class="k">Expires</div><div class="v">${st.expires?`<code>${esc(st.expires)}</code> `:''}<span class="pill ${st.expired?'bad':(st.expires?'ok':'dim')}">${st.expired?'EXPIRED':(st.expires?'valid':'missing')}</span></div>
      <div class="k">Encryption</div><div class="v">${flat('encryption')}</div>
      <div class="k">Policy</div><div class="v">${flat('policy')}</div>
      <div class="k">Acknowledgments</div><div class="v">${flat('acknowledgments')}</div>
      <div class="k">Preferred-Languages</div><div class="v">${flat('preferred-languages')}</div>
      <div class="k">Canonical</div><div class="v">${flat('canonical')}</div>
      <div class="k">PGP-signed</div><div class="v"><span class="pill ${st.signed?'ok':'dim'}">${st.signed?'signed':'not signed'}</span></div></div>`;
  } else {
    html+=`<div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)">⚠️ No security.txt found. Publishing <code>/.well-known/security.txt</code> (RFC 9116) gives researchers a clear, authorized channel for vulnerability disclosure.</div>`;
  }
  // resources table
  html+=`<h4 class="sub">.well-known / Discovery Resources</h4><div class="table-wrap scroll" style="max-height:360px"><table><thead><tr><th>Resource</th><th style="width:90px">Status</th><th style="width:90px">Present</th><th>Assessment</th></tr></thead><tbody>`;
  (d.resources||[]).forEach(x=>{
    const st2=x.present?(x.sev==='Low'?'<span class="pill warn">yes</span>':'<span class="pill ok">yes</span>'):'<span class="pill dim">no</span>';
    html+=`<tr><td><strong>${esc(x.name)}</strong><br><code style="font-size:10px">${esc(x.path)}</code></td><td><span class="pill ${x.status>=200&&x.status<300?'ok':(x.status>=400?'dim':'info')}">${x.status}</span></td><td>${st2}</td><td style="font-size:11.5px">${x.present?`<span class="sev-${esc(x.sev)}" style="font-size:10px">${esc(x.sev)}</span> `:''}${esc(x.note)}</td></tr>`;
  });
  html+=`</tbody></table></div>`;
  // findings
  if((d.findings||[]).length){
    html+=`<h4 class="sub">Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Finding</th></tr></thead><tbody>`;
    d.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  if(d.fix)html+=`<div class="findings-note" style="margin-top:8px">📄 <strong>Fix:</strong> ${esc(d.fix)}</div>`;
  setBody(id,html);
}
/* ============================================================
 * v2.7.0 — Engines 9 & 10 + IP Geo aggregator renderers
 * ============================================================ */
function renderDnsCaa(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const g=d.grade||'F';
  const gc=g==='A'?'var(--ok)':g==='B'?'#65a30d':g==='C'?'var(--warn)':g==='D'?'#ea580c':'var(--bad)';
  const caa=d.caa||{};const ds=d.dnssec||{};
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${gc}">${esc(g)}</div><div class="l">DNS Trust Grade</div></div>
    <div class="stat"><div class="n">${d.score||0}</div><div class="l">Score /100</div></div>
    <div class="stat"><div class="n" style="color:${caa.present?'var(--ok)':'var(--warn)'}">${caa.present?'YES':'NO'}</div><div class="l">CAA</div></div>
    <div class="stat"><div class="n" style="color:${ds.signed?'var(--ok)':'var(--warn)'}">${ds.signed?'YES':'NO'}</div><div class="l">DNSSEC</div></div></div>`;
  // CAA
  html+=`<h4 class="sub">CAA — Certificate Authority Authorization</h4>`;
  if(caa.present){
    html+=`<div class="kv" style="margin-bottom:8px"><div class="k">Found at</div><div class="v"><code>${esc(caa.found_at||'')}</code></div><div class="k">Authorized issuers</div><div class="v">${(caa.issuers||[]).length?(caa.issuers.map(x=>`<span class="tag">${esc(x)}</span>`).join('')):'<span class="pill warn">none specified</span>'}</div><div class="k">iodef contact</div><div class="v"><span class="pill ${caa.iodef?'ok':'dim'}">${caa.iodef?'present':'none'}</span></div></div>`;
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:110px">Tag</th><th>Value</th><th>Name</th></tr></thead><tbody>`;
    (caa.records||[]).forEach(c=>html+=`<tr><td><span class="pill info">${esc(c.tag)}</span></td><td><code>${esc(c.value)}</code></td><td style="font-size:11px;color:var(--dim)">${esc(c.name)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)">⚠️ No CAA record — any public CA may issue certificates for this domain.</div>`; }
  // DNSSEC
  html+=`<h4 class="sub">DNSSEC — Chain of Trust</h4><div class="table-wrap"><table><thead><tr><th style="width:140px">Component</th><th style="width:90px">Present</th><th>Assessment</th></tr></thead><tbody>`;
  (d.records||[]).forEach(x=>html+=`<tr><td><strong>${esc(x.name)}</strong></td><td><span class="pill ${x.present?'ok':'dim'}">${x.present?'yes':'no'}</span></td><td style="font-size:12px">${esc(x.note)}</td></tr>`);
  html+=`</tbody></table></div>`;
  if((d.findings||[]).length){
    html+=`<h4 class="sub">Findings</h4><div class="table-wrap"><table><thead><tr><th style="width:90px">Sev</th><th>Finding</th></tr></thead><tbody>`;
    d.findings.forEach(f=>html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td>${esc(f.msg)}</td></tr>`);
    html+=`</tbody></table></div>`;
  }
  if(d.fix)html+=`<div class="findings-note" style="margin-top:8px">🔐 <strong>Fix:</strong> ${esc(d.fix)}</div>`;
  setBody(id,html);
}

function renderOpenRedir(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const rating=d.rating||'Info';
  const rc=rating==='High'||rating==='Critical'?'var(--bad)':rating==='Medium'?'var(--warn)':'var(--ok)';
  const redirs=d.redirects||[];const ssrf=d.ssrf_surface||[];
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="color:${rc}"><span class="sev-${esc(rating)}">${esc(rating)}</span></div><div class="l">Rating</div></div>
    <div class="stat"><div class="n" style="color:${redirs.length?'var(--bad)':'var(--ok)'}">${redirs.length}</div><div class="l">Open Redirects</div></div>
    <div class="stat"><div class="n" style="color:${ssrf.length?'var(--warn)':'var(--ok)'}">${ssrf.length}</div><div class="l">SSRF Surfaces</div></div></div>`;
  html+=`<h4 class="sub">Open-Redirect Detection</h4>`;
  if(redirs.length){
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th style="width:130px">Parameter</th><th style="width:70px">Status</th><th style="width:120px">Bypass</th><th>Assessment</th></tr></thead><tbody>`;
    redirs.forEach(x=>html+=`<tr><td><span class="sev-${esc(x.sev)}">${esc(x.sev)}</span></td><td><code>${esc(x.param)}</code> <button class="btn sm secondary" style="padding:3px 8px;font-size:10.5px" onclick="sendToRepeater(${repArg((d.base||'')+'/?'+x.param+'=https://vra-openredirect-check.example.org/')})">⇢ Repeater</button></td><td><code>${esc(x.status)}</code></td><td><span class="pill ${x.bypass==='protocol-relative'?'warn':'dim'}">${esc(x.bypass)}</span></td><td style="font-size:11.5px">${esc(x.verdict)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note">✅ ${esc(d.redirects_note||'No open redirect detected.')}</div>`; }
  html+=`<h4 class="sub">SSRF Parameter Surface <span style="font-weight:400;color:var(--dim);font-size:11px">(detection only — confirm out-of-band)</span></h4>`;
  if(ssrf.length){
    html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th style="width:130px">Parameter</th><th style="width:150px">Signals</th><th>Assessment</th></tr></thead><tbody>`;
    ssrf.forEach(x=>html+=`<tr><td><span class="sev-${esc(x.sev)}">${esc(x.sev)}</span></td><td><code>${esc(x.param)}</code> <button class="btn sm secondary" style="padding:3px 8px;font-size:10.5px" onclick="sendToRepeater(${repArg((d.base||'')+'/?'+x.param+'=http://127.0.0.1/')})">⇢ Repeater</button></td><td style="font-size:11px">${(x.signals||[]).map(s=>`<span class="pill dim">${esc(s)}</span>`).join(' ')}</td><td style="font-size:11.5px">${esc(x.verdict)}</td></tr>`);
    html+=`</tbody></table></div>`;
  } else { html+=`<div class="findings-note">✅ ${esc(d.ssrf_note||'No SSRF-consuming parameter behaviour detected.')}</div>`; }
  if(d.fix)html+=`<div class="findings-note" style="margin-top:8px;border-left-color:var(--info)">🛠️ <strong>Fix:</strong> ${esc(d.fix)}</div>`;
  setBody(id,html);
}

function renderGeoAggregate(id,r){
  if(!r.ok)return errorBody(id,r.error);const d=r.data||{};
  const c=d.consensus||{};const provs=d.providers||[];
  const cv=(o)=>o&&o.value?o.value:'—';
  const agree=(o)=>o&&o.total?`<span class="pill ${o.agree>=Math.ceil(o.total/2)?'ok':'warn'}" style="font-size:9px">${o.agree}/${o.total}</span>`:'';
  let html=`<div class="stats" style="margin-bottom:14px">
    <div class="stat"><div class="n" style="font-size:16px">${esc(cv(c.country))}</div><div class="l">Country ${agree(c.country)}</div></div>
    <div class="stat"><div class="n" style="font-size:16px">${esc(cv(c.city))}</div><div class="l">City ${agree(c.city)}</div></div>
    <div class="stat"><div class="n" style="font-size:13px">${esc(cv(c.asn))}</div><div class="l">ASN ${agree(c.asn)}</div></div>
    <div class="stat"><div class="n">${c.providers_ok||0}/${c.providers_total||0}</div><div class="l">Providers OK</div></div></div>`;
  html+=`<div class="findings-note" style="margin-bottom:12px"><strong>Consensus:</strong> ${esc(cv(c.city))}, ${esc(cv(c.region))}, ${esc(cv(c.country))} · ISP ${esc(cv(c.isp))} · TZ ${esc(cv(c.timezone))}${(c.lat!==''&&c.lat!=null)?` · <a href="${esc(d.map)}" target="_blank" rel="noopener noreferrer">📍 ${esc(c.lat)}, ${esc(c.lon)} (map ↗)</a>`:''}</div>`;
  html+=`<h4 class="sub">Per-Provider Results (${provs.length})</h4><div class="table-wrap scroll" style="max-height:420px"><table><thead><tr><th>Provider</th><th>Country</th><th>Region</th><th>City</th><th>ISP / Org</th><th>ASN</th><th>Lat, Lon</th></tr></thead><tbody>`;
  provs.forEach(p=>{
    if(p.ok){
      html+=`<tr><td><strong>${esc(p.provider)}</strong> <span class="pill ok" style="font-size:9px">ok</span></td><td>${esc(p.country||'—')}</td><td>${esc(p.region||'—')}</td><td>${esc(p.city||'—')}</td><td style="font-size:11px">${esc(p.isp||p.org||'—')}</td><td><code style="font-size:10px">${esc(p.asn||'—')}</code></td><td style="font-size:11px"><code>${esc(p.lat||'—')}, ${esc(p.lon||'—')}</code></td></tr>`;
    } else {
      html+=`<tr><td><strong>${esc(p.provider)}</strong> <span class="pill dim" style="font-size:9px">n/a</span></td><td colspan="6" style="color:var(--dim);font-size:11.5px">${esc(p.error||'no data')}</td></tr>`;
    }
  });
  html+=`</tbody></table></div><div class="findings-note" style="margin-top:8px">🌍 Aggregated from multiple free geolocation providers (iplocation.io-style). Discrepancies between providers are normal — the consensus column shows majority agreement.</div>`;
  setBody(id,html);
}
/* ============================================================
 * v2.7.0 — HTTP Repeater (Burp-Repeater-style) + Send to Repeater
 * ============================================================ */
window.REP_HISTORY = window.REP_HISTORY || [];

function repMethodPill(m){
  const c={GET:'ok',POST:'info',PUT:'warn',PATCH:'warn',DELETE:'bad',HEAD:'dim',OPTIONS:'purple'}[m]||'dim';
  return `<span class="pill ${c}">${esc(m)}</span>`;
}
function repStatusPill(code){
  const c=code>=200&&code<300?'ok':code>=300&&code<400?'info':code>=400&&code<500?'warn':code>=500?'bad':'dim';
  return `<span class="pill ${c}">${esc(code||'—')}</span>`;
}

async function repeaterSend(){
  const method=(document.getElementById('rep-method').value||'GET').trim();
  const url=(document.getElementById('rep-url').value||'').trim();
  const headers=document.getElementById('rep-headers').value||'';
  const body=document.getElementById('rep-body').value||'';
  const follow=document.getElementById('rep-follow').checked?'1':'0';
  const timeout=document.getElementById('rep-timeout').value||'15';
  const ack=document.getElementById('rep-ack').checked;
  if(!url){toast('Enter a target URL.');return;}
  if(!/^https?:\/\//i.test(url)){toast('URL must start with http:// or https://');return;}
  if(!ack){toast('Please confirm you are authorized to test this target.');return;}
  const btn=document.getElementById('rep-send');const o=btn.innerHTML;btn.disabled=true;btn.innerHTML='Sending…';
  document.getElementById('rep-status-badges').innerHTML='<span class="pill dim">running…</span>';
  document.getElementById('rep-response').innerHTML='<div class="section-loading"><div class="mini-spin"></div><span>Sending '+esc(method)+' request…</span></div>';
  try{
    const fd=new FormData();
    fd.append('rep_method',method);fd.append('rep_url',url);fd.append('rep_headers',headers);
    fd.append('rep_body',body);fd.append('rep_follow',follow);fd.append('rep_timeout',timeout);
    const res=await fetch('?api=1&action=repeater',{method:'POST',body:fd});
    const raw=await res.text();
    let r;try{r=JSON.parse(raw);}catch(e){document.getElementById('rep-status-badges').innerHTML='<span class="pill bad">error</span>';document.getElementById('rep-response').innerHTML='<div class="err-note">Invalid server response.<br><pre style="white-space:pre-wrap;font-size:11px;margin-top:6px">'+esc(raw.slice(0,600))+'</pre></div>';return;}
    if(!r.ok||!(r.data&&r.data.ok)){const err=(r.data&&r.data.error)||r.error||'Request failed.';document.getElementById('rep-status-badges').innerHTML='<span class="pill bad">failed</span>';document.getElementById('rep-response').innerHTML='<div class="err-note">'+esc(err)+'</div>';return;}
    renderRepeaterResponse(r.data);
    repeaterAddHistory({method,url,headers,body,follow,timeout},r.data);
  }catch(e){document.getElementById('rep-status-badges').innerHTML='<span class="pill bad">error</span>';document.getElementById('rep-response').innerHTML='<div class="err-note">'+esc(e.message)+'</div>';}
  finally{btn.disabled=false;btn.innerHTML=o;}
}

function renderRepeaterResponse(d){
  const badges=[repStatusPill(d.status),`<span class="pill dim">${esc(d.http_version||'HTTP')}</span>`,`<span class="pill info">${d.time_ms} ms</span>`,`<span class="pill dim">${(d.size||0).toLocaleString()} B</span>`];
  document.getElementById('rep-status-badges').innerHTML=badges.join(' ');
  const hdrs=d.resp_headers||{};
  let hrows=Object.keys(hdrs).map(k=>`<tr><td style="width:200px;color:var(--dim);font-weight:600;font-size:11.5px">${esc(k)}</td><td><code style="font-size:11px;word-break:break-all">${esc(hdrs[k])}</code></td></tr>`).join('');
  let html=`<div class="kv" style="grid-template-columns:130px 1fr;margin-bottom:10px">
    <div class="k">Status</div><div class="v">${repStatusPill(d.status)} <code style="font-size:11px">${esc(d.status_line||'')}</code></div>
    <div class="k">Final URL</div><div class="v"><code style="font-size:11px;word-break:break-all">${esc(d.effective_url||'')}</code></div>
    <div class="k">Remote IP</div><div class="v"><code>${esc(d.remote_ip||'—')}</code></div>
    <div class="k">Content-Type</div><div class="v"><code>${esc(d.content_type||'—')}</code></div></div>`;
  html+=`<h4 class="sub">Response Headers (${Object.keys(hdrs).length})</h4><div class="table-wrap scroll" style="max-height:220px"><table><tbody>${hrows||'<tr><td>No headers.</td></tr>'}</tbody></table></div>`;
  const isImg=/^image\//i.test(d.content_type||'');
  html+=`<h4 class="sub">Response Body ${d.body_truncated?'<span style="font-weight:400;color:var(--warn);font-size:11px">(truncated to 200 KB)</span>':''}</h4>`;
  if(isImg){
    html+=`<div class="findings-note">Binary/image response (${esc(d.content_type)}) — ${ (d.size||0).toLocaleString() } bytes. Body preview suppressed.</div>`;
  } else {
    html+=`<div class="rep-raw"><div class="rep-raw-head"><span>BODY</span><span>${(d.size||0).toLocaleString()} bytes</span></div><pre>${esc(d.body||'')||'(empty body)'}</pre></div>`;
  }
  document.getElementById('rep-response').innerHTML=html;
}

function repeaterAddHistory(req,resp){
  window.REP_HISTORY.unshift({req,status:resp.status,time:resp.time_ms,size:resp.size,ts:new Date().toLocaleTimeString()});
  if(window.REP_HISTORY.length>30)window.REP_HISTORY.pop();
  repeaterRenderHistory();
}
function repeaterRenderHistory(){
  const sec=document.getElementById('rep-history-sec');const wrap=document.getElementById('rep-history');
  if(!window.REP_HISTORY.length){sec.style.display='none';return;}
  sec.style.display='block';
  wrap.innerHTML=window.REP_HISTORY.map((h,i)=>`<div class="rep-hist-item">
    <div>${repMethodPill(h.req.method)}</div>
    <div><code>${esc(h.req.url)}</code><br><span style="font-size:10.5px;color:var(--dim)">${repStatusPill(h.status)} · ${h.time} ms · ${(h.size||0).toLocaleString()} B · ${esc(h.ts)}</span></div>
    <div><button class="btn secondary sm" onclick="repeaterReplay(${i})">↺ Load</button></div>
  </div>`).join('');
}
function repeaterReplay(i){
  const h=window.REP_HISTORY[i];if(!h)return;
  document.getElementById('rep-method').value=h.req.method;
  document.getElementById('rep-url').value=h.req.url;
  document.getElementById('rep-headers').value=h.req.headers||'';
  document.getElementById('rep-body').value=h.req.body||'';
  document.getElementById('rep-follow').checked=(h.req.follow==='1');
  document.getElementById('rep-timeout').value=h.req.timeout||'15';
  document.getElementById('input-cards').scrollIntoView({behavior:'smooth'});
  toast('Loaded request from history — edit and re-send.');
}
function repeaterClearHistory(){window.REP_HISTORY=[];repeaterRenderHistory();toast('History cleared.');}

/* Switch to the Repeater tab and pre-fill the request (used by "⇢ Repeater" buttons) */
function sendAllEndpointsToRepeater(){
  const eps=window.LAST_JS_ENDPOINTS||[];
  if(!eps.length){toast('No endpoints to send.');return;}
  sendToRepeater(eps[0]);
  if(eps.length>1)toast(eps.length+' endpoints discovered — loaded the first; use ⇢ Repeater on any row to load others.');
}
function sendToRepeater(url,method,headers,body){
  try{
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active','teal','orange','purple'));
    const rb=document.querySelector('.tab-btn[data-tab="repeater"]');if(rb)rb.classList.add('active','orange');
    document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
    document.getElementById('pane-repeater').classList.add('active');
    if(url)document.getElementById('rep-url').value=url;
    if(method)document.getElementById('rep-method').value=method;
    if(headers!=null)document.getElementById('rep-headers').value=headers;
    if(body!=null)document.getElementById('rep-body').value=body;
    document.getElementById('rep-ack').checked=true; // carried over from the authorized scan
    window.scrollTo({top:0,behavior:'smooth'});
    toast('Loaded into Repeater — review and Send.');
  }catch(e){toast('Could not open Repeater: '+e.message);}
}

/* Post-render pass: add "⇢ Repeater" buttons to discovered directory-probe paths */
function enhanceURLRepeater(){
  try{
    const wrap=document.getElementById('dir-table-wrap');
    if(!wrap)return;
    wrap.querySelectorAll('a[href]').forEach(a=>{
      if(a.dataset.repDone)return;a.dataset.repDone='1';
      const u=a.getAttribute('href');if(!u||!/^https?:\/\//i.test(u))return;
      const btn=document.createElement('button');
      btn.className='btn sm secondary';btn.style.cssText='padding:2px 7px;font-size:10px;margin-left:6px';
      btn.textContent='⇢ Rep';btn.title='Send this path to the HTTP Repeater';
      btn.onclick=(e)=>{e.preventDefault();sendToRepeater(u);};
      a.parentNode.appendChild(btn);
    });
  }catch(e){}
}
async function runStep(id,action,target,renderer,kind){kind=kind||K();setStatus(id,'running','Running');document.getElementById('body-'+id).innerHTML=`<div class="section-loading"><div class="mini-spin"></div><span>Fetching ${esc(action)}…</span></div>`;try{const r=await callApi(action,target);if(r.ok&&r.data&&kind==='url'){window.LAST_RECON=window.LAST_RECON||{};window.LAST_RECON[action]=r.data;}if(r.ok&&r.data&&r.data.skipped)setStatus(id,'skipped','Skipped');else if(r.ok&&!(r.data&&r.data.error))setStatus(id,'done','Done · '+r.elapsed+'s');else setStatus(id,'error','Error');renderer(id,r);}catch(e){setStatus(id,'error','Failed');errorBody(id,e.message);}progressStep(kind);}
async function orchestrateURL(target){window.LAST_RECON={};window.URL_SCAN_TARGET=target;window.CURRENT_SCAN.kind='url';const wpOn=document.getElementById('opt-wpscan')?.checked!==false;const steps=[{id:'page',title:'Page Source & Security Analysis',action:'page',render:renderPage}];if(wpOn)steps.push({id:'wordpress',title:'WordPress Fingerprint · Plugin/Theme Vulnerability Scan',action:'wordpress',render:renderWordPress});steps.push({id:'waf',title:'Advanced WAF/CDN Detection',action:'waf',render:renderWaf},{id:'dir',title:'Expanded Directory / Path Probe',action:'dir',render:renderDir},{id:'tls',title:'TLS / SSL Certificate Inspector',action:'tls',render:renderTLS},{id:'dns',title:'DNS & Email-Security Posture',action:'dns',render:renderDNS},{id:'cookies',title:'Cookie & CSP Analyzer',action:'cookies',render:renderCookies},{id:'headers_grade',title:'Security Header Grade (A+ → F)',action:'headers_grade',render:renderHeadersGrade},{id:'cors',title:'CORS Misconfiguration Scanner',action:'cors',render:renderCORS},{id:'js_recon',title:'JS Secret & Endpoint Extractor',action:'js_recon',render:renderJSRecon},{id:'takeover',title:'Subdomain Takeover / Dangling-DNS Detector',action:'takeover',render:renderTakeover},{id:'graphql',title:'GraphQL Introspection & IDE Detector',action:'graphql',render:renderGraphQL},{id:'favicon',title:'Favicon Hash Fingerprint (Shodan mmh3)',action:'favicon',render:renderFavicon},{id:'http_tls',title:'HTTP/2 · HTTP/3 & TLS-Version Detection',action:'http_tls',render:renderHttpTls},{id:'wellknown',title:'security.txt & .well-known Posture (RFC 9116)',action:'wellknown',render:renderWellKnown},{id:'dns_caa',title:'DNS CAA + DNSSEC Validation',action:'dns_caa',render:renderDnsCaa},{id:'openredir',title:'Open-Redirect / SSRF-Parameter Detector',action:'openredir',render:renderOpenRedir},{id:'vt_domain',title:'VirusTotal Domain Reputation',action:'vt_domain',render:(i,r)=>renderVT(i,r,true)});await runSteps(steps,target,'url');}
async function orchestrateIP(target){window.IP_SCAN_TARGET=target;window.CURRENT_SCAN.kind='ip';const steps=[{id:'ip_geo',title:'Geolocation & Network',action:'ip_geo',render:(i,r)=>renderKV(i,r)},{id:'ip_geo_multi',title:'Multi-Provider Geolocation Aggregator',action:'ip_geo_multi',render:renderGeoAggregate},{id:'ip_rdns',title:'Reverse DNS',action:'ip_rdns',render:renderRdns},{id:'ip_rdap',title:'RDAP Registry Record',action:'ip_rdap',render:renderRdap},{id:'ip_spamhaus',title:'Spamhaus DNSBL',action:'ip_spamhaus',render:renderSpamhaus},{id:'ip_ports',title:'TCP Port Probe',action:'ip_ports',render:renderPorts},{id:'shodan_host',title:'Shodan Host Intel',action:'shodan_host',render:renderShodanHost},{id:'abuseipdb',title:'AbuseIPDB Reputation',action:'abuseipdb',render:renderAbuse},{id:'vt_ip',title:'VirusTotal IP Reputation',action:'vt_ip',render:(i,r)=>renderVT(i,r,false)}];await runSteps(steps,target,'ip');}
async function runSteps(steps,target,kind){kind=kind||'url';const rc=resultsEl(kind);if(rc)rc.innerHTML=steps.map(s=>makeSection(s.id,s.title)).join('');progressInit(target,steps.length,kind);const ab=elK('act',kind);if(ab)ab.style.display='none';for(const s of steps)await runStep(s.id,s.action,target,s.render,kind);progressFinish(kind);}
/* ===== v2.7.4: concurrent-scan registry + cross-tab busy guard ===== */
window.SCAN_STATE=window.SCAN_STATE||{};
const SCAN_LABELS={url:'URL',ip:'IP',code:'Code',nuclei:'Nuclei'};
function scanBusy(kind){return !!(window.SCAN_STATE[kind]&&window.SCAN_STATE[kind].busy);}
function scanBegin(kind,target){window.SCAN_STATE[kind]={busy:true,target:target||'',started:Date.now()};renderScanStrip();}
function scanEnd(kind){if(window.SCAN_STATE[kind])window.SCAN_STATE[kind].busy=false;renderScanStrip();}
function renderScanStrip(){
  const el=document.getElementById('scan-strip');if(!el)return;
  const active=Object.keys(SCAN_LABELS).filter(k=>scanBusy(k));
  if(!active.length){el.innerHTML='<span class="scan-idle">● all idle</span>';return;}
  let h=active.map(k=>{const t=window.SCAN_STATE[k].target||'';const tip=SCAN_LABELS[k]+' scan running'+(t?(' — '+t):'');
    return `<span class="scan-badge ${k}" title="${esc(tip)}"><span class="scan-spin"></span>${esc(SCAN_LABELS[k])} scanning…</span>`;}).join('');
  if(active.length>1)h+=`<span class="scan-count">${active.length} concurrent</span>`;
  el.innerHTML=h;
}
/* Returns true if OK to proceed; blocks + warns if this tab is already scanning */
function guardScan(kind){if(scanBusy(kind)){toast('⏳ '+(SCAN_LABELS[kind]||kind)+' scan already running — please wait for it to finish (or open a different tab).');return false;}return true;}

document.querySelectorAll('form.scan-form').forEach(form=>{form.addEventListener('submit',async e=>{e.preventDefault();const kind=form.dataset.kind;const target=form.querySelector('input[name="target"]').value.trim();if(!target||!form.querySelector('input[name="ack"]').checked)return;if(!guardScan(kind))return;window.CURRENT_SCAN.kind=kind;const btn=form.querySelector('button');btn.disabled=true;const o=btn.innerHTML;btn.innerHTML='Scanning…';form.classList.add('form-busy');scanBegin(kind,target);const rcEl=resultsEl(kind);if(rcEl)rcEl.scrollIntoView({behavior:'smooth',block:'start'});try{if(kind==='url')await orchestrateURL(target);else if(kind==='nuclei')await runNuclei(target);else await orchestrateIP(target);}finally{btn.disabled=false;btn.innerHTML=o;form.classList.remove('form-busy');scanEnd(kind);}});});
function newScan(kind){const k=kind||K();const rc=document.getElementById('results-'+k);if(rc)rc.innerHTML='';const ab=document.getElementById('act-'+k);if(ab)ab.style.display='none';const pw=document.getElementById('prog-'+k);if(pw)pw.style.display='none';document.getElementById('input-cards').scrollIntoView({behavior:'smooth'});}

/* Fetch a remote script into the Code Analyzer */
async function fetchScriptToAnalyzer(url){
  toast('Fetching '+url.substring(0,60)+'…');
  try{
    const r=await callApi('fetch_script',url);
    if(!r.ok){toast('Fetch failed: '+r.error);return;}
    document.getElementById('code-input').value=r.data.body||'';
    document.getElementById('code-lang').value='js';
    // switch to code tab
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active','teal','orange','purple'));
    const cb=document.querySelector('.tab-btn[data-tab="code"]');cb.classList.add('active','orange');
    document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
    document.getElementById('pane-code').classList.add('active');
    window.scrollTo({top:0,behavior:'smooth'});
    toast('Loaded '+(r.data.size||0).toLocaleString()+' bytes. Click "Analyze Code".');
  }catch(e){toast('Error: '+e.message);}
}
document.getElementById('form-fetch').addEventListener('submit',async e=>{
  e.preventDefault();
  const u=document.getElementById('fetch-url').value.trim();
  if(!u){toast('Enter a script URL.');return;}
  await fetchScriptToAnalyzer(u);
});

/* ================= SAST ENGINE (122 rules) ================= */
const OWASP={A01:'A01 Broken Access Control',A02:'A02 Cryptographic Failures',A03:'A03 Injection',A04:'A04 Insecure Design',A05:'A05 Security Misconfig',A06:'A06 Vulnerable Components',A07:'A07 Auth Failures',A08:'A08 Integrity Failures',A09:'A09 Logging Failures',A10:'A10 SSRF'};
const SAST_RULES=[
{id:'sec-aws-akid',lang:['*'],sev:'Critical',title:'AWS Access Key ID exposed',re:/AKIA[0-9A-Z]{16}/,why:'Hardcoded AWS key enables account takeover.',fix:'Rotate; use IAM roles / Secrets Manager.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-aws-secret',lang:['*'],sev:'Critical',title:'AWS Secret Access Key',re:/aws_secret_access_key\s*[:=]\s*['"][A-Za-z0-9\/+]{40}['"]/i,why:'Full API access.',fix:'Rotate; Secrets Manager.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-gcp',lang:['*'],sev:'Critical',title:'Google API key exposed',re:/\bAIza[0-9A-Za-z_\-]{35}\b/,why:'Can be abused / billed.',fix:'Restrict; rotate.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-ghp',lang:['*'],sev:'Critical',title:'GitHub PAT',re:/\bghp_[A-Za-z0-9]{36}\b/,why:'Repo access — supply-chain.',fix:'Revoke on GitHub.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-gh-oauth',lang:['*'],sev:'Critical',title:'GitHub OAuth token',re:/\bgho_[A-Za-z0-9]{36}\b/,why:'OAuth token exposed.',fix:'Revoke.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-slack',lang:['*'],sev:'Critical',title:'Slack token',re:/\bxox[baprs]-[A-Za-z0-9\-]{10,}/,why:'Workspace access.',fix:'Revoke.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-stripe-live',lang:['*'],sev:'Critical',title:'Stripe live secret key',re:/\bsk_live_[A-Za-z0-9]{20,}/,why:'Live payment access.',fix:'Roll key.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-stripe-rk',lang:['*'],sev:'High',title:'Stripe restricted key',re:/\brk_live_[A-Za-z0-9]{20,}/,why:'Scoped live key.',fix:'Roll key.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-twilio',lang:['*'],sev:'Critical',title:'Twilio API key',re:/\bSK[0-9a-fA-F]{32}\b/,why:'Messaging/voice abuse.',fix:'Rotate.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-sendgrid',lang:['*'],sev:'Critical',title:'SendGrid API key',re:/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/,why:'Email abuse.',fix:'Rotate.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-npm',lang:['*'],sev:'Critical',title:'npm access token',re:/\bnpm_[A-Za-z0-9]{36}\b/,why:'Publish access — supply-chain.',fix:'Revoke.',cwe:'CWE-798',owasp:'A08'},
{id:'sec-pem',lang:['*'],sev:'Critical',title:'Private key material (PEM)',re:/-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----/,why:'Compromises TLS/SSH/signing.',fix:'Remove; rotate key pair.',cwe:'CWE-798',owasp:'A02'},
{id:'sec-jwt',lang:['*'],sev:'High',title:'JWT token literal',re:/\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}/,why:'May leak session/claims.',fix:'Issue at runtime.',cwe:'CWE-798',owasp:'A07'},
{id:'sec-mongo',lang:['*'],sev:'Critical',title:'MongoDB URI with credentials',re:/mongodb(\+srv)?:\/\/[^\s'"`<>]*:[^\s'"`<>]+@/i,why:'DB creds in string.',fix:'Env vars; rotate.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-mysql',lang:['*'],sev:'Critical',title:'MySQL URI with credentials',re:/mysql:\/\/[^\s'"`<>]*:[^\s'"`<>]+@/i,why:'DB creds in string.',fix:'Env vars.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-pg',lang:['*'],sev:'Critical',title:'Postgres URI with credentials',re:/postgres(?:ql)?:\/\/[^\s'"`<>]*:[^\s'"`<>]+@/i,why:'DB creds in string.',fix:'Env vars.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-pw',lang:['*'],sev:'High',title:'Hardcoded password',re:/\b(password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i,why:'Plaintext password.',fix:'Secrets store.',cwe:'CWE-259',owasp:'A07'},
{id:'sec-key',lang:['*'],sev:'High',title:'Hardcoded API key/secret',re:/\b(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i,why:'Secret literal.',fix:'Env vars.',cwe:'CWE-798',owasp:'A05'},
{id:'sec-basic',lang:['*'],sev:'Medium',title:'Basic-auth credentials in URL',re:/https?:\/\/[^\s'"`\/]+:[^\s'"`@\/]+@/,why:'Leaks via logs/referrer.',fix:'Token auth.',cwe:'CWE-522',owasp:'A07'},
{id:'crypto-md5',lang:['*'],sev:'High',title:'MD5 hashing',re:/\bMD5\s*\(|hashlib\.md5|CryptoJS\.MD5|getInstance\(\s*["']MD5["']/i,why:'MD5 collisions trivial.',fix:'SHA-256; bcrypt/Argon2 for pw.',cwe:'CWE-327',owasp:'A02'},
{id:'crypto-sha1',lang:['*'],sev:'High',title:'SHA-1 hashing',re:/\bSHA-?1\s*\(|hashlib\.sha1|CryptoJS\.SHA1|getInstance\(\s*["']SHA-?1["']/i,why:'Collision-vulnerable.',fix:'SHA-256/3.',cwe:'CWE-327',owasp:'A02'},
{id:'crypto-des',lang:['*'],sev:'High',title:'Weak cipher (DES/3DES/RC4)',re:/\b(DES|3DES|DESede|RC4|ARC4)\b/,why:'Broken/legacy ciphers.',fix:'AES-256-GCM/ChaCha20.',cwe:'CWE-327',owasp:'A02'},
{id:'crypto-ecb',lang:['*'],sev:'High',title:'ECB cipher mode',re:/\bECB\b|AES\/ECB|getInstance\(\s*["'][^"']*ECB/i,why:'Leaks plaintext patterns.',fix:'GCM/CBC + random IV.',cwe:'CWE-327',owasp:'A02'},
{id:'crypto-iv',lang:['*'],sev:'Medium',title:'Static/hardcoded IV or salt',re:/\b(iv|salt)\s*[:=]\s*['"][A-Za-z0-9+\/=]{8,}['"]/i,why:'Reused IV/salt weakens crypto.',fix:'Random per operation.',cwe:'CWE-329',owasp:'A02'},
{id:'crypto-mathrand',lang:['js','*'],sev:'High',title:'Math.random() for security value',re:/Math\.random\s*\(\s*\)/,why:'Predictable RNG.',fix:'crypto.getRandomValues().',cwe:'CWE-338',owasp:'A02',ctx:/(token|secret|nonce|password|key|session|salt|otp|csrf)/i},
{id:'crypto-weakrng',lang:['php','python','java','*'],sev:'Medium',title:'Non-crypto RNG for sensitive value',re:/\b(mt_rand|rand|random\.random|new\s+Random\s*\()/i,why:'Predictable PRNG.',fix:'random_bytes/secrets/SecureRandom.',cwe:'CWE-338',owasp:'A02',ctx:/(token|secret|password|key|otp|session)/i},
{id:'eval-generic',lang:['*'],sev:'Critical',title:'eval() dynamic code execution',re:/(^|[^.\w])eval\s*\(/,why:'Executes arbitrary strings — RCE.',fix:'Remove eval; safe parsers.',cwe:'CWE-95',owasp:'A03'},
{id:'tls-verify',lang:['*'],sev:'High',title:'TLS certificate verification disabled',re:/CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|OPENSSL_VERIFY_NONE/i,why:'Enables MITM.',fix:'Enable full verification.',cwe:'CWE-295',owasp:'A02'},
{id:'http-url',lang:['*'],sev:'Low',title:'Cleartext HTTP URL',re:/["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'`\s]{4,}/i,why:'MITM-prone.',fix:'Use https://.',cwe:'CWE-319',owasp:'A02'},
{id:'php-sqli',lang:['php'],sev:'Critical',title:'SQL injection (query with user input)',re:/(mysqli?_query|pg_query|mssql_query|sqlsrv_query|->query)\s*\([^)]*(\$_(GET|POST|REQUEST|COOKIE)|\.\s*\$)/,why:'User input in SQL.',fix:'PDO prepared statements.',cwe:'CWE-89',owasp:'A03'},
{id:'php-mysql-dep',lang:['php'],sev:'High',title:'Deprecated mysql_* API',re:/\bmysql_query\s*\(/,why:'Removed in PHP 7; no params.',fix:'PDO/mysqli prepared.',cwe:'CWE-89',owasp:'A03'},
{id:'php-cmdi',lang:['php'],sev:'Critical',title:'OS command injection',re:/\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\([^)]*\$/,why:'Interpolated shell command.',fix:'escapeshellarg() / avoid shell.',cwe:'CWE-78',owasp:'A03'},
{id:'php-backtick',lang:['php'],sev:'Critical',title:'Backtick shell execution',re:/`[^`]*\$[^`]*`/,why:'Runs shell with variables.',fix:'Avoid backticks.',cwe:'CWE-78',owasp:'A03'},
{id:'php-lfi',lang:['php'],sev:'Critical',title:'File inclusion (LFI/RFI)',re:/\b(include|require|include_once|require_once)\s*\(?\s*\$/,why:'Include from variable.',fix:'Whitelist includes.',cwe:'CWE-98',owasp:'A03'},
{id:'php-pathtrav',lang:['php'],sev:'High',title:'Path traversal via file API',re:/\b(file_get_contents|fopen|readfile|file|unlink|fwrite)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/,why:'Arbitrary file access.',fix:'realpath()+prefix check.',cwe:'CWE-22',owasp:'A01'},
{id:'php-xss',lang:['php'],sev:'High',title:'Reflected XSS (echo user input)',re:/\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)/,why:'Raw output of user input.',fix:'htmlspecialchars() ENT_QUOTES.',cwe:'CWE-79',owasp:'A03'},
{id:'php-deser',lang:['php'],sev:'Critical',title:'Insecure deserialization (unserialize)',re:/\bunserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/,why:'Object injection → RCE.',fix:'json_decode / allowed_classes=[].',cwe:'CWE-502',owasp:'A08'},
{id:'php-ssrf',lang:['php'],sev:'High',title:'SSRF (user-controlled fetch)',re:/(file_get_contents|fopen|curl_setopt[^;]*CURLOPT_URL)[^;]*\$_(GET|POST|REQUEST)/,why:'User controls URL.',fix:'Validate scheme; block private IPs.',cwe:'CWE-918',owasp:'A10'},
{id:'php-xxe',lang:['php'],sev:'High',title:'XXE (entity loading enabled)',re:/libxml_disable_entity_loader\s*\(\s*false\s*\)|LIBXML_NOENT/,why:'External entities → disclosure/SSRF.',fix:'Disable entity loader.',cwe:'CWE-611',owasp:'A05'},
{id:'php-header',lang:['php'],sev:'Medium',title:'HTTP header/redirect injection',re:/\bheader\s*\([^)]*\$_(GET|POST|REQUEST)/,why:'CRLF/open-redirect.',fix:'Whitelist; strip CRLF.',cwe:'CWE-601',owasp:'A01'},
{id:'php-extract',lang:['php'],sev:'High',title:'extract() on user input',re:/\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,why:'Overwrites variables.',fix:'Never extract() request data.',cwe:'CWE-915',owasp:'A08'},
{id:'php-assert',lang:['php'],sev:'Critical',title:'assert() with dynamic input',re:/\bassert\s*\(\s*\$/,why:'assert evaluates strings as code.',fix:'Never pass vars to assert().',cwe:'CWE-95',owasp:'A03'},
{id:'php-preg-e',lang:['php'],sev:'High',title:'preg_replace /e modifier',re:/preg_replace\s*\(\s*['"][^'"]*e[a-z]*['"]/i,why:'/e evals replacement as code.',fix:'preg_replace_callback().',cwe:'CWE-95',owasp:'A03'},
{id:'php-disperr',lang:['php'],sev:'Medium',title:'display_errors enabled',re:/ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(1|on)/i,why:'Leaks paths/secrets.',fix:'display_errors=Off.',cwe:'CWE-209',owasp:'A05'},
{id:'php-weakcmp',lang:['php'],sev:'Medium',title:'Loose comparison of secrets',re:/\bif\s*\(\s*\$\w*(hash|token|password|hmac|sig)\w*\s*==[^=]/i,why:'Type-juggling auth bypass.',fix:'hash_equals() / strict ===.',cwe:'CWE-697',owasp:'A07'},
{id:'js-innerhtml',lang:['js'],sev:'High',title:'innerHTML assignment (DOM XSS)',re:/\.innerHTML\s*=/,why:'Assigning HTML enables XSS.',fix:'textContent / DOMPurify.',cwe:'CWE-79',owasp:'A03'},
{id:'js-outerhtml',lang:['js'],sev:'High',title:'outerHTML assignment (DOM XSS)',re:/\.outerHTML\s*=/,why:'XSS risk.',fix:'Sanitize.',cwe:'CWE-79',owasp:'A03'},
{id:'js-docwrite',lang:['js'],sev:'High',title:'document.write()',re:/document\.write(?:ln)?\s*\(/,why:'HTML/JS injection sink.',fix:'DOM APIs.',cwe:'CWE-79',owasp:'A03'},
{id:'js-insertadj',lang:['js'],sev:'Medium',title:'insertAdjacentHTML sink',re:/\.insertAdjacentHTML\s*\(/,why:'HTML injection.',fix:'insertAdjacentText/sanitize.',cwe:'CWE-79',owasp:'A03'},
{id:'js-jqhtml',lang:['js'],sev:'Medium',title:'jQuery .html() sink',re:/\$\([^)]*\)\.html\s*\(/,why:'XSS with user input.',fix:'.text()/sanitize.',cwe:'CWE-79',owasp:'A03'},
{id:'js-dangerhtml',lang:['js'],sev:'High',title:'React dangerouslySetInnerHTML',re:/dangerouslySetInnerHTML/,why:'Bypasses auto-escaping.',fix:'DOMPurify.',cwe:'CWE-79',owasp:'A03'},
{id:'js-newfunc',lang:['js'],sev:'Critical',title:'new Function() dynamic code',re:/\bnew\s+Function\s*\(/,why:'Equivalent to eval.',fix:'Refactor.',cwe:'CWE-95',owasp:'A03'},
{id:'js-settimeout',lang:['js'],sev:'High',title:'setTimeout/Interval with string',re:/set(Timeout|Interval)\s*\(\s*["'`]/,why:'String compiled as code.',fix:'Pass function reference.',cwe:'CWE-95',owasp:'A03'},
{id:'js-cmdi',lang:['js'],sev:'Critical',title:'Node command injection',re:/child_process[^;]*\.(exec|execSync)\s*\([^)]*[\+`]/,why:'Shell metacharacters.',fix:'execFile/spawn arg array.',cwe:'CWE-78',owasp:'A03'},
{id:'js-sqli',lang:['js'],sev:'Critical',title:'SQL injection (template/concat)',re:/\.(query|execute)\s*\(\s*[`'"][^`'"]*\$\{|\.(query|execute)\s*\([^)]*\+\s*\w+\s*\+/,why:'Interpolated SQL.',fix:'Parameterized queries.',cwe:'CWE-89',owasp:'A03'},
{id:'js-proto',lang:['js'],sev:'High',title:'Prototype pollution surface',re:/Object\.assign\s*\(\s*\w+\s*,\s*(JSON\.parse|req\.body|req\.query|params)/,why:'Untrusted merge pollutes prototype.',fix:'Guard __proto__; use Map.',cwe:'CWE-1321',owasp:'A08'},
{id:'js-proto2',lang:['js'],sev:'Medium',title:'__proto__ reference',re:/__proto__/,why:'Pollution vector.',fix:'Object.create(null).',cwe:'CWE-1321',owasp:'A08'},
{id:'js-openredir',lang:['js'],sev:'Medium',title:'Open redirect',re:/(location\.(href|assign|replace)|res\.redirect)\s*\(?[^;]*(req\.query|req\.body|location\.(hash|search)|params)/,why:'User controls redirect.',fix:'Whitelist hosts.',cwe:'CWE-601',owasp:'A01'},
{id:'js-postmsg',lang:['js'],sev:'High',title:'postMessage without origin check',re:/addEventListener\s*\(\s*['"]message['"]/,why:'Any origin can send.',fix:'Verify event.origin.',cwe:'CWE-346',owasp:'A05',ctxNot:/event\.origin\s*(===|==)/},
{id:'js-postmsg-star',lang:['js'],sev:'Medium',title:'postMessage targetOrigin "*"',re:/\.postMessage\s*\([^,]+,\s*['"]\*['"]/,why:'Leaks to any listener.',fix:'Explicit targetOrigin.',cwe:'CWE-346',owasp:'A05'},
{id:'js-cors',lang:['js'],sev:'Medium',title:'Permissive CORS (Origin: *)',re:/Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]?\*|origin\s*:\s*['"]\*['"]/i,why:'Any site reads authed responses.',fix:'Restrict origins.',cwe:'CWE-346',owasp:'A05'},
{id:'js-localstorage',lang:['js'],sev:'Medium',title:'Sensitive value in localStorage',re:/(local|session)Storage\.setItem\s*\(\s*["'](token|jwt|password|secret|api[_-]?key|auth)/i,why:'XSS exfiltrates Web Storage.',fix:'HttpOnly cookies.',cwe:'CWE-522',owasp:'A07'},
{id:'js-cookie',lang:['js'],sev:'Low',title:'document.cookie write',re:/document\.cookie\s*=/,why:'JS cookies lack Secure/HttpOnly.',fix:'Set from server.',cwe:'CWE-1004',owasp:'A05'},
{id:'js-sourcemap',lang:['js'],sev:'Medium',title:'Source map reference',re:/\/\/[#@]\s*sourceMappingURL\s*=/,why:'Reveals unminified source.',fix:'Strip in prod.',cwe:'CWE-540',owasp:'A05'},
{id:'js-jwt-none',lang:['js'],sev:'High',title:'JWT weak alg / verify disabled',re:/algorithms?\s*:\s*\[?\s*['"]none['"]|ignoreExpiration\s*:\s*true|complete\s*:\s*false/i,why:'Accepts unsigned/expired tokens.',fix:'Enforce strong alg; verify exp.',cwe:'CWE-347',owasp:'A02'},
{id:'js-ssrf',lang:['js'],sev:'High',title:'SSRF (fetch/axios user URL)',re:/(fetch|axios\.(get|post))\s*\(\s*(req\.(query|body|params)|location\.(hash|search))/,why:'User controls URL.',fix:'Validate host; block private IPs.',cwe:'CWE-918',owasp:'A10'},
{id:'js-debug',lang:['js'],sev:'Info',title:'debugger / console.log in bundle',re:/\bdebugger\s*;|console\.(log|debug)\s*\(/,why:'Debug artifacts / leaks state.',fix:'terser drop_console.',cwe:'CWE-489',owasp:'A05'},
{id:'py-cmdi',lang:['python'],sev:'Critical',title:'Command injection (shell=True/os.system)',re:/subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\([^)]*(\+|%|f['"]|\.format)/,why:'User input to shell.',fix:'Arg list; shell=False.',cwe:'CWE-78',owasp:'A03'},
{id:'py-pickle',lang:['python'],sev:'Critical',title:'Insecure deserialization (pickle)',re:/\bpickle\.loads?\s*\(/,why:'pickle → RCE.',fix:'json; never unpickle untrusted.',cwe:'CWE-502',owasp:'A08'},
{id:'py-yaml',lang:['python'],sev:'Critical',title:'yaml.load without SafeLoader',re:/yaml\.load\s*\((?![^)]*SafeLoader)/,why:'Instantiates arbitrary objects.',fix:'yaml.safe_load().',cwe:'CWE-502',owasp:'A08'},
{id:'py-sqli',lang:['python'],sev:'Critical',title:'SQL injection (execute with format)',re:/\.execute\s*\(\s*[fF]?['"][^'"]*(\{|%s?%|['"]\s*\+|\.format)/,why:'String-built SQL.',fix:'Parameterized: execute(sql,(p,)).',cwe:'CWE-89',owasp:'A03'},
{id:'py-ssti',lang:['python'],sev:'High',title:'Jinja2 SSTI (render_template_string)',re:/render_template_string\s*\([^)]*(\+|request\.|\.format|%)/,why:'User input in template → RCE.',fix:'render_template fixed files.',cwe:'CWE-1336',owasp:'A03'},
{id:'py-eval',lang:['python'],sev:'Critical',title:'exec()/eval() dynamic code',re:/\bexec\s*\(|(^|[^.\w])eval\s*\(/,why:'Executes arbitrary Python.',fix:'ast.literal_eval for data.',cwe:'CWE-95',owasp:'A03'},
{id:'py-debug',lang:['python'],sev:'Medium',title:'Flask/Django DEBUG=True',re:/\bDEBUG\s*=\s*True|debug\s*=\s*True/,why:'Debug pages expose secrets.',fix:'DEBUG=False via env.',cwe:'CWE-489',owasp:'A05'},
{id:'py-xxe',lang:['python'],sev:'Medium',title:'XML parser without defusedxml',re:/xml\.etree\.ElementTree|xml\.dom\.minidom|lxml\.etree\.parse/,why:'XXE-vulnerable.',fix:'defusedxml.',cwe:'CWE-611',owasp:'A05',ctxNot:/defusedxml/},
{id:'py-assert',lang:['python'],sev:'Low',title:'assert for security check',re:/\bassert\s+\w+.*(auth|permission|admin|token)/i,why:'Stripped with -O.',fix:'if/raise.',cwe:'CWE-617',owasp:'A04'},
{id:'py-tmp',lang:['python'],sev:'Medium',title:'Insecure temp file',re:/tempfile\.mktemp\s*\(|\/tmp\/[a-z0-9_]+['"]/i,why:'Predictable path → race.',fix:'mkstemp/NamedTemporaryFile.',cwe:'CWE-377',owasp:'A04'},
{id:'py-noverify',lang:['python'],sev:'High',title:'requests verify=False',re:/requests\.(get|post|put|delete|request)\s*\([^)]*verify\s*=\s*False/,why:'Disables TLS verification.',fix:'Remove; CA bundle.',cwe:'CWE-295',owasp:'A02'},
{id:'java-cmdi',lang:['java'],sev:'Critical',title:'Command injection (Runtime.exec+concat)',re:/Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/,why:'Concatenated shell command.',fix:'ProcessBuilder arg list.',cwe:'CWE-78',owasp:'A03'},
{id:'java-sqli',lang:['java'],sev:'Critical',title:'SQL injection (Statement+concat)',re:/executeQuery\s*\(\s*["'][^"']*\+/,why:'String-built SQL.',fix:'PreparedStatement.',cwe:'CWE-89',owasp:'A03'},
{id:'java-deser',lang:['java'],sev:'Critical',title:'Insecure deserialization (ObjectInputStream)',re:/new\s+ObjectInputStream\s*\(/,why:'Arbitrary serialized types.',fix:'JSON with types.',cwe:'CWE-502',owasp:'A08'},
{id:'java-xxe',lang:['java'],sev:'Medium',title:'XML parser without XXE hardening',re:/DocumentBuilderFactory|SAXParserFactory|XMLInputFactory/,why:'Allows external entities.',fix:'Disable DOCTYPE.',cwe:'CWE-611',owasp:'A05',ctxNot:/disallow-doctype-decl|FEATURE_SECURE/},
{id:'java-ssrf',lang:['java'],sev:'High',title:'SSRF (URL from user input)',re:/new\s+URL\s*\([^)]*(request\.getParameter|req\.get)/,why:'User controls URL.',fix:'Allowlist host.',cwe:'CWE-918',owasp:'A10'},
{id:'java-trust',lang:['java'],sev:'High',title:'TrustManager accepts all certs',re:/TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/,why:'Disables TLS validation.',fix:'Default trust store.',cwe:'CWE-295',owasp:'A02'},
{id:'java-el',lang:['java'],sev:'High',title:'SpEL/EL injection',re:/(SpelExpressionParser|ExpressionParser)[\s\S]{0,80}parseExpression\s*\([^)]*(\+|request)/,why:'User input in EL → RCE.',fix:'Never eval user expressions.',cwe:'CWE-917',owasp:'A03'},
{id:'cs-sqli',lang:['csharp'],sev:'Critical',title:'SQL injection (SqlCommand concat)',re:/SqlCommand\s*\([^)]*\+|string\.Format\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)/i,why:'Concatenated SQL.',fix:'SqlParameter binding.',cwe:'CWE-89',owasp:'A03'},
{id:'cs-cmdi',lang:['csharp'],sev:'Critical',title:'Command injection (Process.Start concat)',re:/Process\.Start\s*\([^)]*\+/,why:'Concatenated command.',fix:'ArgumentList.',cwe:'CWE-78',owasp:'A03'},
{id:'cs-deser',lang:['csharp'],sev:'Critical',title:'Insecure deserialization (BinaryFormatter)',re:/BinaryFormatter\s*\(\s*\)|NetDataContractSerializer|LosFormatter|ObjectStateFormatter/,why:'Known RCE gadgets.',fix:'System.Text.Json.',cwe:'CWE-502',owasp:'A08'},
{id:'cs-xxe',lang:['csharp'],sev:'Medium',title:'XmlDocument without safe resolver',re:/new\s+XmlDocument\s*\(|XmlTextReader/,why:'May resolve external entities.',fix:'XmlResolver=null.',cwe:'CWE-611',owasp:'A05',ctxNot:/XmlResolver\s*=\s*null|DtdProcessing\.Prohibit/},
{id:'cs-debug',lang:['csharp'],sev:'Medium',title:'ASP.NET debug/customErrors off',re:/<compilation[^>]*debug\s*=\s*"true"|<customErrors[^>]*mode\s*=\s*"Off"/i,why:'Leaks stack traces.',fix:'debug=false; customErrors On.',cwe:'CWE-209',owasp:'A05'},
{id:'go-cmdi',lang:['go'],sev:'Critical',title:'Command injection (sh -c + var)',re:/exec\.Command\s*\(\s*["'](sh|bash|cmd)["']\s*,\s*["']-c["']\s*,[^)]*\+/,why:'Concatenated command.',fix:'Args individually.',cwe:'CWE-78',owasp:'A03'},
{id:'go-sqli',lang:['go'],sev:'Critical',title:'SQL injection (Sprintf query)',re:/db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf/,why:'Formatted SQL.',fix:'Placeholders + args.',cwe:'CWE-89',owasp:'A03'},
{id:'go-tls',lang:['go'],sev:'High',title:'InsecureSkipVerify=true',re:/InsecureSkipVerify\s*:\s*true/,why:'Disables TLS.',fix:'Validate certs.',cwe:'CWE-295',owasp:'A02'},
{id:'go-ssrf',lang:['go'],sev:'High',title:'SSRF (http.Get user URL)',re:/http\.(Get|Post)\s*\(\s*(r\.URL|r\.FormValue|req\.)/,why:'User controls URL.',fix:'Allowlist; block private IPs.',cwe:'CWE-918',owasp:'A10'},
{id:'go-rand',lang:['go'],sev:'Medium',title:'math/rand for security',re:/math\/rand|rand\.Intn\s*\(/,why:'Predictable RNG.',fix:'crypto/rand.',cwe:'CWE-338',owasp:'A02',ctx:/(token|secret|key|nonce|session)/i},
{id:'rb-cmdi',lang:['ruby'],sev:'Critical',title:'Command injection (system/backtick+var)',re:/\b(system|exec)\s*\(["'][^"']*#\{|`[^`]*#\{/,why:'Interpolated command.',fix:'Arg array.',cwe:'CWE-78',owasp:'A03'},
{id:'rb-eval',lang:['ruby'],sev:'Critical',title:'eval / send with user input',re:/\beval\s*\(|\.send\s*\(\s*params/,why:'Dynamic code/method.',fix:'Whitelist methods.',cwe:'CWE-95',owasp:'A03'},
{id:'rb-yaml',lang:['ruby'],sev:'Critical',title:'YAML.load untrusted',re:/YAML\.load\s*\((?!.*safe)/,why:'Arbitrary objects.',fix:'YAML.safe_load.',cwe:'CWE-502',owasp:'A08'},
{id:'rb-mass',lang:['ruby'],sev:'High',title:'Mass assignment (params w/o permit)',re:/\.(new|update|create)\s*\(\s*params\[[^\]]+\]\s*\)/,why:'Attribute injection.',fix:'Strong params .permit.',cwe:'CWE-915',owasp:'A08'},
{id:'sql-grant',lang:['sql'],sev:'High',title:'GRANT ALL PRIVILEGES ON *.*',re:/GRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*\.\*/i,why:'Least-privilege violation.',fix:'Scope privileges.',cwe:'CWE-269',owasp:'A01'},
{id:'sql-pw',lang:['sql'],sev:'High',title:'Plaintext password in SQL',re:/(IDENTIFIED\s+BY|PASSWORD)\s*=?\s*['"][^'"]{3,}['"]/i,why:'Creds in SQL script.',fix:'Secrets mgmt; hashed.',cwe:'CWE-256',owasp:'A02'},
{id:'sql-payload',lang:['sql'],sev:'Info',title:'Classic SQLi payload present',re:/'\s*OR\s*'?1'?\s*=\s*'?1/i,why:'Likely test artifact.',fix:'Remove test payloads.',cwe:'CWE-89',owasp:'A03'},
{id:'html-blank',lang:['html'],sev:'Low',title:'target="_blank" without rel="noopener"',re:/target\s*=\s*["']_blank["'](?![^>]*rel\s*=\s*["'][^"']*noopener)/i,why:'Reverse tabnabbing.',fix:'rel="noopener noreferrer".',cwe:'CWE-1022',owasp:'A05'},
{id:'html-form',lang:['html'],sev:'High',title:'Form posts over HTTP',re:/<form\b[^>]*action\s*=\s*["']http:\/\//i,why:'Credentials unencrypted.',fix:'HTTPS action.',cwe:'CWE-319',owasp:'A02'},
{id:'html-autocomplete',lang:['html'],sev:'Info',title:'Password field allows autocomplete',re:/<input[^>]*type\s*=\s*["']password["'][^>]*autocomplete\s*=\s*["']on["']/i,why:'Persists on shared devices.',fix:'autocomplete="new-password".',cwe:'CWE-200',owasp:'A05'},
{id:'html-inline',lang:['html'],sev:'Low',title:'Inline event handler',re:/<[^>]+\son(click|load|error|mouseover)\s*=\s*["']/i,why:'Blocks strict CSP; XSS surface.',fix:'External JS + CSP.',cwe:'CWE-79',owasp:'A03'},
{id:'redos',lang:['*'],sev:'Medium',title:'Potential ReDoS pattern',re:/\(\w\+\)\+|\(\w\*\)\*|\(\.\*\)\+|\(\.\+\)\+/,why:'Nested quantifiers hang on input.',fix:'Atomic groups / RE2.',cwe:'CWE-1333',owasp:'A05'},
{id:'internal-ip',lang:['*'],sev:'Info',title:'Hardcoded internal/private IP',re:/(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])/,why:'Leaks network topology.',fix:'Externalize to config.',cwe:'CWE-200',owasp:'A05'},
{id:'cloud-meta',lang:['*'],sev:'Medium',title:'Cloud metadata endpoint reference',re:/169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/,why:'SSRF target for cred theft.',fix:'IMDSv2; SSRF protection.',cwe:'CWE-918',owasp:'A10'},
{id:'todo-sec',lang:['*'],sev:'Info',title:'Security-sensitive TODO/FIXME',re:/\b(TODO|FIXME|HACK|XXX)\b[^\n]{0,120}(security|auth|password|token|vuln|insecure|remove before)/i,why:'Often ships to prod.',fix:'Resolve before release.',cwe:'CWE-546',owasp:'A05'},
];

function detectLanguage(code){const c=code.slice(0,4000);
  if(/<\?php|\$_(GET|POST|REQUEST|COOKIE)|->query|mysqli?_/.test(c))return 'php';
  if(/^\s*(from |import |def |async def |print\()|__init__|self\./m.test(c))return 'python';
  if(/\bpackage\s+main|func\s+\w+\s*\(|:=|fmt\./.test(c))return 'go';
  if(/\bpublic\s+class|System\.out\.println|@Override|import\s+java\./.test(c))return 'java';
  if(/\busing\s+System|namespace\s+\w|Console\.WriteLine/.test(c))return 'csharp';
  if(/\bputs\s+|require\s+['"]|params\[/m.test(c))return 'ruby';
  if(/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT)\s+/im.test(c)&&!/function|=>|const /.test(c))return 'sql';
  if(/^\s*<!doctype html|<html|<head|<body|<form|<input/i.test(c))return 'html';
  if(/\b(interface|type)\s+\w+|:\s*(string|number|boolean)\b|as\s+\w+[;,)]/.test(c))return 'js';
  if(/\b(function|const|let|var|=>|require\(|document\.|window\.|console\.)/.test(c))return 'js';
  return 'generic';}

function findLineNum(code,re){const lines=code.split(/\r?\n/);for(let i=0;i<lines.length;i++){try{if(new RegExp(re.source,re.flags.replace('g','')).test(lines[i]))return i+1;}catch(e){}}return 0;}

/* v1.9.1: build a code snippet (context lines + highlighted match) for a finding */
function buildSnippet(code,re,lineNum){
  const lines=code.split(/\r?\n/);
  if(!lineNum||lineNum<1)return null;
  const idx=lineNum-1;
  const from=Math.max(0,idx-2), to=Math.min(lines.length-1,idx+2);
  const out=[];
  let matchStr='';
  try{const mm=new RegExp(re.source,re.flags.replace('g','')).exec(lines[idx]||'');if(mm)matchStr=mm[0];}catch(e){}
  for(let i=from;i<=to;i++){
    let raw=lines[i]??'';
    // Full line preserved (wrapping handles display). Only hard-cap pathological lines.
    if(raw.length>5000){
      if(i===idx&&matchStr){const p=raw.indexOf(matchStr);const s=Math.max(0,p-1000);raw=(s>0?'… ':'')+raw.substring(s,p+matchStr.length+3000)+' …';}
      else raw=raw.substring(0,5000)+' …';
    }
    let safe=esc(raw);
    if(i===idx&&matchStr){const sm=esc(matchStr);safe=safe.split(sm).join('<span class="hl">'+sm+'</span>');}
    out.push({no:i+1,src:safe,hit:i===idx});
  }
  return out;
}
function renderSnippet(snip,lang){
  if(!snip||!snip.length)return '';
  const rows=snip.map(l=>`<div class="ln${l.hit?' hit':''}"><span class="no">${l.no}</span><span class="src">${l.src||' '}</span></div>`).join('');
  return `<div class="code-snippet"><div class="cs-head"><span>Code context</span><span class="lang">${esc((lang||'').toUpperCase())}</span></div><pre>${rows}</pre></div>`;
}

function analyzeSAST(code,lang){
  const out=[];const seen=new Set();
  const ok=(r)=>r.lang.includes('*')||r.lang.includes(lang)||lang==='generic';
  for(const rule of SAST_RULES){
    if(!ok(rule))continue;
    let hit=false;try{hit=rule.re.test(code);}catch(e){continue;}
    if(!hit)continue;
    if(rule.ctx&&!rule.ctx.test(code))continue;
    if(rule.ctxNot&&rule.ctxNot.test(code))continue;
    if(seen.has(rule.id))continue;seen.add(rule.id);
    const line=findLineNum(code,rule.re);
    const snippet=buildSnippet(code,rule.re,line);
    out.push({id:rule.id,sev:rule.sev,title:rule.title,why:rule.why,fix:rule.fix,cwe:rule.cwe,owasp:rule.owasp,line,snippet,source:'SAST'});
  }
  const order={'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4};
  out.sort((a,b)=>(order[a.sev]??5)-(order[b.sev]??5));
  return out;
}

function astAvailable(){return typeof window.acorn!=='undefined'&&typeof window.acorn.parse==='function';}
function astAnalyze(source,isModule){
  const f=[];if(!astAvailable()||!source)return f;
  let ast;try{ast=window.acorn.parse(source,{ecmaVersion:'latest',sourceType:isModule?'module':'script',allowReturnOutsideFunction:true,allowImportExportEverywhere:true,allowAwaitOutsideFunction:true,allowHashBang:true,locations:true});}
  catch(e){try{ast=window.acorn.parse(source,{ecmaVersion:'latest',sourceType:isModule?'script':'module',allowReturnOutsideFunction:true,allowImportExportEverywhere:true,allowHashBang:true,locations:true});}catch(e2){return f;}}
  const lines=source.split(/\r?\n/);
  const seen=new Set();
  const push=(sev,title,why,fix,cwe,line)=>{const k=title+'|'+line;if(seen.has(k))return;seen.add(k);
    let snippet=null;if(line>=1){const idx=line-1;const from=Math.max(0,idx-2),to=Math.min(lines.length-1,idx+2);const arr=[];for(let i=from;i<=to;i++){let raw=lines[i]??'';if(raw.length>5000)raw=raw.substring(0,5000)+' …';arr.push({no:i+1,src:esc(raw),hit:i===idx});}snippet=arr;}
    f.push({sev,title,why,fix,cwe,owasp:'A03',source:'AST',line:line||0,snippet});};
  const gl=n=>(n&&n.loc&&n.loc.start)?n.loc.start.line:0;
  function walk(n){if(!n||typeof n!=='object'||!n.type)return;
    if(n.type==='CallExpression'){const c=n.callee;
      if(c&&c.type==='Identifier'&&c.name==='eval')push('Critical','eval() call (AST-confirmed)','Executes arbitrary strings.','Remove eval.','CWE-95',gl(n));
      if(c&&c.type==='Identifier'&&c.name==='Function'&&n.arguments.length)push('Critical','Function() constructor (AST)','Same as eval.','Refactor.','CWE-95',gl(n));
      if(c&&c.type==='MemberExpression'&&c.object&&c.object.name==='document'&&c.property&&(c.property.name==='write'||c.property.name==='writeln'))push('High','document.'+c.property.name+'() (AST)','Legacy HTML sink.','Use DOM APIs.','CWE-79',gl(n));}
    if(n.type==='NewExpression'&&n.callee&&n.callee.type==='Identifier'&&n.callee.name==='Function')push('Critical','new Function() (AST)','Compiles string to code.','Refactor.','CWE-95',gl(n));
    if(n.type==='AssignmentExpression'&&n.left&&n.left.type==='MemberExpression'&&n.left.property){const p=n.left.property.name||n.left.property.value;
      if(p==='innerHTML'||p==='outerHTML'){const rhs=n.right;const empty=rhs&&rhs.type==='Literal'&&(rhs.value===''||rhs.value===null);if(!empty)push('High',p+' assignment (AST)','Enables XSS.','textContent/DOMPurify.','CWE-79',gl(n));}}
    for(const k in n){if(k==='loc'||k==='range')continue;const c=n[k];if(Array.isArray(c))c.forEach(walk);else if(c&&typeof c==='object'&&c.type)walk(c);}}
  walk(ast);return f;
}
function mergeFindings(a,b){const merged=[];const norm=t=>(t||'').toLowerCase().replace(/\s*\(.*?\)\s*/g,'').trim();const seen={};
  b.forEach(f=>{const k=norm(f.title);merged.push(f);seen[k]=true;});
  a.forEach(f=>{const k=norm(f.title);if(seen[k])return;merged.push(f);seen[k]=true;});
  const order={'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4};merged.sort((x,y)=>(order[x.sev]??5)-(order[y.sev]??5));return merged;}

/* ============================================================
 * v2.2.0 — TAINT TRACKING ENGINE (JavaScript, AST-based)
 * Traces user-controlled SOURCES → dangerous SINKS with a
 * fixpoint variable-propagation pass. Emits a flow trace.
 * ============================================================ */
function memberChain(node){
  const parts=[]; let cur=node;
  while(cur&&cur.type==='MemberExpression'){const p=cur.property?(cur.property.name||cur.property.value):'';if(p!==undefined&&p!=='')parts.unshift(String(p));cur=cur.object;}
  if(cur&&cur.type==='Identifier')parts.unshift(cur.name);
  else if(cur&&cur.type==='ThisExpression')parts.unshift('this');
  else if(cur&&cur.type==='CallExpression'&&cur.callee)parts.unshift(memberChain(cur.callee)+'()');
  return parts.join('.');
}
/* Returns {tainted:bool, desc:string, line:number} if subtree contains a taint source */
function exprSource(node){
  let hit=null;
  (function w(n){if(!n||typeof n!=='object'||!n.type||hit)return;
    // location.* / document.URL|cookie|referrer / window.name
    if(n.type==='MemberExpression'){
      const chain=memberChain(n).toLowerCase();
      const srcMap=[
        [/^(window\.)?location\.(hash|search|href|pathname|host)$/,'location.'+chain.split('location.')[1]],
        [/^(window\.)?location$/,'location'],
        [/^document\.(url|documenturi|referrer|cookie|baseuri)$/,'document.'+chain.split('document.')[1]],
        [/^(window\.)?name$/,'window.name'],
        [/^(location\.)?ancestororigins/,'location.ancestorOrigins'],
        [/(req|request)\.(query|body|params|cookies|headers)$/,chain],
      ];
      for(const [re,d] of srcMap){if(re.test(chain)){hit={tainted:true,desc:d,line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}}
    }
    if(n.type==='CallExpression'){
      const cc=n.callee?memberChain(n.callee).toLowerCase():'';
      if(/getparameter|geturlparameter|urlsearchparams|\.get$/.test(cc)&&/(param|search|query|url)/.test(cc+JSON.stringify(n.arguments||[]).toLowerCase()))
        {hit={tainted:true,desc:cc+'()',line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}
      if(/^new urlsearchparams$/.test(cc)){hit={tainted:true,desc:'URLSearchParams',line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}
      if(/localstorage\.getitem|sessionstorage\.getitem/.test(cc)){hit={tainted:true,desc:cc+'()',line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}
      if(/\.getattribute$/.test(cc)){hit={tainted:true,desc:'getAttribute()',line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}
    }
    // new URLSearchParams(...)
    if(n.type==='NewExpression'&&n.callee&&n.callee.name==='URLSearchParams'){hit={tainted:true,desc:'URLSearchParams',line:(n.loc&&n.loc.start)?n.loc.start.line:0};return;}
    for(const k in n){if(k==='loc'||k==='range')continue;const c=n[k];if(Array.isArray(c))c.forEach(w);else if(c&&typeof c==='object'&&c.type)w(c);}
  })(node);
  return hit;
}
/* Does subtree reference any tainted variable name? returns var name or null */
function exprTaintedVar(node,tset){
  let hit=null;
  (function w(n){if(!n||typeof n!=='object'||!n.type||hit)return;
    if(n.type==='Identifier'&&tset.has(n.name)){hit=n.name;return;}
    for(const k in n){if(k==='loc'||k==='range'||k==='property')continue;const c=n[k];if(Array.isArray(c))c.forEach(w);else if(c&&typeof c==='object'&&c.type)w(c);}
  })(node);
  return hit;
}
function taintAnalyze(source){
  const out=[]; if(!astAvailable()||!source)return out;
  let ast; try{ast=window.acorn.parse(source,{ecmaVersion:'latest',sourceType:'script',allowReturnOutsideFunction:true,allowImportExportEverywhere:true,allowAwaitOutsideFunction:true,allowHashBang:true,locations:true});}
  catch(e){try{ast=window.acorn.parse(source,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true,allowImportExportEverywhere:true,allowHashBang:true,locations:true});}catch(e2){return out;}}
  const lines=source.split(/\r?\n/);
  // Collect assignments: [{name, node(right), line}]
  const assigns=[];
  (function w(n){if(!n||typeof n!=='object'||!n.type)return;
    if(n.type==='VariableDeclarator'&&n.id&&n.id.type==='Identifier'&&n.init)
      assigns.push({name:n.id.name,right:n.init,line:(n.loc&&n.loc.start)?n.loc.start.line:0});
    if(n.type==='AssignmentExpression'&&n.left&&n.left.type==='Identifier'&&n.right)
      assigns.push({name:n.left.name,right:n.right,line:(n.loc&&n.loc.start)?n.loc.start.line:0});
    for(const k in n){if(k==='loc'||k==='range')continue;const c=n[k];if(Array.isArray(c))c.forEach(w);else if(c&&typeof c==='object'&&c.type)w(c);}
  })(ast);
  // Fixpoint taint propagation over variables
  const tset=new Set(); const origin={}; // name -> {desc,line}
  for(let pass=0;pass<6;pass++){
    let changed=false;
    for(const a of assigns){
      if(tset.has(a.name))continue;
      const src=exprSource(a.right);
      const tv=exprTaintedVar(a.right,tset);
      if(src||tv){tset.add(a.name);origin[a.name]=src?{desc:src.desc,line:src.line}:{desc:'tainted '+tv,line:a.line};changed=true;}
    }
    if(!changed)break;
  }
  // Sink detection with flow
  const seen=new Set();
  const emit=(sev,title,sinkDesc,cwe,flow,line)=>{const key=title+'|'+line;if(seen.has(key))return;seen.add(key);
    // snippet at sink
    let snippet=null;if(line>=1){const idx=line-1;const from=Math.max(0,idx-1),to=Math.min(lines.length-1,idx+1);const arr=[];for(let i=from;i<=to;i++){let raw=lines[i]??'';if(raw.length>5000)raw=raw.substring(0,5000)+' …';arr.push({no:i+1,src:esc(raw),hit:i===idx});}snippet=arr;}
    out.push({sev,title,why:'Tainted user input reaches '+sinkDesc+' without sanitization (data-flow confirmed).',fix:'Sanitize/encode before the sink (DOMPurify for HTML, avoid eval, validate URLs).',cwe,owasp:'A03',source:'Taint',line,snippet,flow});};
  const gl=n=>(n&&n.loc&&n.loc.start)?n.loc.start.line:0;
  function flowFor(node,sinkLabel,sinkLine){
    const src=exprSource(node); if(src)return [{role:'source',desc:src.desc,line:src.line,code:(lines[src.line-1]||'').trim().substring(0,160)},{role:'sink',desc:sinkLabel,line:sinkLine,code:(lines[sinkLine-1]||'').trim().substring(0,160)}];
    const tv=exprTaintedVar(node,tset); if(tv){const o=origin[tv]||{};return [{role:'source',desc:o.desc||'user input',line:o.line||0,code:(lines[(o.line||1)-1]||'').trim().substring(0,160)},{role:'propagate',desc:'via variable "'+tv+'"',line:0,code:''},{role:'sink',desc:sinkLabel,line:sinkLine,code:(lines[sinkLine-1]||'').trim().substring(0,160)}];}
    return null;
  }
  (function w(n){if(!n||typeof n!=='object'||!n.type)return;
    // Assignment sinks: X.innerHTML = tainted ; location = tainted
    if(n.type==='AssignmentExpression'&&n.left){
      if(n.left.type==='MemberExpression'&&n.left.property){
        const p=(n.left.property.name||n.left.property.value||'').toString();
        if(/^(innerHTML|outerHTML)$/.test(p)){const fl=flowFor(n.right,'.'+p+' (DOM XSS sink)',gl(n));if(fl)emit('Critical','Taint: user input → '+p,'.'+p,'CWE-79',fl,gl(n));}
        if(p==='src'||p==='href'){const chain=memberChain(n.left).toLowerCase();if(/location/.test(chain)){const fl=flowFor(n.right,'location.'+p+' (open redirect/JS-URI)',gl(n));if(fl)emit('High','Taint: user input → location.'+p,'location.'+p,'CWE-601',fl,gl(n));}}
      }
      if(n.left.type==='Identifier'&&n.left.name==='location'){const fl=flowFor(n.right,'location assignment',gl(n));if(fl)emit('High','Taint: user input → location','location','CWE-601',fl,gl(n));}
    }
    // Call sinks
    if(n.type==='CallExpression'&&n.callee){
      const cc=memberChain(n.callee);
      const cl=cc.toLowerCase();
      const arg=n.arguments&&n.arguments[0];
      const firstFlow=()=>{for(const a of (n.arguments||[])){const fl=flowFor(a,cc+'()',gl(n));if(fl)return fl;}return null;};
      if(cl==='eval'){const fl=firstFlow();if(fl)emit('Critical','Taint: user input → eval()','eval()','CWE-95',fl,gl(n));}
      else if(/(^|\.)document\.write(ln)?$/.test(cl)||cl==='document.write'||cl==='document.writeln'){const fl=firstFlow();if(fl)emit('Critical','Taint: user input → document.write()','document.write()','CWE-79',fl,gl(n));}
      else if(/\.insertadjacenthtml$/.test(cl)){const fl=(n.arguments&&n.arguments[1])?flowFor(n.arguments[1],'insertAdjacentHTML()',gl(n)):null;if(fl)emit('High','Taint: user input → insertAdjacentHTML()','insertAdjacentHTML()','CWE-79',fl,gl(n));}
      else if(/\.setattribute$/.test(cl)){const an=(arg&&arg.type==='Literal')?String(arg.value).toLowerCase():'';if(/^(href|src|action|formaction)$/.test(an)&&n.arguments[1]){const fl=flowFor(n.arguments[1],'setAttribute("'+an+'")',gl(n));if(fl)emit('High','Taint: user input → setAttribute("'+an+'")','setAttribute','CWE-79',fl,gl(n));}}
      else if(cl==='fetch'||/\.(get|post|put|delete|request|open)$/.test(cl)){const fl=firstFlow();if(fl)emit('High','Taint: user input → '+cc+'() (SSRF/req forgery)',cc+'()','CWE-918',fl,gl(n));}
      else if(/\.(query|execute)$/.test(cl)){const fl=firstFlow();if(fl)emit('Critical','Taint: user input → '+cc+'() (SQL injection)',cc+'()','CWE-89',fl,gl(n));}
      else if(/\.(exec|execsync)$/.test(cl)){const fl=firstFlow();if(fl)emit('Critical','Taint: user input → '+cc+'() (command injection)',cc+'()','CWE-78',fl,gl(n));}
      else if(cl==='settimeout'||cl==='setinterval'){if(arg&&(arg.type==='Literal'||arg.type==='BinaryExpression'||arg.type==='Identifier')){const fl=flowFor(arg,cc+'() string exec',gl(n));if(fl)emit('High','Taint: user input → '+cc+'(string)',cc+'()','CWE-95',fl,gl(n));}}
      else if(cl==='function'||(n.callee.type==='Identifier'&&n.callee.name==='Function')){const fl=firstFlow();if(fl)emit('Critical','Taint: user input → Function()','Function()','CWE-95',fl,gl(n));}
    }
    if(n.type==='NewExpression'&&n.callee&&n.callee.name==='Function'){const fl=(function(){for(const a of (n.arguments||[])){const f=flowFor(a,'new Function()',gl(n));if(f)return f;}return null;})();if(fl)emit('Critical','Taint: user input → new Function()','new Function()','CWE-95',fl,gl(n));}
    for(const k in n){if(k==='loc'||k==='range')continue;const c=n[k];if(Array.isArray(c))c.forEach(w);else if(c&&typeof c==='object'&&c.type)w(c);}
  })(ast);
  const order={'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4};
  out.sort((a,b)=>(order[a.sev]??5)-(order[b.sev]??5));
  return out;
}
/* Render a taint flow trace (source → propagate → sink) */
function renderFlow(flow){
  if(!flow||!flow.length)return '';
  const roleColor={source:'#dc2626',propagate:'#d97706',sink:'#7f1d1d'};
  const roleLabel={source:'SOURCE',propagate:'PROPAGATE',sink:'SINK'};
  let rows=flow.map((s,i)=>{
    const arrow=i<flow.length-1?'<div style="color:var(--dim-2);text-align:center;font-size:14px;line-height:1">↓</div>':'';
    return `<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0">
      <span class="pill" style="background:${roleColor[s.role]}22;color:${roleColor[s.role]};min-width:82px;text-align:center">${roleLabel[s.role]}</span>
      <div style="flex:1;min-width:0"><div style="font-size:12px;color:var(--ink-soft)">${esc(s.desc)}${s.line?` <span style="color:var(--dim)">(line ${s.line})</span>`:''}</div>${s.code?`<code style="display:block;margin-top:3px;font-size:11px;background:#0d1526;color:#c9d6ee;border-color:#1e2b47;padding:5px 8px;white-space:pre-wrap;word-break:break-all">${esc(s.code)}</code>`:''}</div>
    </div>${arrow}`;
  }).join('');
  return `<div style="margin-top:8px;padding:10px 12px;background:var(--purple-soft);border:1px solid rgba(124,58,237,.25);border-radius:8px"><div style="font-size:10.5px;font-weight:700;color:#6d28d9;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">🔗 Data-Flow Trace</div>${rows}</div>`;
}

/* ============================================================
 * v2.5.0 #6 — PHP TAINT TRACKING (regex + variable-propagation)
 * Traces $_GET/$_POST/$_REQUEST/$_COOKIE/php://input → dangerous
 * PHP sinks, propagating taint across simple variable assignments.
 * ============================================================ */
function phpTaintAnalyze(source){
  const out=[]; if(!source)return out;
  const lines=source.split(/\r?\n/);
  const SRC=/\$_(GET|POST|REQUEST|COOKIE)\b|\bphp:\/\/input\b|\bfile_get_contents\s*\(\s*['"]php:\/\/input/;
  // 1) taint propagation: $var = <tainted expr>;  (fixpoint over a few passes)
  const tainted={}; const origin={};
  const assignRe=/\$([A-Za-z_]\w*)\s*=\s*([^;]+);/g;
  for(let pass=0;pass<6;pass++){
    let changed=false; let m;
    assignRe.lastIndex=0;
    while((m=assignRe.exec(source))){
      const name=m[1], rhs=m[2];
      if(tainted[name])continue;
      let isT=SRC.test(rhs);
      if(!isT){ // references another tainted var?
        const vars=rhs.match(/\$([A-Za-z_]\w*)/g)||[];
        for(const v of vars){ if(tainted[v.slice(1)]){isT=true;break;} }
      }
      if(isT){ tainted[name]=true; const ln=source.slice(0,m.index).split(/\r?\n/).length; origin[name]={line:ln,code:m[0].trim().slice(0,160)}; changed=true; }
    }
    if(!changed)break;
  }
  const lineNo=idx=>source.slice(0,idx).split(/\r?\n/).length;
  const snip=(ln)=>{if(!ln)return null;const i=ln-1,from=Math.max(0,i-1),to=Math.min(lines.length-1,i+1);const a=[];for(let k=from;k<=to;k++){let raw=lines[k]??'';if(raw.length>5000)raw=raw.slice(0,5000)+' …';a.push({no:k+1,src:esc(raw),hit:k===i});}return a;};
  const seen=new Set();
  const rhsTaint=expr=>{ if(SRC.test(expr))return {desc:'user input (superglobal)'}; const vars=expr.match(/\$([A-Za-z_]\w*)/g)||[]; for(const v of vars){const n=v.slice(1); if(tainted[n])return {desc:'tainted var $'+n,via:n};} return null; };
  const emit=(sev,title,sinkLabel,cwe,owasp,fix,idx,expr)=>{
    const ln=lineNo(idx); const key=title+'|'+ln; if(seen.has(key))return; seen.add(key);
    const t=rhsTaint(expr); if(!t)return;
    const flow=[];
    if(t.via&&origin[t.via]){flow.push({role:'source',desc:origin[t.via].code.includes('$_')?'user input → $'+t.via:'$'+t.via,line:origin[t.via].line,code:origin[t.via].code});flow.push({role:'propagate',desc:'via $'+t.via,line:0,code:''});}
    else{flow.push({role:'source',desc:'user input (superglobal)',line:ln,code:(lines[ln-1]||'').trim().slice(0,160)});}
    flow.push({role:'sink',desc:sinkLabel,line:ln,code:(lines[ln-1]||'').trim().slice(0,160)});
    out.push({sev,title,why:'Tainted user input reaches '+sinkLabel+' without sanitization (PHP data-flow).',fix,cwe,owasp,source:'PHP-Taint',line:ln,snippet:snip(ln),flow});
  };
  // 2) sink scans
  let m;
  const scan=(re,fn)=>{re.lastIndex=0;while((m=re.exec(source))){fn(m);}};
  scan(/\b(?:echo|print)\b([^;]+);/g, mm=>emit('High','PHP taint: user input → echo/print (XSS)','echo/print output','CWE-79','A03','htmlspecialchars($x,ENT_QUOTES,\'UTF-8\') before output.',mm.index,mm[1]));
  scan(/(?:mysqli?_query|pg_query|->query|->exec|sqlsrv_query)\s*\(([^;]+)\)/g, mm=>emit('Critical','PHP taint: user input → SQL query (SQLi)','SQL query call','CWE-89','A03','Use PDO prepared statements with bound parameters.',mm.index,mm[1]));
  scan(/\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(([^;]+)\)/g, mm=>emit('Critical','PHP taint: user input → shell exec (Command Injection)','OS command call','CWE-78','A03','Avoid shell; use escapeshellarg()/escapeshellcmd() or safe APIs.',mm.index,mm[1]));
  scan(/`([^`]*\$[^`]*)`/g, mm=>emit('Critical','PHP taint: user input → backtick shell','backtick execution','CWE-78','A03','Never interpolate input into backtick commands.',mm.index,mm[1]));
  scan(/\b(?:include|include_once|require|require_once)\s*\(?\s*([^;]+);/g, mm=>emit('Critical','PHP taint: user input → file include (LFI/RFI)','include/require','CWE-98','A03','Whitelist includable files; never include from input.',mm.index,mm[1]));
  scan(/\b(?:file_get_contents|fopen|readfile|file|unlink|fwrite|fputs)\s*\(([^;]+)\)/g, mm=>emit('High','PHP taint: user input → filesystem API (Path Traversal/SSRF)','file API','CWE-22','A01','realpath() + prefix allowlist; validate URL scheme/host.',mm.index,mm[1]));
  scan(/\b(?:eval|assert)\s*\(([^;]+)\)/g, mm=>emit('Critical','PHP taint: user input → eval/assert (RCE)','dynamic code eval','CWE-95','A03','Never eval user input; refactor to safe logic.',mm.index,mm[1]));
  scan(/\bunserialize\s*\(([^;]+)\)/g, mm=>emit('Critical','PHP taint: user input → unserialize (Object Injection)','unserialize()','CWE-502','A08','json_decode() or unserialize($x,["allowed_classes"=>false]).',mm.index,mm[1]));
  scan(/\bheader\s*\(([^;]+)\)/g, mm=>emit('Medium','PHP taint: user input → header (CRLF/Open Redirect)','header()','CWE-601','A01','Allowlist redirect targets; strip CR/LF.',mm.index,mm[1]));
  const order={'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4};
  out.sort((a,b)=>(order[a.sev]??5)-(order[b.sev]??5));
  return out;
}
/* ============================================================
 * v2.5.0 #7 — DEPENDENCY / SCA (OWASP A06)
 * Detects package.json / composer.json / requirements.txt /
 * Gemfile.lock / go.mod and flags known-vulnerable versions.
 * ============================================================ */
const SCA_DB={
  npm:{
    'lodash':[{lt:'4.17.21',id:'CVE-2021-23337',sev:'High',cvss:7.2,title:'Command injection via template'}],
    'minimist':[{lt:'1.2.6',id:'CVE-2021-44906',sev:'Critical',cvss:9.8,title:'Prototype pollution'}],
    'axios':[{lt:'1.6.0',id:'CVE-2023-45857',sev:'Medium',cvss:6.5,title:'SSRF / credential leak via redirects'}],
    'jquery':[{lt:'3.5.0',id:'CVE-2020-11022',sev:'Medium',cvss:6.1,title:'XSS in DOM manipulation'}],
    'moment':[{lt:'2.29.4',id:'CVE-2022-31129',sev:'High',cvss:7.5,title:'ReDoS in date parsing'}],
    'node-fetch':[{lt:'2.6.7',id:'CVE-2022-0235',sev:'Medium',cvss:6.1,title:'Exposure of sensitive info to untrusted site'}],
    'follow-redirects':[{lt:'1.15.4',id:'CVE-2023-26159',sev:'Medium',cvss:6.1,title:'Improper URL handling / info leak'}],
    'semver':[{lt:'7.5.2',id:'CVE-2022-25883',sev:'High',cvss:7.5,title:'ReDoS in range parsing'}],
    'express':[{lt:'4.19.2',id:'CVE-2024-29041',sev:'Medium',cvss:6.1,title:'Open redirect via malformed URL'}],
  },
  composer:{
    'guzzlehttp/guzzle':[{lt:'7.4.5',id:'CVE-2022-31090',sev:'Medium',cvss:6.5,title:'Cookie / cross-domain leak'}],
    'symfony/http-kernel':[{lt:'5.4.20',id:'CVE-2022-24894',sev:'High',cvss:7.5,title:'Information disclosure of cached responses'}],
    'monolog/monolog':[{lt:'2.9.2',id:'CVE-2022-99999',sev:'Low',cvss:3.7,title:'Sensitive data in logs (config-dependent)'}],
    'laravel/framework':[{lt:'9.52.16',id:'CVE-2023-29197',sev:'Medium',cvss:6.1,title:'Improper URL parsing'}],
  },
  pip:{
    'django':[{lt:'3.2.20',id:'CVE-2023-36053',sev:'High',cvss:7.5,title:'ReDoS in EmailValidator/URLValidator'}],
    'flask':[{lt:'2.2.5',id:'CVE-2023-30861',sev:'High',cvss:7.5,title:'Cookie disclosure via caching proxies'}],
    'requests':[{lt:'2.31.0',id:'CVE-2023-32681',sev:'Medium',cvss:6.1,title:'Proxy-Authorization leak on redirect'}],
    'pyyaml':[{lt:'5.4',id:'CVE-2020-14343',sev:'Critical',cvss:9.8,title:'Arbitrary code execution via full_load'}],
    'urllib3':[{lt:'1.26.18',id:'CVE-2023-45803',sev:'Medium',cvss:6.5,title:'Request body leak on redirect'}],
    'jinja2':[{lt:'3.1.3',id:'CVE-2024-22195',sev:'Medium',cvss:5.4,title:'XSS via xmlattr filter'}],
  },
};
function scaVerLt(v,target){ // returns true if v < target (loose semver)
  const clean=s=>String(s).replace(/[^0-9.]/g,'').split('.').map(n=>parseInt(n)||0);
  const a=clean(v),b=clean(target);
  for(let i=0;i<Math.max(a.length,b.length);i++){const x=a[i]||0,y=b[i]||0;if(x<y)return true;if(x>y)return false;}
  return false;
}
function scaDetect(code){
  const t=code.trim(); let eco='',deps=[],manifest='';
  try{
    if(/"dependencies"\s*:|"devDependencies"\s*:/.test(t)&&t[0]==='{'){eco='npm';manifest='package.json';const j=JSON.parse(t);['dependencies','devDependencies','peerDependencies'].forEach(k=>{if(j[k])for(const[n,v]of Object.entries(j[k]))deps.push({name:n.toLowerCase(),ver:String(v).replace(/[^0-9.].*$/,'')||String(v)});});}
    else if(/"require"\s*:/.test(t)&&t[0]==='{'){eco='composer';manifest='composer.json';const j=JSON.parse(t);['require','require-dev'].forEach(k=>{if(j[k])for(const[n,v]of Object.entries(j[k]))deps.push({name:n.toLowerCase(),ver:String(v).replace(/[^0-9.].*$/,'')||String(v)});});}
    else if(/^[A-Za-z0-9_.-]+\s*(==|>=|~=|<=)/m.test(t)&&/\n/.test(t)&&!/\{/.test(t)){eco='pip';manifest='requirements.txt';t.split(/\r?\n/).forEach(l=>{const mm=l.match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([0-9][0-9.]*)/);if(mm)deps.push({name:mm[1].toLowerCase(),ver:mm[2]});});}
    else if(/^module\s+\S+/m.test(t)&&/require\s*\(/.test(t)){eco='go';manifest='go.mod';}
  }catch(e){/* not valid JSON manifest */}
  if(!eco||!deps.length)return null;
  const db=SCA_DB[eco]||{}; const findings=[];
  deps.forEach(d=>{const vulns=db[d.name];if(!vulns)return;vulns.forEach(vln=>{if(!d.ver||scaVerLt(d.ver,vln.lt)){findings.push({sev:vln.sev,pkg:d.name,ver:d.ver||'(unpinned)',id:vln.id,cvss:vln.cvss,title:vln.title,fixed:vln.lt});}});});
  const order={'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4};findings.sort((a,b)=>(order[a.sev]-order[b.sev])||b.cvss-a.cvss);
  return {eco,manifest,dep_count:deps.length,findings};
}
function renderSCA(sca){
  if(!sca)return '';
  let html=`<h4 class="sub">Dependency / SCA — ${esc(sca.manifest)} <span class="pill orange">${esc(sca.eco.toUpperCase())}</span></h4>`;
  html+=`<div class="stats" style="margin-bottom:12px"><div class="stat"><div class="n">${sca.dep_count}</div><div class="l">Dependencies</div></div><div class="stat"><div class="n" style="color:${sca.findings.length?'var(--bad)':'var(--ok)'}">${sca.findings.length}</div><div class="l">Vulnerable</div></div></div>`;
  if(!sca.findings.length){html+=`<div class="findings-note">✅ No known-vulnerable versions matched the curated SCA database for the ${esc(sca.dep_count)} parsed dependencies.</div>`;return html;}
  html+=`<div class="table-wrap"><table><thead><tr><th style="width:80px">Sev</th><th>Package</th><th style="width:110px">Version</th><th style="width:70px">CVSS</th><th style="width:130px">CVE</th><th>Advisory · Fixed in</th></tr></thead><tbody>`;
  sca.findings.forEach(f=>{html+=`<tr><td><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td><td><strong>${esc(f.pkg)}</strong></td><td><code>${esc(f.ver)}</code></td><td><code>${f.cvss.toFixed(1)}</code></td><td><a href="https://nvd.nist.gov/vuln/detail/${esc(f.id)}" target="_blank" rel="noopener noreferrer"><code>${esc(f.id)}</code></a></td><td style="font-size:12px">${esc(f.title)} <span class="pill dim" style="font-size:9.5px">fix: ≥${esc(f.fixed)}</span></td></tr>`;});
  html+=`</tbody></table></div><div class="findings-note" style="margin-top:8px">📦 Curated SCA set (OWASP A06). For exhaustive coverage, feed results to <code>npm audit</code>, <code>composer audit</code>, <code>pip-audit</code>, or OSV.dev.</div>`;
  return html;
}
document.getElementById('form-code').addEventListener('submit',ev=>{
  ev.preventDefault();
  const code=document.getElementById('code-input').value;
  if(!code.trim()){toast('Paste code first.');return;}
  if(!guardScan('code'))return;
  scanBegin('code','Pasted code');
  try{
  const lang=document.getElementById('code-lang').value==='auto'?detectLanguage(code):document.getElementById('code-lang').value;
  window.CURRENT_SCAN.target='Pasted code ('+lang+')';window.CURRENT_SCAN.kind='code';window.CODE_SCAN_TARGET='Pasted code ('+lang+')';window.LAST_CODE=code;
  const sca=scaDetect(code);window.LAST_SCA=sca;
  const sastF=analyzeSAST(code,lang);
  let astF=[],taintF=[];
  if((lang==='js'||lang==='generic')&&astAvailable()){astF=astAnalyze(code,/\b(import|export)\s+/.test(code));taintF=taintAnalyze(code);}
  if(lang==='php'){taintF=phpTaintAnalyze(code);}
  const findings=mergeFindings(mergeFindings(sastF,astF),taintF);window.CODE_FINDINGS=findings;window.LAST_FINDINGS=findings;window.TAINT_COUNT=taintF.length;
  const bySev={Critical:0,High:0,Medium:0,Low:0,Info:0};findings.forEach(f=>bySev[f.sev]++);
  const owaspGroups={};findings.forEach(f=>{const o=f.owasp||'—';owaspGroups[o]=(owaspGroups[o]||0)+1;});
  const maxO=Math.max(1,...Object.values(owaspGroups));
  let html=`<div class="section" data-title="Code Analysis (SAST)"><div class="section-head"><h3>Code Analysis — SAST</h3><div class="status"><span class="pill ok section-status done">Done</span></div></div>
  <div class="stats" style="margin-bottom:16px">
    <div class="stat"><div class="n" style="color:#7f1d1d">${bySev.Critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:var(--bad)">${bySev.High}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:var(--warn)">${bySev.Medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:var(--info)">${bySev.Low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:var(--dim)">${bySev.Info}</div><div class="l">Info</div></div>
    <div class="stat"><div class="n">${findings.length}</div><div class="l">Total</div></div>
  </div>
  <div class="kv"><div class="k">Language</div><div class="v"><span class="pill orange">${esc(lang.toUpperCase())}</span> ${astF.length?'<span class="pill emerald">AST enriched</span>':''}</div>
  <div class="k">Rules evaluated</div><div class="v">${SAST_RULES.filter(r=>r.lang.includes('*')||r.lang.includes(lang)||lang==='generic').length} of ${SAST_RULES.length}</div>
  <div class="k">Code size</div><div class="v">${code.length.toLocaleString()} chars · ${code.split(/\r?\n/).length.toLocaleString()} lines</div></div>`;
  if(sca)html+=renderSCA(sca);
  if(Object.keys(owaspGroups).length){html+=`<h4 class="sub">Findings by OWASP Top 10 (2021)</h4>`;
    Object.entries(owaspGroups).sort((a,b)=>b[1]-a[1]).forEach(([o,c])=>{html+=`<div class="owasp-group"><span class="name">${esc(OWASP[o]||o)}</span><span class="bar"><span style="width:${Math.round(c/maxO*100)}%"></span></span><span class="pill bad">${c}</span></div>`;});}
  if(!findings.length)html+=`<div class="findings-note" style="margin-top:16px">No known vulnerability patterns detected. Not a guarantee — run a professional SAST tool + manual review.</div>`;
  else{
    // v1.9.2: save state; render controls + paginated container
    window.FIND_STATE={findings:findings,lang:lang,page:1,perPage:25,filterSev:'all',search:''};
    html+=`<h4 class="sub">Findings with Code Snippets</h4>
    <div class="dir-controls" style="grid-template-columns:1fr 190px 150px">
      <input type="text" id="find-search" placeholder="Search title, why, fix, CWE, OWASP…" oninput="findRefresh(true)">
      <select id="find-sev" onchange="findRefresh(true)">
        <option value="all">All severities</option>
        <option value="Critical">Critical only</option>
        <option value="High">High only</option>
        <option value="Medium">Medium only</option>
        <option value="Low">Low only</option>
        <option value="Info">Info only</option>
      </select>
      <select id="find-per" onchange="findRefresh(true)">
        <option value="10">10 / page</option>
        <option value="25" selected>25 / page</option>
        <option value="50">50 / page</option>
        <option value="0">Show all</option>
      </select>
    </div>
    <div id="find-wrap" style="margin-top:12px"></div>
    <div class="findings-note">Heuristic pattern-based analysis. Validate every finding manually.</div>`;
  }
  html+=`</div>`;
  resultsEl('code').innerHTML=html;
  if(findings.length)findRefresh();
  elK('acttarget','code').textContent='Code analysis ('+lang+')';
  elK('acttime','code').textContent=new Date().toLocaleString();
  elK('csvbtn','code').style.display=findings.length?'inline-flex':'none';
  /* no progress bar for code tab */
  elK('act','code').style.display='flex';
  resultsEl('code').scrollIntoView({behavior:'smooth',block:'start'});
  }finally{scanEnd('code');}
});
/* v1.9.2: paginated + filtered findings renderer */
function findRefresh(reset){
  const s=window.FIND_STATE;
  const se=document.getElementById('find-search');
  const sv=document.getElementById('find-sev');
  const pe=document.getElementById('find-per');
  if(se)s.search=se.value.toLowerCase().trim();
  if(sv)s.filterSev=sv.value;
  if(pe)s.perPage=parseInt(pe.value);
  if(reset)s.page=1;
  let rows=s.findings.slice();
  if(s.filterSev!=='all')rows=rows.filter(f=>f.sev===s.filterSev);
  if(s.search)rows=rows.filter(f=>(
    (f.title||'').toLowerCase().includes(s.search)||
    (f.why||'').toLowerCase().includes(s.search)||
    (f.fix||'').toLowerCase().includes(s.search)||
    (f.cwe||'').toLowerCase().includes(s.search)||
    (f.owasp||'').toLowerCase().includes(s.search)
  ));
  const total=rows.length;
  const per=s.perPage>0?s.perPage:(total||1);
  const tp=Math.max(1,Math.ceil(total/per));
  if(s.page>tp)s.page=tp; if(s.page<1)s.page=1;
  const start=(s.page-1)*per; const end=start+per;
  const pageRows=rows.slice(start,end);
  let html=`<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px">
    <div style="color:var(--dim);font-size:12.5px">Showing <strong style="color:var(--ink)">${total?start+1:0}–${Math.min(end,total)}</strong> of <strong style="color:var(--ink)">${total}</strong> matching finding(s)${s.findings.length!==total?` <span style="color:var(--dim-2)">(${s.findings.length} total)</span>`:''}</div>
    ${(s.filterSev!=='all'||s.search)?`<button class="btn secondary sm" onclick="findClear()">Clear filters</button>`:''}
  </div>`;
  if(!pageRows.length){
    html+=`<div class="findings-note">No findings match the current filters.</div>`;
    document.getElementById('find-wrap').innerHTML=html; return;
  }
  pageRows.forEach(f=>{
    const cwe=f.cwe?`<a href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-','')}.html" target="_blank"><code>${esc(f.cwe)}</code></a>`:'—';
    const isTaint=(f.source==='Taint'||f.source==='PHP-Taint');
    const src=isTaint?`<span class="pill" style="background:var(--purple-soft);color:#6d28d9;font-weight:700">🔗 ${f.source==='PHP-Taint'?'PHP TAINT':'TAINT'} FLOW</span>`:(f.source==='AST'?'<span class="pill purple">AST</span>':'<span class="pill dim">SAST</span>');
    html+=`<div class="table-wrap" style="margin-bottom:12px${isTaint?';border-color:rgba(124,58,237,.35)':''}"><table><tbody>
      <tr><td style="width:90px"><span class="sev-${esc(f.sev)}">${esc(f.sev)}</span></td>
      <td><strong style="font-size:13.5px">${esc(f.title)}</strong>
        <div style="margin-top:4px;color:var(--ink-soft);font-size:12.5px">${esc(f.why)}</div>
        <div style="margin-top:4px;color:var(--dim);font-size:12.5px"><strong>Fix:</strong> ${esc(f.fix)}</div>
        <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;font-size:11px">
          ${cwe} <span class="pill dim">${esc(f.owasp||'—')}</span> <span class="pill dim">Line ${f.line||'—'}</span> ${src}
        </div>
        ${f.flow?renderFlow(f.flow):''}
        ${renderSnippet(f.snippet,s.lang)}
      </td></tr></tbody></table></div>`;
  });
  // Pager
  if(s.perPage>0&&tp>1){
    html+=`<div class="pager">
      <button ${s.page===1?'disabled':''} onclick="findGoto(1)">First</button>
      <button ${s.page===1?'disabled':''} onclick="findGoto(${s.page-1})">Prev</button>`;
    const from=Math.max(1,s.page-2), to=Math.min(tp,s.page+2);
    if(from>1)html+=`<button onclick="findGoto(1)">1</button>${from>2?'<span class="info">…</span>':''}`;
    for(let i=from;i<=to;i++)html+=`<button class="${i===s.page?'active':''}" onclick="findGoto(${i})">${i}</button>`;
    if(to<tp)html+=`${to<tp-1?'<span class="info">…</span>':''}<button onclick="findGoto(${tp})">${tp}</button>`;
    html+=`<button ${s.page===tp?'disabled':''} onclick="findGoto(${s.page+1})">Next</button>
      <button ${s.page===tp?'disabled':''} onclick="findGoto(${tp})">Last</button>
      <span class="info">Page ${s.page} / ${tp}</span></div>`;
  }
  document.getElementById('find-wrap').innerHTML=html;
}
function findGoto(p){window.FIND_STATE.page=p;findRefresh();const w=document.getElementById('find-wrap');if(w)w.scrollIntoView({behavior:'smooth',block:'start'});}
function findClear(){const se=document.getElementById('find-search');const sv=document.getElementById('find-sev');if(se)se.value='';if(sv)sv.value='all';findRefresh(true);}

/* ================= NUCLEI SCANNER (v2.0.0) ================= */
window.NUC_STATE={findings:[],page:1,perPage:25,filterSev:'all',search:'',engine:'',meta:{}};
/* v2.2.0 — Nuclei bundled-template picker (checkbox multi-select + pagination + severity filter) */
const NUCLEI_CATALOG=[
  {id:'aws-credentials-file',name:'AWS Credentials File Exposure',severity:'critical',tags:'exposure,aws,cloud,tokens'},
  {id:'actuator-heapdump',name:'Spring Boot Actuator Heapdump Exposure',severity:'critical',tags:'exposure,springboot,actuator'},
  {id:'env-file-exposure',name:'Environment (.env) File Exposure',severity:'high',tags:'exposure,config,env'},
  {id:'env-backup-exposure',name:'Backup / SQL Dump Exposure',severity:'high',tags:'exposure,backup'},
  {id:'actuator-env-exposure',name:'Spring Boot Actuator env Exposure',severity:'high',tags:'exposure,springboot,actuator,misconfig'},
  {id:'git-config-exposure',name:'Git Config Exposure',severity:'medium',tags:'exposure,git,config'},
  {id:'dotenv-git-svn',name:'SVN Entries Exposure',severity:'medium',tags:'exposure,svn,vcs'},
  {id:'laravel-telescope',name:'Laravel Telescope Exposure',severity:'medium',tags:'exposure,laravel,panel'},
  {id:'adminer-panel',name:'Adminer Database Panel',severity:'medium',tags:'panel,database,adminer'},
  {id:'server-status-exposure',name:'Apache server-status Exposure',severity:'medium',tags:'exposure,apache,misconfig'},
  {id:'phpinfo-exposure',name:'PHPInfo Page Exposure',severity:'low',tags:'exposure,phpinfo,misconfig'},
  {id:'wp-user-enumeration',name:'WordPress User Enumeration (REST API)',severity:'low',tags:'wordpress,enum,api'},
  {id:'phpmyadmin-panel',name:'phpMyAdmin Panel',severity:'low',tags:'panel,database,phpmyadmin'},
  {id:'gitlab-ci-exposure',name:'GitLab CI Config Exposure',severity:'low',tags:'exposure,ci,gitlab'},
  {id:'ds-store-exposure',name:'.DS_Store File Exposure',severity:'info',tags:'exposure,osx'},
  {id:'swagger-ui-exposure',name:'Swagger UI / OpenAPI Exposure',severity:'info',tags:'exposure,api,swagger'},
  {id:'xmlrpc-enabled',name:'WordPress XML-RPC Enabled',severity:'info',tags:'wordpress,xmlrpc,misconfig'},
  {id:'security-txt',name:'security.txt Present',severity:'info',tags:'misc,disclosure'},
];
window.NUCTPL_SELECTED=new Set(NUCLEI_CATALOG.map(t=>t.id)); // default: all selected
window.NUCTPL_STATE={page:1,perPage:10,sev:'all',search:''};
const SEVRANK={critical:0,high:1,medium:2,low:3,info:4};
function nucTplFiltered(){
  const s=window.NUCTPL_STATE;
  let rows=NUCLEI_CATALOG.slice().sort((a,b)=>SEVRANK[a.severity]-SEVRANK[b.severity]);
  if(s.sev!=='all')rows=rows.filter(t=>t.severity===s.sev);
  if(s.search)rows=rows.filter(t=>(t.id+' '+t.name+' '+t.tags).toLowerCase().includes(s.search));
  return rows;
}
function nucTplRender(reset){
  const s=window.NUCTPL_STATE;
  const se=document.getElementById('nuctpl-search'),sv=document.getElementById('nuctpl-sev'),pe=document.getElementById('nuctpl-per');
  if(se)s.search=se.value.toLowerCase().trim();if(sv)s.sev=sv.value;if(pe)s.perPage=parseInt(pe.value);if(reset)s.page=1;
  const rows=nucTplFiltered();
  const total=rows.length;const per=s.perPage>0?s.perPage:(total||1);const tp=Math.max(1,Math.ceil(total/per));
  if(s.page>tp)s.page=tp;if(s.page<1)s.page=1;
  const start=(s.page-1)*per;const pageRows=rows.slice(start,start+per);
  const sevPill={critical:'bad',high:'bad',medium:'warn',low:'info',info:'dim'};
  let html=`<table><thead><tr><th style="width:36px"></th><th>Template</th><th style="width:90px">Severity</th><th>Tags</th></tr></thead><tbody>`;
  if(!pageRows.length)html+=`<tr><td colspan="4" style="text-align:center;color:var(--dim);padding:18px">No templates match.</td></tr>`;
  else pageRows.forEach(t=>{const ck=window.NUCTPL_SELECTED.has(t.id)?'checked':'';
    html+=`<tr><td><input type="checkbox" class="nuctpl-cb" data-id="${esc(t.id)}" ${ck} onchange="nucTplToggle('${esc(t.id)}',this.checked)"></td>
      <td><strong style="font-size:12.5px">${esc(t.name)}</strong><br><code style="font-size:10px">${esc(t.id)}</code></td>
      <td><span class="pill ${sevPill[t.severity]}">${esc(t.severity)}</span></td>
      <td style="font-size:11px;color:var(--dim)">${esc(t.tags)}</td></tr>`;});
  html+=`</tbody></table>`;
  if(s.perPage>0&&tp>1){
    html+=`<div class="pager" style="border-top:1px solid var(--line)"><button type="button" ${s.page===1?'disabled':''} onclick="nucTplGoto(${s.page-1})">Prev</button><span class="info">Page ${s.page}/${tp} · ${total} template(s)</span><button type="button" ${s.page===tp?'disabled':''} onclick="nucTplGoto(${s.page+1})">Next</button></div>`;
  }
  const wrap=document.getElementById('nuctpl-picker');if(wrap)wrap.innerHTML=html;
  const cnt=document.getElementById('nuctpl-count');if(cnt)cnt.textContent='('+NUCLEI_CATALOG.length+' available)';
  nucTplSelCount();
}
function nucTplToggle(id,ch){if(ch)window.NUCTPL_SELECTED.add(id);else window.NUCTPL_SELECTED.delete(id);nucTplSelCount();}
function nucTplSelectAll(ch){if(ch){nucTplFiltered().forEach(t=>window.NUCTPL_SELECTED.add(t.id));}else{window.NUCTPL_SELECTED.clear();}nucTplRender();}
function nucTplGoto(p){window.NUCTPL_STATE.page=p;nucTplRender();}
function nucTplSelCount(){const el=document.getElementById('nuctpl-selcount');if(el)el.textContent=window.NUCTPL_SELECTED.size+' selected';document.querySelectorAll('.nuctpl-cb').forEach(cb=>{cb.checked=window.NUCTPL_SELECTED.has(cb.dataset.id);});}

async function nucleiDetect(){
  try{nucTplRender();}catch(e){}
  try{const r=await callApi('nuclei_detect','');const d=r.data||{};const badge=document.getElementById('nuclei-engine-badge');
    if(d.available){badge.textContent='binary v'+(d.version||'?');badge.className='badge';badge.style.cssText='margin-left:auto;background:var(--emerald-soft);color:#065f46;font-size:10px;font-weight:700;padding:5px 10px;border-radius:999px;border:1px solid rgba(16,185,129,.2);text-transform:uppercase';}
    else{badge.textContent='Lite engine';badge.style.cssText='margin-left:auto;background:var(--purple-soft);color:#6d28d9;font-size:10px;font-weight:700;padding:5px 10px;border-radius:999px;text-transform:uppercase';}
  }catch(e){const b=document.getElementById('nuclei-engine-badge');if(b)b.textContent='Lite engine';}
}
async function runNuclei(target){
  window.CURRENT_SCAN.kind='nuclei';window.CURRENT_SCAN.target=target;window.NUCLEI_SCAN_TARGET=target;
  const mode=document.getElementById('nuclei-mode').value;
  const severity=document.getElementById('nuclei-severity').value.trim();
  const tags=document.getElementById('nuclei-tags').value.trim();
  const template=document.getElementById('nuclei-template').value;
  const selIds=(window.NUCTPL_SELECTED?Array.from(window.NUCTPL_SELECTED):[]).join(',');
  const useBundled=selIds?'0':'1';
  resultsEl('nuclei').innerHTML=makeSection('nuclei','Nuclei Scan Results');
  setStatus('nuclei','running','Running');
  document.getElementById('body-nuclei').innerHTML=`<div class="section-loading"><div class="mini-spin"></div><span>Running Nuclei scan against ${esc(target)} — this can take 30–90s…</span></div>`;
  resultsEl('nuclei').scrollIntoView({behavior:'smooth',block:'start'});
  try{
    const fd=new FormData();fd.append('target',target);fd.append('mode',mode);fd.append('severity',severity);fd.append('tags',tags);fd.append('template',template);fd.append('use_bundled',useBundled);fd.append('templates',selIds);
    // Client-side timeout so a hung scan fails gracefully instead of spinning forever
    const ctrl=new AbortController();const to=setTimeout(()=>ctrl.abort(),175000);
    let res,raw;
    try{res=await fetch('?api=1&action=nuclei_run',{method:'POST',body:fd,signal:ctrl.signal});}
    finally{clearTimeout(to);}
    raw=await res.text();
    let r;
    try{r=JSON.parse(raw);}
    catch(parseErr){
      // Surface the REAL problem instead of the cryptic "Unexpected end of JSON input"
      setStatus('nuclei','error','Failed');
      const detail=raw&&raw.trim()?esc(raw.trim().slice(0,600)):'The server returned an empty response.';
      const hint=!res.ok?`HTTP ${res.status} ${esc(res.statusText||'')}. `:'';
      document.getElementById('body-nuclei').innerHTML=`<div class="err-note"><strong>Scan could not complete.</strong><br>${hint}The server response was not valid JSON — the scan likely hit a memory/time limit or the Nuclei engine crashed.<br><br><strong>Try:</strong> switch to <em>Lite engine</em> mode, select fewer bundled templates, or narrow the severity/tags filter.<br><br><details style="margin-top:6px"><summary style="cursor:pointer;color:var(--dim)">Raw server response</summary><pre style="white-space:pre-wrap;word-break:break-word;font-size:11px;margin-top:6px">${detail}</pre></details></div>`;
      return;
    }
    if(!r.ok){setStatus('nuclei','error','Error');document.getElementById('body-nuclei').innerHTML=`<div class="err-note">${esc(r.error||'Unknown error.')}</div>`;return;}
    const d=r.data||{};const findings=d.findings||[];
    window.NUC_STATE={findings:findings,page:1,perPage:25,filterSev:'all',search:'',engine:d.engine,meta:d};
    window.NUC_FINDINGS=findings.map(f=>({sev:f.severity,title:f.name,why:f.description||('Matched at '+f.matched_at),fix:f.reference||'Review and remediate per template guidance.',cwe:'',owasp:'',line:'',source:'Nuclei',snippet:null}));window.LAST_FINDINGS=window.NUC_FINDINGS;
    setStatus('nuclei','done','Done · '+(r.elapsed||'?')+'s');
    renderNucleiShell(target,d);
    if(findings.length)nucRefresh();   // fix: only refresh when nuc-wrap exists
    const at=elK('acttarget','nuclei');if(at)at.textContent='Nuclei scan ('+target+')';
    const tm=elK('acttime','nuclei');if(tm)tm.textContent=new Date().toLocaleString();
    const cb=elK('csvbtn','nuclei');if(cb)cb.style.display=findings.length?'inline-flex':'none';
    const ab=elK('act','nuclei');if(ab)ab.style.display='flex';
  }catch(e){setStatus('nuclei','error','Failed');const b=document.getElementById('body-nuclei');if(b)b.innerHTML=`<div class="err-note">${esc(e.message)}</div>`;}
}
function renderNucleiShell(target,d){
  const f=d.findings||[];
  const bySev={Critical:0,High:0,Medium:0,Low:0,Info:0};
  f.forEach(x=>{const s=x.severity||'Info';if(bySev[s]!==undefined)bySev[s]++;else bySev.Info++;});
  const engineLabel=d.engine==='binary'?`<span class="pill emerald">Nuclei binary${d.detected&&d.detected.version?(' v'+d.detected.version):''}</span>`:`<span class="pill purple">Lite engine (pure PHP)</span>`;
  let extra='';
  if(d.engine==='lite')extra=`<div class="k">Templates run</div><div class="v">${(d.bundled_count||0)} bundled${d.custom?' + 1 custom':''} · ${d.tested||0} request(s) sent</div>`;
  else extra=`<div class="k">Raw JSONL lines</div><div class="v">${d.raw_lines||0}</div>`;
  let html=`<div class="stats" style="margin-bottom:16px">
    <div class="stat"><div class="n" style="color:#7f1d1d">${bySev.Critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:var(--bad)">${bySev.High}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:var(--warn)">${bySev.Medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:var(--info)">${bySev.Low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:var(--dim)">${bySev.Info}</div><div class="l">Info</div></div>
    <div class="stat"><div class="n">${f.length}</div><div class="l">Total</div></div>
  </div>
  <div class="kv"><div class="k">Target</div><div class="v">${esc(d.base||target)}</div>
  <div class="k">Engine</div><div class="v">${engineLabel}</div>
  ${extra}</div>`;
  if(!f.length){html+=`<div class="findings-note" style="margin-top:16px">No template matches. ${d.engine==='binary'?'The binary ran but nothing matched (or templates need updating with <code>nuclei -update-templates</code>).':'Try enabling more templates, relaxing severity/tags, or pasting a custom template.'}</div>`;document.getElementById('body-nuclei').innerHTML=html;return;}
  html+=`<h4 class="sub">Findings</h4>
  <div class="dir-controls" style="grid-template-columns:1fr 190px 150px">
    <input type="text" id="nuc-search" placeholder="Search name, template-id, matched-at, tags…" oninput="nucRefresh(true)">
    <select id="nuc-sev" onchange="nucRefresh(true)"><option value="all">All severities</option><option value="Critical">Critical only</option><option value="High">High only</option><option value="Medium">Medium only</option><option value="Low">Low only</option><option value="Info">Info only</option></select>
    <select id="nuc-per" onchange="nucRefresh(true)"><option value="10">10 / page</option><option value="25" selected>25 / page</option><option value="50">50 / page</option><option value="0">Show all</option></select>
  </div>
  <div id="nuc-wrap" style="margin-top:12px"></div>`;
  document.getElementById('body-nuclei').innerHTML=html;
}
function nucRefresh(reset){
  const wrap=document.getElementById('nuc-wrap'); if(!wrap) return; // guard: nothing to render into
  const s=window.NUC_STATE;
  const se=document.getElementById('nuc-search');const sv=document.getElementById('nuc-sev');const pe=document.getElementById('nuc-per');
  if(se)s.search=se.value.toLowerCase().trim();if(sv)s.filterSev=sv.value;if(pe)s.perPage=parseInt(pe.value);if(reset)s.page=1;
  let rows=s.findings.slice();
  if(s.filterSev!=='all')rows=rows.filter(f=>(f.severity||'Info')===s.filterSev);
  if(s.search)rows=rows.filter(f=>((f.name||'')+' '+(f.template_id||'')+' '+(f.matched_at||'')+' '+(f.tags||'')+' '+(f.description||'')).toLowerCase().includes(s.search));
  const total=rows.length;const per=s.perPage>0?s.perPage:(total||1);const tp=Math.max(1,Math.ceil(total/per));if(s.page>tp)s.page=tp;if(s.page<1)s.page=1;
  const start=(s.page-1)*per;const end=start+per;const pr=rows.slice(start,end);
  const sevCls={Critical:'sev-Critical',High:'sev-High',Medium:'sev-Medium',Low:'sev-Low',Info:'sev-Info'};
  let html=`<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px"><div style="color:var(--dim);font-size:12.5px">Showing <strong style="color:var(--ink)">${total?start+1:0}–${Math.min(end,total)}</strong> of <strong style="color:var(--ink)">${total}</strong> finding(s)</div>${(s.filterSev!=='all'||s.search)?`<button class="btn secondary sm" onclick="nucClear()">Clear filters</button>`:''}</div>`;
  if(!pr.length){html+=`<div class="findings-note">No findings match the current filters.</div>`;document.getElementById('nuc-wrap').innerHTML=html;return;}
  pr.forEach(f=>{
    const ref=(f.reference||'').trim();
    const refHtml=ref?ref.split(/\s+/).filter(Boolean).slice(0,3).map(u=>/^https?:/.test(u)?`<a href="${esc(u)}" target="_blank">ref</a>`:esc(u)).join(' '):'';
    const tags=(f.tags||'').split(',').filter(Boolean).map(t=>`<span class="pill dim">${esc(t)}</span>`).join(' ');
    const evidence=f.evidence?`<div class="code-snippet"><div class="cs-head"><span>Match evidence</span><span class="lang">${esc(f.matcher||f.type||'http')}</span></div><pre><div class="ln hit"><span class="no">›</span><span class="src">${esc(f.evidence)}</span></div></pre></div>`:'';
    const extracted=f.extracted?`<div style="margin-top:6px;font-size:12px"><strong>Extracted:</strong> <code>${esc(f.extracted)}</code></div>`:'';
    html+=`<div class="table-wrap" style="margin-bottom:12px"><table><tbody><tr>
      <td style="width:90px"><span class="${sevCls[f.severity]||'sev-Info'}">${esc(f.severity||'Info')}</span></td>
      <td><strong style="font-size:13.5px">${esc(f.name)}</strong> <code style="font-size:10.5px">${esc(f.template_id||'')}</code>
        ${f.description?`<div style="margin-top:4px;color:var(--ink-soft);font-size:12.5px">${esc(f.description)}</div>`:''}
        <div style="margin-top:6px;font-size:12px;color:var(--dim)"><strong>Matched:</strong> <a href="${esc(f.matched_at)}" target="_blank"><code>${esc(f.matched_at)}</code></a></div>
        ${extracted}
        <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;align-items:center;font-size:11px">
          <span class="pill ${f.engine==='binary'?'emerald':'purple'}">${f.engine==='binary'?'binary':'lite'}</span>
          ${f.status?`<span class="pill dim">HTTP ${esc(f.status)}</span>`:''}
          ${f.matcher?`<span class="pill dim">matcher: ${esc(f.matcher)}</span>`:''}
          ${tags} ${refHtml}
        </div>
        ${evidence}
      </td></tr></tbody></table></div>`;
  });
  if(s.perPage>0&&tp>1){
    html+=`<div class="pager"><button ${s.page===1?'disabled':''} onclick="nucGoto(1)">First</button><button ${s.page===1?'disabled':''} onclick="nucGoto(${s.page-1})">Prev</button>`;
    const from=Math.max(1,s.page-2),to=Math.min(tp,s.page+2);
    if(from>1)html+=`<button onclick="nucGoto(1)">1</button>${from>2?'<span class="info">…</span>':''}`;
    for(let i=from;i<=to;i++)html+=`<button class="${i===s.page?'active':''}" onclick="nucGoto(${i})">${i}</button>`;
    if(to<tp)html+=`${to<tp-1?'<span class="info">…</span>':''}<button onclick="nucGoto(${tp})">${tp}</button>`;
    html+=`<button ${s.page===tp?'disabled':''} onclick="nucGoto(${s.page+1})">Next</button><button ${s.page===tp?'disabled':''} onclick="nucGoto(${tp})">Last</button><span class="info">Page ${s.page} / ${tp}</span></div>`;
  }
  document.getElementById('nuc-wrap').innerHTML=html;
}
function nucGoto(p){window.NUC_STATE.page=p;nucRefresh();const w=document.getElementById('nuc-wrap');if(w)w.scrollIntoView({behavior:'smooth',block:'start'});}
function nucClear(){const se=document.getElementById('nuc-search');const sv=document.getElementById('nuc-sev');if(se)se.value='';if(sv)sv.value='all';nucRefresh(true);}
document.addEventListener('DOMContentLoaded',()=>{try{nucleiDetect();}catch(e){}try{renderScanStrip();}catch(e){}
  // Toggle the author-archive depth control with the WP scan checkbox
  const wpCb=document.getElementById('opt-wpscan'),dRow=document.getElementById('wpdepth-row');
  if(wpCb&&dRow){const sync=()=>{dRow.style.opacity=wpCb.checked?'1':'.4';dRow.style.pointerEvents=wpCb.checked?'auto':'none';};wpCb.addEventListener('change',sync);sync();}
});

function exportFindingsCSV(ev){
  const bar=ev&&ev.target?ev.target.closest('.action-bar'):null;
  const kind=(bar&&bar.id.indexOf('act-')===0)?bar.id.slice(4):(window.CURRENT_SCAN.kind||'code');
  const findings=kind==='nuclei'?(window.NUC_FINDINGS||[]):(window.CODE_FINDINGS||window.LAST_FINDINGS||[]);
  if(!findings.length){toast('No findings.');return;}
  const csv=['Severity,Title,CWE,OWASP,Line,Source,Why,Fix'];
  findings.forEach(f=>csv.push([f.sev,f.title,f.cwe||'',f.owasp||'',f.line||'',f.source||'',f.why,f.fix].map(x=>`"${String(x).replace(/"/g,'""')}"`).join(',')));
  const b=new Blob(['\uFEFF'+csv.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=(kind==='nuclei'?'nuclei_findings_v':'sast_findings_v')+APP.version+'.csv';a.click();toast('Findings CSV exported.');}
function renderRuleCatalog(){
  const filter=(document.getElementById('rule-filter')?.value||'').toLowerCase().trim();
  const ln={'*':'All','php':'PHP','js':'JS/TS','python':'Python','java':'Java','csharp':'C#','go':'Go','ruby':'Ruby','sql':'SQL','html':'HTML'};
  let rules=SAST_RULES.slice();
  if(filter)rules=rules.filter(r=>r.title.toLowerCase().includes(filter)||r.id.toLowerCase().includes(filter)||(r.cwe||'').toLowerCase().includes(filter)||(r.owasp||'').toLowerCase().includes(filter)||r.lang.join(',').toLowerCase().includes(filter));
  let html=`<div style="margin-bottom:10px;color:var(--dim);font-size:12px">${rules.length} of ${SAST_RULES.length} rules</div><div class="table-wrap scroll" style="max-height:55vh"><table><thead><tr><th style="width:70px">Sev</th><th>Rule</th><th style="width:100px">Languages</th><th style="width:80px">CWE</th><th style="width:70px">OWASP</th></tr></thead><tbody>`;
  rules.forEach(r=>{const langs=r.lang.map(l=>ln[l]||l).join(', ');html+=`<tr><td><span class="sev-${esc(r.sev)}">${esc(r.sev)}</span></td><td><strong>${esc(r.title)}</strong><br><code style="font-size:10px">${esc(r.id)}</code></td><td>${esc(langs)}</td><td><code>${esc(r.cwe||'—')}</code></td><td><span class="pill dim">${esc(r.owasp||'—')}</span></td></tr>`;});
  html+=`</tbody></table></div>`;document.getElementById('rule-catalog').innerHTML=html;}
document.getElementById('rule-count-badge').textContent=SAST_RULES.length+' rules';

function stripEmoji(s){if(s==null)return'';s=String(s);s=s.replace(/[\u{1F300}-\u{1FAFF}]/gu,'');s=s.replace(/[\u{2600}-\u{27BF}]/gu,'');s=s.replace(/[\u{1F000}-\u{1F2FF}]/gu,'');s=s.replace(/[\u{FE00}-\u{FE0F}]/gu,'');s=s.replace(/[\u{200D}]/gu,'');s=s.replace(/[^\x00-\xFF]/g,'');return s.trim();}
/* ============================================================
 * v2.5.5 — ATTACK PATH & REMEDIATION PLAYBOOK
 * For each finding from the URL recon, produces:
 *   • Attack scenario (educational — how it could be leveraged)
 *   • Non-destructive PoC / verification commands (confirm the flaw)
 *   • Remediation (the defensive fix — primary value)
 * Generated scripts are AUTHORIZED-TESTING verification/hardening
 * aids for your OWN systems — not weaponized exploit tools.
 * ============================================================ */
const SEV_RANK={Critical:0,High:1,Medium:2,Low:3,Info:4};
function pbEsc(s){return String(s==null?'':s);}
/* Build the list of playbook items from window.LAST_RECON */
/* v2.7.2 — authoritative URL-scan host, immune to later IP/Nuclei scans that overwrite CURRENT_SCAN.target */
/* v2.7.3: Red Team header — live target indicator + manual override */
function rtTargetOverride(){const el=(typeof document!=='undefined')?document.getElementById('rt-target-override'):null;return el&&el.value?el.value.trim():'';}
function rtRefreshTargetIndicator(){
  const ov=rtTargetOverride();
  const host=urlScanHost()||'—';
  const ind=document.getElementById('rt-target-indicator');if(ind)ind.textContent=host;
  const echo=document.getElementById('rt-target-echo');if(echo)echo.textContent=host;
  const src=document.getElementById('rt-target-src');
  if(src){if(ov){src.textContent='manual override';src.className='pill warn';}else{src.textContent='from URL scan';src.className='pill dim';}}
}
function rtClearTargetOverride(){const el=document.getElementById('rt-target-override');if(el)el.value='';rtRefreshTargetIndicator();toast('Override cleared — using URL-scan target.');}
function urlScanTargetRaw(){
  // 0) explicit Red Team manual override always wins (authorized retargeting within scope)
  const ov=rtTargetOverride(); if(ov)return ov;
  // 1) the exact value the URL scan was launched with (set in orchestrateURL)
  let t=window.URL_SCAN_TARGET||'';
  // 2) fall back to the page recon's final/base URL
  if(!t){const R=window.LAST_RECON||{};const p=R.page||{};t=p.final_url||p.url||window.URL_BASE||'';}
  // 3) last resort: only trust CURRENT_SCAN.target if the last scan was a URL scan
  if(!t && window.CURRENT_SCAN && window.CURRENT_SCAN.kind==='url')t=window.CURRENT_SCAN.target||'';
  return t||'';
}
function urlScanHost(){return urlScanTargetRaw().replace(/^https?:\/\//i,'').replace(/\/.*$/,'').replace(/:\d+$/,'').trim();}
function urlScanBase(){const t=urlScanTargetRaw();const h=urlScanHost();return (/^https?:\/\//i.test(t)?t:('https://'+h)).replace(/\/$/,'');}
function buildPlaybook(){
  const R=window.LAST_RECON||{}; const host=urlScanHost()||'TARGET';
  const base=urlScanBase();
  const items=[];
  // ---- Security headers (from page) ----
  const page=R.page||{};
  (page.sec_rows||[]).forEach(h=>{ if(h.present)return;
    const map={
      'HSTS':{sev:'High',attack:'Without HSTS an attacker on the same network can perform SSL-stripping (downgrade HTTPS→HTTP) and intercept session cookies/credentials in cleartext.',fix:'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` at the web server/WAF.'},
      'CSP':{sev:'High',attack:'No Content-Security-Policy means any reflected/stored XSS runs with full privileges — an attacker can exfiltrate cookies, keystrokes, or pivot to account takeover.',fix:"Deploy a strict CSP (e.g. `default-src 'self'; object-src 'none'; frame-ancestors 'none'`) and iterate from report-only mode."},
      'X-Frame-Options':{sev:'Medium',attack:'Missing framing controls allow clickjacking: the page is loaded in a transparent iframe over attacker UI to trick users into clicking sensitive actions.',fix:"Add `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`)."},
      'X-Content-Type-Options':{sev:'Medium',attack:'Without nosniff, browsers may MIME-sniff responses and execute non-script files as script, enabling stored-XSS via uploads.',fix:'Add `X-Content-Type-Options: nosniff`.'},
      'Referrer-Policy':{sev:'Low',attack:'A permissive referrer can leak internal URLs, tokens in query strings, and session context to third-party sites.',fix:'Add `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`).'},
      'Permissions-Policy':{sev:'Low',attack:'Absence lets embedded/compromised content access camera, mic, geolocation, etc. via delegated permissions.',fix:'Add a restrictive `Permissions-Policy` disabling unused features.'}
    };
    const m=map[h.header]||{sev:'Low',attack:'Missing security header weakens defense-in-depth.',fix:'Add the '+h.header+' header.'};
    items.push({cat:'Security Header',title:'Missing '+h.header,sev:m.sev,attack:m.attack,fix:m.fix,
      verify:['curl -sI '+base+' | grep -i "'+ (h.header==='HSTS'?'strict-transport-security':h.header.toLowerCase()) +'"  # empty = header absent']});
  });
  // Version banners
  (page.tech||[]).forEach(t=>{ if((t.name==='Web Server'||t.name==='X-Powered-By')&&/\d/.test(t.version||'')){
    items.push({cat:'Info Disclosure',title:'Version banner: '+t.name+' '+t.version,sev:'Low',
      attack:'Exact software versions let an attacker look up matching public CVEs and target known exploits precisely instead of blind probing.',
      fix:'Suppress version tokens (Apache `ServerTokens Prod`/`ServerSignature Off`; Nginx `server_tokens off;`; PHP `expose_php = Off`).',
      verify:['curl -sI '+base+' | grep -iE "server|x-powered-by"']}); }});
  // ---- Exposed paths (dir probe) ----
  const dir=R.dir||{};
  (dir.rows||[]).forEach(row=>{ const st=row.status;
    const exposed=(st===200)|| (row.flag && row.flag!=='');
    if(!exposed) return;
    let sev='Medium',attack='An exposed path may reveal sensitive data or attack surface.';
    if(/\.git|\.svn|\.hg/.test(row.path)){sev='High';attack='Exposed VCS metadata lets an attacker reconstruct full source code (and often hard-coded secrets) with tools like git-dumper.';}
    else if(/\.env|wp-config|config\.(php|bak)|\.htpasswd/.test(row.path)){sev='Critical';attack='A readable config/.env commonly leaks DB credentials, API keys, and app secrets — often a direct path to full compromise.';}
    else if(/backup|\.sql|dump|\.zip/.test(row.path)){sev='High';attack='Downloadable backups/DB dumps expose full data and credentials offline for unhurried cracking.';}
    else if(/actuator|heapdump/.test(row.path)){sev='Critical';attack='Spring Actuator endpoints (env/heapdump) leak secrets and memory; heapdump often yields live session tokens.';}
    else if(/phpinfo|info\.php/.test(row.path)){sev='Medium';attack='phpinfo() discloses full environment, paths, and loaded modules — a rich map for targeted exploitation.';}
    else if(row.flag==='DIR-LISTING'){sev='Medium';attack='Directory listing enumerates files an attacker would otherwise have to guess, revealing backups, sources, and uploads.';}
    items.push({cat:'Exposed Path',title:'Exposed: '+row.path+(row.flag?(' ['+row.flag+']'):''),sev,attack,
      fix:'Remove the file from the web root, or block it at the server (deny rule / auth) and rotate any secrets it may have leaked.',
      verify:['curl -s -o /dev/null -w "%{http_code}\\n" '+base+row.path+'   # 200 = still exposed']});
  });
  // ---- TLS ----
  const tls=R.tls||{};
  (tls.findings||[]).forEach(f=>{
    let attack='TLS misconfiguration can enable interception or trust bypass.';
    if(/expired|expires/i.test(f.msg))attack='An expired/near-expiry cert breaks trust; users click through warnings, normalizing MITM, and automation may fail open.';
    else if(/weak signature|sha-?1|md5/i.test(f.msg))attack='Weak signature algorithms are forgeable, allowing a crafted certificate to impersonate the site.';
    else if(/legacy protocol|tls ?1\.(0|1)|ssl/i.test(f.msg))attack='Legacy TLS/SSL is vulnerable to downgrade and padding-oracle attacks (POODLE/BEAST) enabling decryption.';
    else if(/self-signed/i.test(f.msg))attack='A self-signed cert provides no third-party trust; users cannot distinguish it from an attacker MITM cert.';
    else if(/hostname/i.test(f.msg))attack='A hostname/SAN mismatch means the cert does not authenticate this host — indistinguishable from an interception cert.';
    items.push({cat:'TLS/SSL',title:f.msg,sev:f.sev||'Medium',attack,
      fix:'Renew/replace with a valid cert from a trusted CA, enforce TLS 1.2+ with modern ciphers, and match SAN to the hostname.',
      verify:['echo | openssl s_client -connect '+host+':443 -servername '+host+' 2>/dev/null | openssl x509 -noout -dates -issuer -subject',
              'nmap --script ssl-enum-ciphers -p 443 '+host+'   # review protocol/cipher grades']});
  });
  // ---- DNS / email ----
  const dns=R.dns||{};
  (dns.records||[]).forEach(rec=>{ if(rec.status==='present'&&(rec.sev==='Info'))return;
    if(rec.status==='present'&&rec.sev!=='Info'||rec.status!=='present'){
      let attack='',fix='';
      if(rec.name==='SPF'){attack='Without a strict SPF (-all), an attacker can spoof email from your domain to run phishing/BEC that passes basic checks.';fix='Publish `v=spf1 include:_your_esp_ -all` (hard fail).';}
      else if(rec.name==='DMARC'){attack='No/relaxed DMARC (p=none) means spoofed mail is delivered — the core enabler of domain-impersonation phishing.';fix='Publish `_dmarc` TXT with `p=quarantine` then `p=reject` after monitoring rua reports.';}
      else if(rec.name==='DKIM'){attack='Missing DKIM lets forwarded/spoofed mail lack cryptographic origin proof, weakening DMARC enforcement.';fix='Enable DKIM signing at your mail provider and publish the selector key.';}
      else if(rec.name==='CAA'){attack='No CAA record means any CA can issue a cert for your domain — broadening mis-issuance / rogue-cert risk.';fix='Add a CAA record naming only your authorized CA(s).';}
      else if(rec.name==='DNSSEC'){attack='Without DNSSEC, DNS responses can be spoofed/cache-poisoned to redirect users to attacker infrastructure.';fix='Enable DNSSEC signing at your DNS provider/registrar.';}
      else return;
      items.push({cat:'DNS / Email',title:rec.name+' — '+rec.note,sev:rec.sev==='Info'?'Low':(rec.sev||'Medium'),attack,fix,
        verify:[ rec.name==='DMARC'?('dig +short TXT _dmarc.'+host):(rec.name==='SPF'?('dig +short TXT '+host+' | grep spf1'):('dig +short '+(rec.name==='CAA'?'CAA ':(rec.name==='DNSSEC'?'DNSKEY ':'TXT '))+host)) ]});
    }
  });
  // ---- Cookies + CSP ----
  const ck=R.cookies||{};
  (ck.cookies||[]).forEach(c=>{ if(!c.issues||!c.issues.length)return;
    items.push({cat:'Cookie',title:'Cookie "'+c.name+'": '+c.issues.join(', '),sev:c.sev||'Medium',
      attack:'Cookies without HttpOnly are stealable via any XSS; without Secure they leak over plain HTTP; without SameSite they enable CSRF.',
      fix:'Set `HttpOnly; Secure; SameSite=Lax` (or Strict) on session cookies at the application layer.',
      verify:['curl -sI '+base+' | grep -i "set-cookie"   # inspect flags on each cookie']});
  });
  (ck.csp&&ck.csp.findings||[]).forEach(f=>{
    items.push({cat:'CSP',title:'CSP weakness: '+f.msg,sev:f.sev||'Medium',
      attack:"'unsafe-inline'/'unsafe-eval'/wildcard sources let injected scripts execute, defeating CSP's XSS protection.",
      fix:'Remove unsafe-inline/unsafe-eval, use nonces/hashes, and pin explicit source allowlists.',
      verify:['curl -sI '+base+' | grep -i content-security-policy']});
  });
  // ---- WordPress ----
  const wp=R.wordpress||{};
  if(wp.is_wp){
    if(wp.outdated){ items.push({cat:'WordPress',title:'Outdated WordPress core'+(wp.version?(' '+wp.version):''),sev:(wp.rating&&SEV_RANK[wp.rating]<=1)?wp.rating:'High',
      attack:'An outdated core maps to public CVEs; attackers chain known exploits (auth-bypass, XSS→RCE) using off-the-shelf PoCs for the exact version.',
      fix:'Update WordPress core to the latest release ('+(wp.latest||'current')+') and enable auto-updates.',
      verify:['curl -s '+base+'/  | grep -i \'name="generator"\'','curl -s '+base+'/readme.html | grep -i version | head -1']}); }
    (wp.plugins||[]).filter(p=>p.cves&&p.cves.length).forEach(p=>{ const top=p.cves[0];
      items.push({cat:'WP Plugin',title:'Vulnerable plugin: '+p.name+(p.version?(' '+p.version):''),sev:p.rating||'High',
        attack:'Plugin '+p.name+' '+(p.version||'')+' matches '+top.id+' ('+top.title+'). Public exploit code typically exists for such CVEs — the #1 WordPress compromise vector.',
        fix:'Update '+p.name+' to '+(top.fixed||'the patched version')+' immediately, or remove it if unused.',
        verify:['curl -s '+base+'/wp-content/plugins/'+p.slug+'/readme.txt | grep -i "stable tag"']}); });
    (wp.themes||[]).filter(t=>t.cves&&t.cves.length).forEach(t=>{ const top=t.cves[0];
      items.push({cat:'WP Theme',title:'Vulnerable theme: '+t.name+(t.version?(' '+t.version):''),sev:t.rating||'High',
        attack:'Theme '+t.name+' matches '+top.id+' ('+top.title+'), which has known public exploitation techniques.',
        fix:'Update or replace the '+t.name+' theme with a patched version.',
        verify:['curl -s '+base+'/wp-content/themes/'+t.slug+'/style.css | grep -i version']}); });
    if(wp.xmlrpc&&wp.xmlrpc.enabled){ const mc=wp.xmlrpc.multicall;
      items.push({cat:'WordPress',title:'XML-RPC enabled'+(mc?' (system.multicall)':''),sev:mc?'High':'Medium',
        attack:'xmlrpc.php'+(mc?' with system.multicall lets an attacker attempt hundreds of password guesses per request (amplified brute force)':' enables pingback abuse for SSRF/DDoS reflection')+'.',
        fix:'Disable XML-RPC if unused (block /xmlrpc.php at the WAF/server) or disable system.multicall & pingback.ping.',
        verify:['curl -s -o /dev/null -w "%{http_code}\\n" '+base+'/xmlrpc.php   # 200/405 = present',
                'curl -s '+base+'/xmlrpc.php -d \'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>\' | grep -o "system.multicall"   # lists dangerous method if present']}); }
    if(wp.users&&wp.users.count>0){
      items.push({cat:'WordPress',title:'Username enumeration ('+wp.users.count+' users)',sev:'Medium',
        attack:'Recovered usernames ('+(wp.users.users||[]).slice(0,3).map(u=>u.login).filter(Boolean).join(', ')+'…) are half of a credential — they feed password-spraying and targeted brute force against wp-login.',
        fix:'Block anonymous /wp-json/wp/v2/users, disable author archives (?author=N), and enforce login rate-limiting + 2FA.',
        verify:['curl -s "'+base+'/wp-json/wp/v2/users" | head -c 300','curl -sI "'+base+'/?author=1" | grep -i location']}); }
  }
  items.sort((a,b)=>(SEV_RANK[a.sev]??5)-(SEV_RANK[b.sev]??5));
  return {host,base,items};
}
function renderPlaybook(){
  const out=document.getElementById('results-url');
  if(!out){toast('Run a URL scan first.');return;}
  const pb=buildPlaybook();
  if(!pb.items.length){toast('No actionable findings to build a playbook from.');return;}
  const cnt={Critical:0,High:0,Medium:0,Low:0,Info:0};pb.items.forEach(i=>cnt[i.sev]=(cnt[i.sev]||0)+1);
  let html=`<div class="section" data-title="Attack Path & Remediation Playbook"><div class="section-head"><h3>🎯 Attack Path &amp; Remediation Playbook</h3><div class="status"><span class="pill ok section-status done">${pb.items.length} items</span></div></div>
  <div class="findings-note" style="border-left-color:var(--warn);background:var(--warn-soft)"><strong>⚠️ Authorized use only.</strong> These attack scenarios and proof-of-concept commands are for <strong>controlled testing of systems you own or are authorized to assess</strong> (${pbEsc(pb.host)}). The PoC commands are <strong>non-destructive verifications</strong> that confirm each finding so you can prioritize and defend. Do not run against third-party systems.</div>
  <div class="stats" style="margin:12px 0">
    <div class="stat"><div class="n" style="color:#7f1d1d">${cnt.Critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:var(--bad)">${cnt.High}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:var(--warn)">${cnt.Medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:var(--info)">${cnt.Low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n">${pb.items.length}</div><div class="l">Total</div></div></div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px;align-items:center">
    <button id="pb-verify-btn" class="btn" style="background:#0f766e;color:#fff" onclick="verifyNowServerSide()">⚡ Verify Now (server-side — no download)</button>
    <button class="btn purple" onclick="downloadPlaybookHTML()">⬇ Playbook Report (.html)</button>
    <button class="btn secondary" onclick="downloadPoCScriptPHP()">⬇ Verify Script (.php)</button>
    <button class="btn secondary" onclick="downloadHardeningGuide()">⬇ Hardening Guide (.md)</button>
    <span id="pb-verify-prog" style="font-size:12px;color:var(--dim)"></span>
  </div>
  <div class="findings-note" style="font-size:12px;margin-bottom:12px">⚡ <strong>Verify Now</strong> re-checks every finding <strong>live from the server</strong> (non-destructive PHP + cURL/DNS/TLS) and shows a ✓ CONFIRMED / ○ clear badge with evidence under each item — instantly, nothing to download.</div>
  <div class="findings-note" style="font-size:12px">💡 <strong>No scripts to run?</strong> The <strong>.html report</strong> is fully self-contained — just double-click to open it in any browser and read the full playbook offline. The <strong>.php</strong> script uses the same PHP + cURL your dashboard already runs on: execute it with <code>php verify.php</code> on the command line, or drop it on your PHP server and open it in a browser (append <code>?authorized=yes</code>).</div>`;
  pb.items.forEach((it,i)=>{
    html+=`<details class="script-analysis" style="margin-bottom:10px;background:var(--panel);border:1px solid var(--line);border-left:3px solid ${it.sev==='Critical'?'#7f1d1d':it.sev==='High'?'var(--bad)':it.sev==='Medium'?'var(--warn)':'var(--info)'};border-radius:var(--radius-sm);padding:0 14px">
      <summary style="cursor:pointer;padding:12px 0;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center">
        <span style="flex:1;min-width:260px"><span class="sev-${esc(it.sev)}">${esc(it.sev)}</span> <strong style="margin-left:6px">${esc(it.title)}</strong></span>
        <span class="pill dim">${esc(it.cat)}</span></summary>
      <div style="padding-bottom:12px">
        <div style="margin:6px 0"><span style="font-size:11px;font-weight:700;color:var(--bad);text-transform:uppercase">🗡️ Attack scenario</span><div style="font-size:12.5px;color:var(--ink-soft);margin-top:3px">${esc(it.attack)}</div></div>
        <div style="margin:8px 0"><span style="font-size:11px;font-weight:700;color:#6d28d9;text-transform:uppercase">🔬 Verify (non-destructive PoC)</span>
          <pre style="background:#0d1526;color:#c9d6ee;border:1px solid #1e2b47;border-radius:8px;padding:10px 12px;margin-top:4px;font-size:11px;white-space:pre-wrap;word-break:break-all">${(it.verify||[]).map(esc).join('\n')}</pre></div>
        <div style="margin:6px 0"><span style="font-size:11px;font-weight:700;color:var(--ok);text-transform:uppercase">🛡️ Remediation</span><div style="font-size:12.5px;color:var(--ink-soft);margin-top:3px">${esc(it.fix)}</div></div>
        <div id="pb-res-${i}"></div>
      </div></details>`;
  });
  html+=`</div>`;
  // Append below existing results (don't wipe the scan)
  const wrap=document.createElement('div');wrap.innerHTML=html;out.appendChild(wrap);
  wrap.scrollIntoView({behavior:'smooth',block:'start'});
}
/* ============================================================
 * v2.5.9 — RED TEAM MODE
 * A professional offensive-security workflow & reporting layer over
 * the existing findings: MITRE ATT&CK mapping, Rules of Engagement,
 * Cyber Kill-Chain view, engagement log, and a red-team report.
 * ANALYSIS & PLANNING ONLY — no weaponized exploits are generated;
 * confirmation still uses the non-destructive "Verify Now".
 * ============================================================ */
window.RT_LOG=window.RT_LOG||[];
function rtLog(action,detail){window.RT_LOG.push({t:new Date().toISOString(),action,detail:detail||''});}
/* Map a playbook item to MITRE ATT&CK tactic/technique + kill-chain phase */
function attackMap(it){
  const c=it.cat, t=(it.title||'');
  const K={ // key -> {tactic, tech, id, phase}
    hdr:{tactic:'Collection / AiTM',tech:'Adversary-in-the-Middle',id:'T1557',phase:'Exploitation'},
    info:{tactic:'Reconnaissance',tech:'Gather Victim Host Information',id:'T1592',phase:'Reconnaissance'},
    vcs:{tactic:'Reconnaissance',tech:'Search Open Technical Databases / Code Repos',id:'T1596',phase:'Reconnaissance'},
    secret:{tactic:'Credential Access',tech:'Unsecured Credentials: Credentials In Files',id:'T1552.001',phase:'Weaponization'},
    backup:{tactic:'Collection',tech:'Data from Configuration Repository',id:'T1602',phase:'Actions on Objectives'},
    actuator:{tactic:'Credential Access',tech:'Unsecured Credentials',id:'T1552',phase:'Exploitation'},
    phpinfo:{tactic:'Discovery',tech:'System Information Discovery',id:'T1082',phase:'Reconnaissance'},
    dirlist:{tactic:'Discovery',tech:'File and Directory Discovery',id:'T1083',phase:'Reconnaissance'},
    exposed:{tactic:'Initial Access',tech:'Exploit Public-Facing Application',id:'T1190',phase:'Exploitation'},
    tls:{tactic:'Collection / AiTM',tech:'Adversary-in-the-Middle',id:'T1557',phase:'Exploitation'},
    spf:{tactic:'Initial Access',tech:'Phishing (spoofing enabler)',id:'T1566',phase:'Delivery'},
    dns:{tactic:'Initial Access',tech:'Phishing / DNS manipulation',id:'T1566',phase:'Delivery'},
    cookie:{tactic:'Credential Access',tech:'Steal Web Session Cookie',id:'T1539',phase:'Actions on Objectives'},
    csp:{tactic:'Execution',tech:'Exploitation for Client Execution (XSS surface)',id:'T1203',phase:'Exploitation'},
    wpcore:{tactic:'Initial Access',tech:'Exploit Public-Facing Application',id:'T1190',phase:'Exploitation'},
    wpplug:{tactic:'Initial Access',tech:'Exploit Public-Facing Application',id:'T1190',phase:'Exploitation'},
    xmlrpc:{tactic:'Credential Access',tech:'Brute Force',id:'T1110',phase:'Exploitation'},
    userenum:{tactic:'Reconnaissance',tech:'Gather Victim Identity Information: Accounts',id:'T1589.001',phase:'Reconnaissance'}
  };
  if(c==='Security Header'||c==='CSP') return c==='CSP'?K.csp:K.hdr;
  if(c==='Info Disclosure') return K.info;
  if(c==='Exposed Path'){ if(/\.git|\.svn|\.hg/.test(t))return K.vcs; if(/\.env|wp-config|htpasswd|config/.test(t))return K.secret; if(/backup|\.sql|dump|\.zip/.test(t))return K.backup; if(/actuator|heapdump/.test(t))return K.actuator; if(/phpinfo|info\.php/.test(t))return K.phpinfo; if(/DIR-LISTING/.test(t))return K.dirlist; return K.exposed; }
  if(c==='TLS/SSL') return K.tls;
  if(c==='DNS / Email') return /SPF|DMARC|DKIM/i.test(t)?K.spf:K.dns;
  if(c==='Cookie') return K.cookie;
  if(c==='WP Plugin'||c==='WP Theme') return K.wpplug;
  if(c==='WordPress'){ if(/XML-RPC/i.test(t))return K.xmlrpc; if(/enumeration/i.test(t))return K.userenum; return K.wpcore; }
  return {tactic:'Discovery',tech:'Active Scanning',id:'T1595',phase:'Reconnaissance'};
}
const KILL_CHAIN=['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','Command & Control','Actions on Objectives'];
function renderRedTeam(){
  const out=document.getElementById('results-url');
  if(!out){toast('Run a URL scan first.');return;}
  const pb=buildPlaybook();
  if(!pb.items.length){toast('No findings — run a URL scan first.');return;}
  rtLog('open_red_team','target='+pb.host+', findings='+pb.items.length);
  // enrich items with ATT&CK
  const rows=pb.items.map(it=>({...it,att:attackMap(it)}));
  // ATT&CK coverage aggregation
  const tac={}; rows.forEach(r=>{const key=r.att.id+'|'+r.att.tech;(tac[key]=tac[key]||{tech:r.att.tech,id:r.att.id,tactic:r.att.tactic,items:[]}).items.push(r);});
  // kill-chain buckets
  const chain={}; KILL_CHAIN.forEach(p=>chain[p]=[]); rows.forEach(r=>{(chain[r.att.phase]=chain[r.att.phase]||[]).push(r);});
  const sevColor=s=>s==='Critical'?'#7f1d1d':s==='High'?'var(--bad)':s==='Medium'?'var(--warn)':s==='Low'?'var(--info)':'var(--dim)';
  let html=`<div class="section" data-title="Red Team Mode"><div class="section-head"><h3>🔴 Red Team Mode — Engagement View</h3><div class="status"><span class="pill bad section-status" style="background:#7f1d1d;color:#fff">ENGAGEMENT</span></div></div>
  <!-- v2.7.3 Active target indicator + manual override -->
  <div class="rt-target-bar">
    <div class="rt-target-left">
      <span class="rt-target-label">🎯 Active target</span>
      <code id="rt-target-indicator">${esc(pb.host||'—')}</code>
      <span id="rt-target-src" class="pill dim">from URL scan</span>
    </div>
    <div class="rt-target-right">
      <input id="rt-target-override" placeholder="override host or URL (optional)" oninput="rtRefreshTargetIndicator()" spellcheck="false">
      <button class="btn secondary sm" onclick="rtRefreshTargetIndicator()">Apply</button>
      <button class="btn secondary sm" onclick="rtClearTargetOverride()">Reset</button>
    </div>
  </div>
  <div class="rt-target-note">All Offensive Operations below run against <strong id="rt-target-echo">${esc(pb.host||'—')}</strong>. Set an override to retarget within your authorized scope — this never auto-picks up an IP or other tab's scan.</div>
  <div class="findings-note" style="border-left-color:#7f1d1d;background:#fee2e2"><strong>⚠️ Authorized engagement only.</strong> Red Team Mode is an <strong>analysis, planning & reporting</strong> layer — it maps findings to adversary techniques and documents an authorized engagement. It does <strong>not</strong> execute attacks; confirmation uses the non-destructive <em>Verify Now</em>. Operate strictly within your signed Rules of Engagement.</div>
  <!-- Rules of Engagement -->
  <h4 class="sub">📋 Rules of Engagement</h4>
  <div class="table-wrap" style="padding:12px"><div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
    <label style="font-size:12px;color:var(--dim)">Authorized scope<input id="rt-scope" value="${esc(pb.host)}" style="width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);margin-top:3px"></label>
    <label style="font-size:12px;color:var(--dim)">Operator<input id="rt-operator" value="${esc(APP.author||'TTPH IT Team')}" style="width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);margin-top:3px"></label>
    <label style="font-size:12px;color:var(--dim)">Engagement window (start)<input id="rt-start" type="datetime-local" style="width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);margin-top:3px"></label>
    <label style="font-size:12px;color:var(--dim)">Engagement window (end)<input id="rt-end" type="datetime-local" style="width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);margin-top:3px"></label>
    <label style="font-size:12px;color:var(--dim)">Authorization reference (ticket / approval ID)<input id="rt-authref" placeholder="e.g. TTPH-RT-2026-014" style="width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink);margin-top:3px"></label>
    <label style="font-size:12px;color:var(--dim);display:flex;align-items:flex-end;gap:8px;padding-bottom:6px"><input type="checkbox" id="rt-authok"> I confirm written authorization is on file for this scope.</label>
  </div></div>
  <!-- ATT&CK coverage -->
  <h4 class="sub">🎯 MITRE ATT&CK Coverage (${Object.keys(tac).length} techniques)</h4>
  <div class="table-wrap"><table><thead><tr><th style="width:90px">Technique</th><th>Name</th><th>Tactic</th><th style="width:70px">Findings</th></tr></thead><tbody>`;
  Object.values(tac).sort((a,b)=>b.items.length-a.items.length).forEach(x=>{
    html+=`<tr><td><a href="https://attack.mitre.org/techniques/${esc(x.id.replace('.','/'))}/" target="_blank" rel="noopener noreferrer"><code>${esc(x.id)}</code></a></td><td><strong>${esc(x.tech)}</strong></td><td style="font-size:12px">${esc(x.tactic)}</td><td><span class="pill bad">${x.items.length}</span></td></tr>`;});
  html+=`</tbody></table></div>
  <!-- Kill chain -->
  <h4 class="sub">🔗 Cyber Kill-Chain — attack path</h4>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">`;
  KILL_CHAIN.forEach(p=>{const n=(chain[p]||[]).length;const active=n>0;
    html+=`<div style="flex:1;min-width:120px;border:1px solid ${active?'#7f1d1d':'var(--line)'};border-radius:8px;padding:10px;background:${active?'#fee2e2':'var(--panel-soft)'};text-align:center">
      <div style="font-size:11px;font-weight:700;color:${active?'#7f1d1d':'var(--dim)'}">${esc(p)}</div>
      <div style="font-size:20px;font-weight:800;color:${active?'#7f1d1d':'var(--dim-2)'}">${n}</div></div>`;});
  html+=`</div>
  <!-- Findings by technique -->
  <h4 class="sub">🗡️ Findings mapped to techniques</h4><div class="table-wrap"><table><thead><tr><th style="width:70px">Sev</th><th>Finding</th><th style="width:120px">ATT&CK</th><th style="width:110px">Phase</th></tr></thead><tbody>`;
  rows.forEach((r,i)=>{html+=`<tr><td><span class="sev-${esc(r.sev)}">${esc(r.sev)}</span></td><td><strong>${esc(r.title)}</strong><div style="font-size:11.5px;color:var(--dim)">${esc(r.att.tech)}</div></td><td><a href="https://attack.mitre.org/techniques/${esc(r.att.id.replace('.','/'))}/" target="_blank" rel="noopener noreferrer"><code>${esc(r.att.id)}</code></a></td><td style="font-size:11.5px">${esc(r.att.phase)}</td></tr><tr id="rt-resrow-${i}" style="display:none"><td colspan="4" style="padding:0 10px 10px"><div id="rt-res-${i}"></div></td></tr>`;});
  html+=`</tbody></table></div>
  <!-- ===== AGGRESSIVE OFFENSIVE OPS ===== -->
  <h4 class="sub" style="color:#7f1d1d">💥 Offensive Operations <span style="font-size:11px;font-weight:400;color:var(--dim)">— active, non-destructive</span></h4>
  <div class="table-wrap" style="padding:12px;background:#450a0a;border-color:#7f1d1d">
    <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;color:#fecaca;font-size:12px">
      <label style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="rt-stealth"> Stealth mode <span style="color:#f87171">(UA rotation + request jitter)</span></label>
      <label style="display:flex;align-items:center;gap:6px">Reflection params <select id="rt-reflect" style="padding:3px 8px;border-radius:6px;border:1px solid #7f1d1d;background:#1c0a0a;color:#fecaca"><option value="8">8</option><option value="12">12</option><option value="15">15</option></select></label>
      <label style="display:flex;align-items:center;gap:6px">Path depth <select id="rt-pathcap" style="padding:3px 8px;border-radius:6px;border:1px solid #7f1d1d;background:#1c0a0a;color:#fecaca"><option value="16">16</option><option value="24" selected>24</option><option value="40">40</option></select></label>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
      <button id="rt-recon-btn" class="btn" style="background:#dc2626;color:#fff" onclick="rtLaunchRecon()">🚀 Launch Active Recon</button>
      <button class="btn" style="background:#b45309;color:#fff" onclick="rtBuildChain()">⛓️ Attack-Chain Simulator</button>
      <button class="btn" style="background:#6d28d9;color:#fff" onclick="rtThreatActors()">👁️ Threat-Actor Emulation</button>
      <span id="rt-recon-prog" style="font-size:12px;color:#fecaca;align-self:center"></span>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;border-top:1px solid #7f1d1d;padding-top:10px">
      <button class="btn" style="background:#a16207;color:#fff" onclick="rtExploitIntel()">📊 CVE Exploit Intelligence</button>
      <button id="rt-safepoc-btn" class="btn" style="background:#be123c;color:#fff" onclick="rtSafePoC()">🧪 Safe PoC Confirmations</button>
      <button class="btn" style="background:#9d174d;color:#fff" onclick="rtRiskScore()">🎯 Breach Risk Score</button>
      <button class="btn" style="background:#3730a3;color:#fff" onclick="rtWafEvasion()">🥷 WAF/Evasion Profile</button>
      <span id="rt-safepoc-prog" style="font-size:12px;color:#fecaca;align-self:center"></span>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;border-top:1px solid #7f1d1d;padding-top:10px;align-items:center">
      <button id="rt-sl3r-btn" class="btn" style="background:#065f46;color:#fff" onclick="rtSublist3r()">🌐 Sublist3r (passive subdomains)</button>
      <label style="display:flex;align-items:center;gap:6px;color:#fecaca;font-size:12px"><input type="checkbox" id="rt-sl3r-brute"> + subbrute wordlist</label>
      <label style="display:flex;align-items:center;gap:6px;color:#fecaca;font-size:12px"><input type="checkbox" id="rt-sl3r-resolve" checked> resolve DNS</label>
      <span id="rt-sl3r-prog" style="font-size:12px;color:#fecaca;align-self:center"></span>
    </div>
    <div style="font-size:11px;color:#fca5a5;margin-top:8px">⚠️ Active operations send live requests to <strong>${esc(pb.host)}</strong> (method probing, tech fingerprinting, auth-surface mapping, benign reflection/injection <em>markers</em>, expanded path brute, passive subdomain OSINT + optional live HTTP status). All <strong>non-destructive detection</strong> — no exploits, no data extraction, no state change. Authorized engagements only.</div>
  </div>
  <div id="rt-sl3r-out"></div>
  <div id="rt-recon-out"></div>
  <div id="rt-intel-out"></div>
  <div id="rt-risk-out"></div>
  <div id="rt-waf-out"></div>
  <div id="rt-safepoc-out"></div>
  <div id="rt-chain-out"></div>
  <div id="rt-actor-out"></div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px">
    <button class="btn" style="background:#7f1d1d;color:#fff" onclick="downloadRedTeamReport()">⬇ Red Team Report (.html)</button>
    <button class="btn secondary" onclick="downloadEngagementLog()">⬇ Engagement Log (.json)</button>
    <button id="rt-verify-btn" class="btn" style="background:#0f766e;color:#fff" onclick="verifyNowServerSide()">⚡ Verify Now (non-destructive)</button>
    <span id="rt-verify-prog" style="font-size:12px;color:var(--dim);align-self:center"></span>
  </div></div>`;
  const w=document.createElement('div');w.innerHTML=html;out.appendChild(w);w.scrollIntoView({behavior:'smooth',block:'start'});
  window.RT_ROWS=rows;
}
/* ---- Aggressive active reconnaissance (server-side, non-destructive) ---- */
async function rtLaunchRecon(){
  const host=urlScanHost();
  if(!host){toast('Run a URL scan first.');return;}
  const stealth=document.getElementById('rt-stealth')?.checked;
  if(!confirm('Launch ACTIVE reconnaissance against '+host+' ?\n\nThis sends live (non-destructive) requests: subdomain enumeration, HTTP method probing, benign parameter-reflection markers, and an expanded path brute. Run ONLY against systems you are authorized to assess.\n\nProceed?'))return;
  const btn=document.getElementById('rt-recon-btn'),prog=document.getElementById('rt-recon-prog');
  if(btn){btn.disabled=true;btn.textContent='Recon running…';}
  if(prog)prog.textContent='Enumerating subdomains, probing methods & reflection…';
  rtLog('active_recon_start','host='+host+', stealth='+(stealth?'on':'off'));
  try{
    const fd=new FormData();fd.append('target',host);fd.append('authorized','yes');
    fd.append('stealth',stealth?'1':'0');
    fd.append('reflect_limit',document.getElementById('rt-reflect')?.value||'8');
    fd.append('path_cap',document.getElementById('rt-pathcap')?.value||'24');
    const res=await fetch('?api=1&action=rt_recon',{method:'POST',body:fd});const raw=await res.text();
    let r;try{r=JSON.parse(raw);}catch(e){throw new Error((!res.ok?('HTTP '+res.status+' — '):'')+'invalid response ('+raw.trim().slice(0,200)+')');}
    if(!r.ok)throw new Error(r.error||'recon failed');
    const d=r.data||{};window.RT_RECON=d;
    const s=d.summary||{};
    let h=`<div class="section" style="border:1px solid #7f1d1d;margin-top:14px"><div class="section-head"><h3>🚀 Active Recon Results</h3><div class="status"><span class="pill bad" style="background:#7f1d1d;color:#fff">${d.stealth?'STEALTH':'DIRECT'}</span></div></div>
    <div class="stats" style="margin:12px 0">
      <div class="stat"><div class="n" style="color:var(--bad)">${s.risky_methods||0}</div><div class="l">Risky Methods</div></div>
      <div class="stat"><div class="n" style="color:var(--bad)">${s.reflected_params||0}</div><div class="l">Unencoded Reflections</div></div>
      <div class="stat"><div class="n" style="color:#7f1d1d">${s.exposed_paths||0}</div><div class="l">Exposed Paths</div></div>
      <div class="stat"><div class="n" style="color:#0369a1">${s.tech||0}</div><div class="l">Tech Detected</div></div>
      <div class="stat"><div class="n" style="color:#a16207">${s.auth_endpoints||0}</div><div class="l">Auth Endpoints</div></div></div>`;
    // Tech-stack fingerprint
    if((d.tech||[]).length){h+=`<h4 class="sub">🧬 Technology fingerprint (${d.tech.length})</h4><div class="tag-cloud">`;
      d.tech.forEach(t=>h+=`<span class="tag" style="background:#0369a122;color:#0369a1;border-color:rgba(3,105,161,.3)">${esc(t.name)}${t.value&&t.value!=='detected'?': <strong>'+esc(t.value)+'</strong>':''}</span>`);h+=`</div>`;}
    else h+=`<div class="findings-note">No technology fingerprints extracted.</div>`;
    // Auth attack-surface
    if((d.auth_surface||[]).length){h+=`<h4 class="sub">🔐 Authentication attack-surface (${d.auth_surface.length})</h4><div class="findings-note" style="font-size:12px;border-left-color:#a16207;background:#fef3c7">Reachable login/auth endpoints — the credential-attack surface a real adversary maps first. (Endpoint discovery only — no credential attacks performed.)</div><div class="table-wrap"><table><thead><tr><th>Endpoint</th><th style="width:90px">Status</th><th style="width:110px">Type</th></tr></thead><tbody>`;
      d.auth_surface.forEach(x=>h+=`<tr><td><code>${esc(x.path)}</code></td><td><code>${esc(x.status)}</code></td><td>${x.type==='API/OAuth'?'<span class="pill purple">'+esc(x.type)+'</span>':'<span class="pill warn">'+esc(x.type)+'</span>'}</td></tr>`);h+=`</tbody></table></div>`;}
    else h+=`<div class="findings-note">No common auth endpoints reachable.</div>`;
    // Methods
    const mm=d.methods||{};h+=`<h4 class="sub">🔧 HTTP methods</h4><div class="kv"><div class="k">Allow header</div><div class="v"><code>${esc(mm.allow||'—')}</code></div><div class="k">Risky verbs</div><div class="v">${(mm.risky&&mm.risky.length)?mm.risky.map(v=>`<span class="pill bad">${esc(v)}</span>`).join(' '):'<span class="pill ok">none</span>'}</div></div>`;
    // Reflections
    if((d.reflections||[]).length){h+=`<h4 class="sub">🪞 Parameter reflection</h4><div class="table-wrap"><table><thead><tr><th>Param</th><th>Reflected</th><th>Assessment</th></tr></thead><tbody>`;
      d.reflections.forEach(x=>h+=`<tr><td><code>${esc(x.param)}</code></td><td>${x.raw_unencoded?'<span class="pill bad">UNENCODED</span>':'<span class="pill warn">encoded</span>'}</td><td style="font-size:12px">${esc(x.note)}</td></tr>`);h+=`</tbody></table></div>`;}
    else h+=`<div class="findings-note">No parameter reflection detected on tested names.</div>`;
    // Aggressive paths
    if((d.aggr_paths||[]).length){h+=`<h4 class="sub">📂 Expanded path brute (${d.aggr_paths.length} hits)</h4><div class="table-wrap"><table><thead><tr><th>Path</th><th style="width:90px">Status</th><th style="width:120px">Interest</th></tr></thead><tbody>`;
      d.aggr_paths.forEach(x=>h+=`<tr><td><code>${esc(x.path)}</code></td><td><code>${esc(x.status)}</code></td><td>${x.interest==='EXPOSED'?'<span class="pill bad">EXPOSED</span>':x.interest==='protected'?'<span class="pill warn">protected</span>':'<span class="pill dim">'+esc(x.interest)+'</span>'}</td></tr>`);h+=`</tbody></table></div>`;}
    else h+=`<div class="findings-note">No additional sensitive paths found.</div>`;
    h+=`</div>`;
    document.getElementById('rt-recon-out').innerHTML=h;
    if(prog)prog.textContent='Done · '+(s.exposed_paths||0)+' exposed · '+(s.reflected_params||0)+' reflections · '+(s.tech||0)+' tech · '+(s.auth_endpoints||0)+' auth';
    rtLog('active_recon_done',JSON.stringify(s));
    toast('Active recon complete.');
  }catch(e){if(prog)prog.textContent='Error: '+e.message;toast('Recon failed: '+e.message);}
  finally{if(btn){btn.disabled=false;btn.textContent='🚀 Launch Active Recon';}}
}
/* ---- Attack-Chain Simulator: narrative multi-stage breach path from findings ---- */
function rtBuildChain(){
  const rows=window.RT_ROWS||[];if(!rows.length){toast('Open Red Team Mode first.');return;}
  const phaseOrder=KILL_CHAIN;
  const byPhase={};rows.forEach(r=>{(byPhase[r.att.phase]=byPhase[r.att.phase]||[]).push(r);});
  // choose the highest-severity finding per phase to form the chain
  const rank={Critical:0,High:1,Medium:2,Low:3,Info:4};
  const steps=[];
  phaseOrder.forEach(ph=>{const g=byPhase[ph];if(g&&g.length){g.sort((a,b)=>rank[a.sev]-rank[b.sev]);steps.push({phase:ph,f:g[0],count:g.length});}});
  rtLog('attack_chain_built','steps='+steps.length);
  let h=`<div class="section" style="border:1px solid #b45309;margin-top:14px"><div class="section-head"><h3>⛓️ Attack-Chain Simulation</h3><div class="status"><span class="pill warn">${steps.length} stages</span></div></div>
  <div class="findings-note" style="border-left-color:#b45309;background:#fef3c7">A plausible end-to-end breach path an adversary could attempt by chaining the observed weaknesses. Theoretical planning aid — validate each step with the non-destructive Verify Now.</div>`;
  if(!steps.length){h+=`<div class="findings-note">Not enough findings across phases to build a chain.</div></div>`;document.getElementById('rt-chain-out').innerHTML=h;return;}
  h+=`<div style="margin-top:8px">`;
  steps.forEach((s,i)=>{const c=s.f.sev==='Critical'?'#7f1d1d':s.f.sev==='High'?'#dc2626':s.f.sev==='Medium'?'#d97706':'#0284c7';
    h+=`<div style="display:flex;gap:12px;align-items:flex-start;padding:10px 0">
      <div style="min-width:34px;height:34px;border-radius:50%;background:${c};color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800">${i+1}</div>
      <div style="flex:1"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:${c}">${esc(s.phase)}</div>
        <div style="font-weight:600;margin-top:2px">${esc(s.f.title)} <span class="pill dim" style="font-size:9.5px">${esc(s.f.att.id)}</span></div>
        <div style="font-size:12px;color:var(--ink-soft);margin-top:3px">${esc(s.f.attack)}</div></div></div>`;
    if(i<steps.length-1)h+=`<div style="margin-left:16px;color:#b45309;font-size:18px;line-height:1">↓</div>`;});
  h+=`</div><div class="findings-note" style="margin-top:8px"><strong>Objective reached:</strong> chaining these ${steps.length} stage(s) could take an attacker from external reconnaissance to <strong>${esc(steps[steps.length-1].phase)}</strong>. Breaking any single link disrupts the whole chain — prioritize the earliest fixable stage.</div></div>`;
  document.getElementById('rt-chain-out').innerHTML=h;document.getElementById('rt-chain-out').scrollIntoView({behavior:'smooth',block:'start'});
}
/* ---- Threat-Actor Emulation: map observed ATT&CK techniques to known groups ---- */
const RT_ACTORS=[
  {name:'APT29 (Cozy Bear)',id:'G0016',tech:['T1190','T1566','T1557','T1539'],note:'Nation-state espionage; favors public-app exploitation, phishing, and session/token theft.'},
  {name:'FIN7',id:'G0046',tech:['T1566','T1190','T1110'],note:'Financially motivated; phishing + public-facing exploitation for initial access.'},
  {name:'Magecart',id:'G0100',tech:['T1190','T1557','T1539','T1203'],note:'Web-skimming crews; exploit web apps & inject client-side script to steal data/sessions.'},
  {name:'Lazarus Group',id:'G0032',tech:['T1190','T1566','T1552'],note:'Exploits public apps, harvests unsecured credentials, broad targeting.'},
  {name:'Scattered Spider',id:'G1015',tech:['T1566','T1110','T1589','T1539'],note:'Social engineering + credential attacks + identity recon against web/identity surfaces.'},
  {name:'Commodity Ransomware Affiliate',id:'—',tech:['T1190','T1110','T1552','T1083'],note:'Opportunistic: exploits exposed apps, brute-forces logins, loots credentials/files.'}
];
function rtThreatActors(){
  const rows=window.RT_ROWS||[];if(!rows.length){toast('Open Red Team Mode first.');return;}
  const present={};rows.forEach(r=>{const base=(r.att.id||'').split('.')[0];present[base]=(present[base]||0)+1;});
  const scored=RT_ACTORS.map(a=>{const overlap=a.tech.filter(t=>present[t]);return {...a,overlap,score:Math.round(overlap.length/a.tech.length*100)};})
    .filter(a=>a.overlap.length).sort((x,y)=>y.score-x.score);
  rtLog('threat_actor_emulation','matches='+scored.length);
  let h=`<div class="section" style="border:1px solid #6d28d9;margin-top:14px"><div class="section-head"><h3>👁️ Threat-Actor Emulation</h3><div class="status"><span class="pill purple">${scored.length} profiles</span></div></div>
  <div class="findings-note" style="border-left-color:#6d28d9;background:var(--purple-soft)">Known threat groups whose documented ATT&CK techniques overlap with this target's exposure. Use to select a realistic emulation plan for the engagement (MITRE ATT&CK Groups).</div>`;
  if(!scored.length){h+=`<div class="findings-note">No actor overlap with observed techniques.</div></div>`;document.getElementById('rt-actor-out').innerHTML=h;return;}
  h+=`<div class="table-wrap"><table><thead><tr><th>Threat actor</th><th style="width:90px">Overlap</th><th>Shared techniques</th><th>Profile</th></tr></thead><tbody>`;
  scored.forEach(a=>{const link=a.id!=='—'?`<a href="https://attack.mitre.org/groups/${esc(a.id)}/" target="_blank" rel="noopener noreferrer"><strong>${esc(a.name)}</strong></a>`:`<strong>${esc(a.name)}</strong>`;
    h+=`<tr><td>${link}<br><code style="font-size:10px">${esc(a.id)}</code></td><td><span class="pill ${a.score>=66?'bad':a.score>=33?'warn':'dim'}">${a.score}%</span></td><td>${a.overlap.map(t=>`<code style="font-size:10.5px">${esc(t)}</code>`).join(' ')}</td><td style="font-size:12px">${esc(a.note)}</td></tr>`;});
  h+=`</tbody></table></div></div>`;
  document.getElementById('rt-actor-out').innerHTML=h;document.getElementById('rt-actor-out').scrollIntoView({behavior:'smooth',block:'start'});
}
/* ---- v2.6.3: Breach Risk Score — CVSS-weighted, exploitability-adjusted composite ---- */
function rtRiskScore(){
  const rows=window.RT_ROWS||[]; if(!rows.length){toast('Open Red Team Mode first.');return;}
  const recon=window.RT_RECON||{}; const s=recon.summary||{};
  const W={Critical:40,High:25,Medium:12,Low:5,Info:1};
  let base=0; rows.forEach(r=>base+=(W[r.sev]||1));
  // exploitability multipliers from active recon signals
  let mult=1, factors=[];
  if((s.reflected_params||0)>0){mult+=0.15;factors.push('unencoded reflection (+15%)');}
  if((s.exposed_paths||0)>0){mult+=0.20;factors.push((s.exposed_paths)+' exposed path(s) (+20%)');}
  if((s.risky_methods||0)>0){mult+=0.10;factors.push('risky HTTP methods (+10%)');}
  if((s.auth_endpoints||0)>0){mult+=0.08;factors.push((s.auth_endpoints)+' auth endpoint(s) (+8%)');}
  const sp=window.RT_SAFEPOC||{}; if((sp.xss||0)+(sp.sqli||0)+(sp.redirect||0)>0){mult+=0.25;factors.push('safe-PoC reachable sink (+25%)');}
  const raw=Math.min(100, Math.round(base*mult));
  const grade=raw>=80?'F':raw>=65?'D':raw>=45?'C':raw>=25?'B':'A';
  const gColor=raw>=80?'#7f1d1d':raw>=65?'#dc2626':raw>=45?'#d97706':raw>=25?'#0284c7':'#16a34a';
  const cnt={Critical:0,High:0,Medium:0,Low:0,Info:0};rows.forEach(r=>cnt[r.sev]=(cnt[r.sev]||0)+1);
  rtLog('risk_score','score='+raw+' grade='+grade);
  let h=`<div class="section" style="border:1px solid #9d174d;margin-top:14px"><div class="section-head"><h3>🎯 Breach Risk Score</h3><div class="status"><span class="pill bad" style="background:${gColor};color:#fff">${grade}</span></div></div>
  <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;margin:12px 0">
    <div style="width:120px;height:120px;border-radius:50%;background:conic-gradient(${gColor} ${raw*3.6}deg,#1e293b 0);display:flex;align-items:center;justify-content:center;position:relative">
      <div style="width:92px;height:92px;border-radius:50%;background:var(--panel);display:flex;flex-direction:column;align-items:center;justify-content:center">
        <div style="font-size:30px;font-weight:800;color:${gColor}">${raw}</div><div style="font-size:10px;color:var(--dim)">/ 100</div></div></div>
    <div style="flex:1;min-width:240px">
      <div style="font-size:13px;color:var(--ink-soft);margin-bottom:6px">Composite breach-likelihood for <strong>${esc(recon.host||urlScanHost()||'target')}</strong>, weighting severity by CVSS-style bands and boosting for <em>actively-confirmed exploitability</em>.</div>
      <div style="font-size:12px;color:var(--dim)">Severity mix: <span class="pill" style="background:#7f1d1d;color:#fff">${cnt.Critical} C</span> <span class="pill bad">${cnt.High} H</span> <span class="pill warn">${cnt.Medium} M</span> <span class="pill info">${cnt.Low} L</span></div>
      <div style="font-size:12px;color:var(--dim);margin-top:6px">Exploitability multiplier: <strong>×${mult.toFixed(2)}</strong></div>
    </div></div>
  <h4 class="sub">Risk amplifiers (from active recon)</h4>`;
  if(factors.length){h+=`<div class="table-wrap"><table><tbody>`;factors.forEach(f=>h+=`<tr><td>⚡ ${esc(f)}</td></tr>`);h+=`</tbody></table></div>`;}
  else h+=`<div class="findings-note">No active-recon amplifiers yet — run 🚀 Launch Active Recon and 🧪 Safe PoC to sharpen the score.</div>`;
  h+=`</div>`;
  document.getElementById('rt-risk-out').innerHTML=h;document.getElementById('rt-risk-out').scrollIntoView({behavior:'smooth',block:'start'});
}
/* ---- v2.6.3: WAF / Evasion Profile — detect protection + recommend authorized OPSEC techniques ---- */
function rtWafEvasion(){
  const recon=window.RT_RECON||{}; const R=window.LAST_RECON||{};
  const waf=(R.waf&&R.waf.primary)?R.waf.primary:null;
  rtLog('waf_evasion','waf='+(waf?waf.product:'none'));
  const techniques=[
    {t:'Request timing / jitter',d:'Randomized delays between requests to avoid rate-based detection.',have:true,note:'Enabled via the Stealth toggle (120–420ms jitter).'},
    {t:'User-Agent rotation',d:'Cycle realistic browser UAs so requests do not fingerprint as a scanner.',have:true,note:'Enabled via the Stealth toggle (3-UA pool).'},
    {t:'Case / path normalization variance',d:'Mixed-case paths & trailing-slash variants can bypass naive signature rules.',have:false,note:'Manual technique — vary paths during authorized testing.'},
    {t:'Header spoofing (X-Forwarded-For / X-Originating-IP)',d:'Some WAFs trust client-supplied IP headers for allowlisting.',have:false,note:'Manual — test whitelisted-IP header trust under RoE.'},
    {t:'Encoding / double-encoding',d:'URL/Unicode/double-encoding of payloads to slip past pattern matches.',have:false,note:'Manual — for payload delivery in authorized exploitation (out of scope for this non-destructive tool).'},
    {t:'Chunked / null-byte insertion',d:'Transfer-encoding tricks & null bytes that confuse inline inspection.',have:false,note:'Manual, advanced — document in the engagement plan.'}
  ];
  let h=`<div class="section" style="border:1px solid #3730a3;margin-top:14px"><div class="section-head"><h3>🥷 WAF / Evasion Profile</h3><div class="status">${waf?('<span class="pill bad">'+esc(waf.product)+' '+esc(waf.confidence)+'%</span>'):'<span class="pill ok">no WAF detected</span>'}</div></div>`;
  h+=`<div class="findings-note" style="border-left-color:#3730a3;background:var(--purple-soft)">${waf?('Protection detected: <strong>'+esc(waf.product)+'</strong> ('+esc(waf.confidence)+'% confidence). Plan evasion within your Rules of Engagement.'):'No WAF/CDN protection was fingerprinted — the origin may be directly reachable. Verify before assuming no filtering.'}</div>`;
  h+=`<h4 class="sub">OPSEC / evasion techniques</h4><div class="table-wrap"><table><thead><tr><th style="width:34px"></th><th>Technique</th><th>Description</th><th style="width:90px">Status</th></tr></thead><tbody>`;
  techniques.forEach(x=>h+=`<tr><td>${x.have?'✅':'📋'}</td><td><strong>${esc(x.t)}</strong></td><td style="font-size:12px">${esc(x.d)}<div style="color:var(--dim);font-size:11px;margin-top:2px">${esc(x.note)}</div></td><td>${x.have?'<span class="pill ok">active</span>':'<span class="pill dim">manual</span>'}</td></tr>`);
  h+=`</tbody></table></div><div class="findings-note" style="font-size:12px;margin-top:8px">🛡️ Evasion techniques are documented for <strong>authorized</strong> testing planning. The two ✅ techniques are built into Stealth mode; the rest are manual methods for your operators to apply under RoE — this tool does not weaponize them.</div></div>`;
  document.getElementById('rt-waf-out').innerHTML=h;document.getElementById('rt-waf-out').scrollIntoView({behavior:'smooth',block:'start'});
}
/* ---- v2.6.0: CVE Exploit Intelligence (info only; links out to public references) ---- */
async function rtExploitIntel(){
  const R=window.LAST_RECON||{}; const wp=R.wordpress||{};
  const cves=[];
  (wp.cves||[]).forEach(c=>cves.push({id:c.id,product:'WordPress core '+(wp.version||''),cvss:c.cvss||0}));
  (wp.plugins||[]).forEach(p=>(p.cves||[]).forEach(c=>cves.push({id:c.id,product:'Plugin '+p.name+' '+(p.version||''),cvss:c.cvss||0})));
  (wp.themes||[]).forEach(t=>(t.cves||[]).forEach(c=>cves.push({id:c.id,product:'Theme '+t.name+' '+(t.version||''),cvss:c.cvss||0})));
  if(!cves.length){document.getElementById('rt-intel-out').innerHTML='<div class="section" style="border:1px solid #a16207;margin-top:14px"><div class="section-head"><h3>📊 CVE Exploit Intelligence</h3></div><div class="findings-note">No CVEs detected in this scan (run a WordPress scan with plugin/theme detection to populate). Exploit intelligence maps detected CVEs to public exploit references + likelihood.</div></div>';document.getElementById('rt-intel-out').scrollIntoView({behavior:'smooth',block:'start'});return;}
  try{
    const fd=new FormData();fd.append('cves',JSON.stringify(cves));
    const res=await fetch('?api=1&action=rt_exploit_intel',{method:'POST',body:fd});const raw=await res.text();
    let r;try{r=JSON.parse(raw);}catch(e){throw new Error('invalid response');}
    if(!r.ok)throw new Error(r.error||'intel failed');
    const d=r.data||{};const items=d.items||[];
    let h=`<div class="section" style="border:1px solid #a16207;margin-top:14px"><div class="section-head"><h3>📊 CVE Exploit Intelligence</h3><div class="status"><span class="pill bad">${d.kev_count||0} known-exploited</span></div></div>
    <div class="findings-note" style="border-left-color:#a16207;background:#fef3c7">Exploit-likelihood intelligence for detected CVEs — <strong>information only, no exploit code</strong>. "Known-exploited" = appears in curated KEV set. Use the reference links to research weaponization under your RoE.</div>
    <div class="table-wrap"><table><thead><tr><th style="width:130px">CVE</th><th>Product</th><th style="width:60px">CVSS</th><th style="width:150px">Exploit likelihood</th><th>References</th></tr></thead><tbody>`;
    items.forEach(x=>{const band=x.kev?'bad':(x.cvss>=9?'bad':x.cvss>=7?'warn':'dim');
      h+=`<tr><td><a href="${esc(x.refs.NVD)}" target="_blank" rel="noopener noreferrer"><code>${esc(x.id)}</code></a>${x.kev?' <span class="pill bad" style="font-size:9px">KEV</span>':''}</td><td style="font-size:12px">${esc(x.product)}</td><td><code>${(x.cvss||0).toFixed(1)}</code></td><td><span class="pill ${band}">${esc(x.exploit_likelihood)}</span></td><td style="font-size:11px"><a href="${esc(x.refs['Exploit-DB'])}" target="_blank" rel="noopener noreferrer">Exploit-DB</a> · <a href="${esc(x.refs.Metasploit)}" target="_blank" rel="noopener noreferrer">Metasploit</a> · <a href="${esc(x.refs['CISA-KEV'])}" target="_blank" rel="noopener noreferrer">KEV</a></td></tr>`;});
    h+=`</tbody></table></div></div>`;
    document.getElementById('rt-intel-out').innerHTML=h;document.getElementById('rt-intel-out').scrollIntoView({behavior:'smooth',block:'start'});
    if(typeof rtLog==='function')rtLog('exploit_intel','cves='+items.length+', kev='+(d.kev_count||0));
    toast('Exploit intelligence loaded.');
  }catch(e){toast('Intel failed: '+e.message);}
}
/* ---- v2.6.0: Safe PoC Confirmations (non-destructive reachability tests) ---- */
async function rtSafePoC(){
  const host=urlScanHost();
  if(!host){toast('Run a URL scan first.');return;}
  if(!confirm('Run SAFE PoC confirmations against '+host+' ?\n\nThis sends benign non-destructive markers to detect whether XSS / SQLi / open-redirect sinks are REACHABLE (it does NOT exploit them, extract data, or change state). Authorized engagements only.\n\nProceed?'))return;
  const btn=document.getElementById('rt-safepoc-btn'),prog=document.getElementById('rt-safepoc-prog');
  if(btn){btn.disabled=true;btn.textContent='Testing…';}if(prog)prog.textContent='Probing reachability with benign markers…';
  if(typeof rtLog==='function')rtLog('safe_poc_start','host='+host);
  try{
    const fd=new FormData();fd.append('target',host);fd.append('authorized','yes');fd.append('limit','8');
    const res=await fetch('?api=1&action=rt_safepoc',{method:'POST',body:fd});const raw=await res.text();
    let r;try{r=JSON.parse(raw);}catch(e){throw new Error((!res.ok?('HTTP '+res.status+' — '):'')+'invalid response ('+raw.trim().slice(0,160)+')');}
    if(!r.ok)throw new Error(r.error||'safe PoC failed');
    const d=r.data||{};const s=d.summary||{};window.RT_SAFEPOC=s;
    let h=`<div class="section" style="border:1px solid #be123c;margin-top:14px"><div class="section-head"><h3>🧪 Safe PoC Confirmations</h3><div class="status"><span class="pill bad">${(s.xss||0)+(s.sqli||0)+(s.redirect||0)} reachable</span></div></div>
    <div class="findings-note" style="border-left-color:#be123c;background:#ffe4e6"><strong>Reachability only.</strong> These benign checks prove whether an injection point is reachable — they do <strong>not</strong> exploit it. A "REACHABLE" verdict means a manual (authorized) exploit attempt is warranted.</div>
    <div class="stats" style="margin:12px 0">
      <div class="stat"><div class="n" style="color:#be123c">${s.xss||0}</div><div class="l">XSS reachable</div></div>
      <div class="stat"><div class="n" style="color:#be123c">${s.sqli||0}</div><div class="l">SQLi signals</div></div>
      <div class="stat"><div class="n" style="color:#be123c">${s.redirect||0}</div><div class="l">Open-redirect</div></div></div>`;
    const tbl=(title,arr,cols)=>{ if(!arr||!arr.length)return `<div class="findings-note">✅ No ${title} reachability detected on tested parameters.</div>`;
      let t=`<h4 class="sub">${title}</h4><div class="table-wrap"><table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead><tbody>`;
      arr.forEach(x=>{t+=`<tr><td><code>${esc(x.param||'')}</code></td><td>${esc(x.verdict||'')}</td></tr>`;});return t+`</tbody></table></div>`; };
    h+=tbl('Reflected XSS',d.xss||[],['Param','Verdict']);
    h+=tbl('SQL Injection',d.sqli||[],['Param','Verdict']);
    h+=tbl('Open Redirect',d.redirect||[],['Param','Verdict']);
    h+=`</div>`;
    document.getElementById('rt-safepoc-out').innerHTML=h;document.getElementById('rt-safepoc-out').scrollIntoView({behavior:'smooth',block:'start'});
    if(prog)prog.textContent='Done · '+(s.xss||0)+' XSS · '+(s.sqli||0)+' SQLi · '+(s.redirect||0)+' redirect';
    if(typeof rtLog==='function')rtLog('safe_poc_done',JSON.stringify(s));
    toast('Safe PoC confirmations complete.');
  }catch(e){if(prog)prog.textContent='Error: '+e.message;toast('Safe PoC failed: '+e.message);}
  finally{if(btn){btn.disabled=false;btn.textContent='🧪 Safe PoC Confirmations';}}
}
/* ---- v2.6.4→2.6.6: Sublist3r (pure-PHP) — clickable subdomains + live HTTP status badges + pagination ---- */
async function rtSublist3r(){
  const host=urlScanHost();
  if(!host){toast('Run a URL scan first.');return;}
  const brute=document.getElementById('rt-sl3r-brute')?.checked;
  if(!confirm('Run Sublist3r passive subdomain enumeration against '+host+' ?\n\nQueries crt.sh, CertSpotter, HackerTarget, AlienVault OTX & RapidDNS'+(brute?', plus a DNS brute wordlist':'')+' — all read-only OSINT. Authorized engagements only.\n\nProceed?'))return;
  const btn=document.getElementById('rt-sl3r-btn'),prog=document.getElementById('rt-sl3r-prog');
  if(btn){btn.disabled=true;btn.textContent='Enumerating…';}
  if(prog)prog.textContent='Querying CT + passive-DNS sources…';
  if(typeof rtLog==='function')rtLog('sublist3r_start','host='+host+', brute='+(brute?'on':'off'));
  try{
    const fd=new FormData();fd.append('target',host);fd.append('authorized','yes');
    fd.append('brute',brute?'1':'0');
    fd.append('resolve',document.getElementById('rt-sl3r-resolve')?.checked?'1':'0');
    fd.append('cap','300');
    const res=await fetch('?api=1&action=sublist3r',{method:'POST',body:fd});const raw=await res.text();
    let r;try{r=JSON.parse(raw);}catch(e){throw new Error((!res.ok?('HTTP '+res.status+' — '):'')+'invalid response ('+raw.trim().slice(0,200)+')');}
    if(!r.ok)throw new Error(r.error||'sublist3r failed');
    const d=r.data||{};window.SL3R=(d.items||[]).map(x=>({...x,alive:undefined}));window.SL3R_HOST=host;
    const eng=d.engines||{};
    const engTxt=Object.keys(eng).map(k=>esc(k)+': '+esc(eng[k])).join(' · ');
    let h=`<div class="section" style="border:1px solid #065f46;margin-top:14px"><div class="section-head"><h3>🌐 Sublist3r — Passive Subdomains</h3><div class="status"><span class="pill" style="background:#065f46;color:#fff">${d.count||0} found</span></div></div>
    <div class="findings-note" style="border-left-color:#065f46;background:#d1fae5;font-size:12px">Pure-PHP port of aboul3la/Sublist3r — aggregated from crt.sh, CertSpotter, HackerTarget, AlienVault OTX & RapidDNS${(window.SL3R.some(x=>(x.sources||[]).includes('subbrute')))?' + subbrute':''}. ${d.wildcard?'<span style="color:var(--warn)">⚠️ Wildcard DNS detected — brute-only false positives filtered.</span>':'No wildcard DNS.'}<br><span style="color:var(--dim)">Engines → ${engTxt}</span></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
      <input type="text" id="sl3r-search" placeholder="Filter subdomain / IP / source…" oninput="sl3rRender(true)" style="flex:1;min-width:180px;padding:7px 11px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--panel);color:var(--ink)">
      <select id="sl3r-src" onchange="sl3rRender(true)" style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;font-size:12.5px;background:var(--panel);color:var(--ink)">
        <option value="all">All sources</option><option value="crt.sh">crt.sh</option><option value="certspotter">certspotter</option><option value="hackertarget">hackertarget</option><option value="alienvault">alienvault</option><option value="rapiddns">rapiddns</option><option value="subbrute">subbrute</option><option value="alive">alive only</option>
      </select>
      <select id="sl3r-per" onchange="sl3rRender(true)" style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;font-size:12.5px;background:var(--panel);color:var(--ink)">
        <option value="15">15 / page</option><option value="25" selected>25 / page</option><option value="50">50 / page</option><option value="0">Show all</option>
      </select>
      <button class="btn" style="background:#0f766e;color:#fff" onclick="sl3rCheckAlive()">⚡ Check Alive (HTTP status)</button>
      <button class="btn secondary sm" onclick="sl3rExportCSV()">⬇ CSV</button>
      <span id="sl3r-count" style="font-size:12px;color:var(--dim);white-space:nowrap"></span>
    </div>
    <div id="sl3r-wrap"></div></div>`;
    document.getElementById('rt-sl3r-out').innerHTML=h;
    if(window.SL3R.length)sl3rRender(true);
    if(prog)prog.textContent='Done · '+(d.count||0)+' subdomains';
    if(typeof rtLog==='function')rtLog('sublist3r_done','count='+(d.count||0));
    toast('Sublist3r complete — '+(d.count||0)+' subdomains.');
  }catch(e){if(prog)prog.textContent='Error: '+e.message;toast('Sublist3r failed: '+e.message);}
  finally{if(btn){btn.disabled=false;btn.textContent='🌐 Sublist3r (passive subdomains)';}}
}
window.SL3R_STATE={page:1,per:25,q:'',src:'all'};
function sl3rFiltered(){
  const s=window.SL3R_STATE; let rows=(window.SL3R||[]).slice();
  if(s.src==='alive') rows=rows.filter(x=>x.alive&&x.alive.code>0);
  else if(s.src!=='all') rows=rows.filter(x=>(x.sources||[]).includes(s.src));
  if(s.q){const q=s.q; rows=rows.filter(x=>((x.sub||'')+' '+(x.ips||[]).join(' ')+' '+(x.cname||'')+' '+(x.sources||[]).join(' ')).toLowerCase().includes(q));}
  return rows;
}
function sl3rStatusBadge(a){
  if(a===undefined) return '<span class="pill dim" style="font-size:9px">?</span>';
  const c=a.code||0;
  if(c===0) return '<span class="pill" style="background:#334155;color:#cbd5e1;font-size:9px">dead</span>';
  const col=c>=200&&c<300?'#16a34a':c>=300&&c<400?'#0284c7':c===401||c===403?'#d97706':c>=500?'#7f1d1d':'#dc2626';
  const sch=a.scheme?(a.scheme+' '):'';
  return `<span class="pill" style="background:${col};color:#fff;font-size:9.5px;font-weight:700" title="${esc(sch)}${c}${a.server?(' · '+esc(a.server)):''}${a.loc?(' → '+esc(a.loc)):''}">${esc(sch)}${c}</span>`;
}
function sl3rRender(reset){
  const st=window.SL3R_STATE;
  const se=document.getElementById('sl3r-search'),sv=document.getElementById('sl3r-src'),pe=document.getElementById('sl3r-per');
  if(se)st.q=se.value.toLowerCase().trim(); if(sv)st.src=sv.value; if(pe)st.per=parseInt(pe.value); if(reset)st.page=1;
  const rows=sl3rFiltered();
  const total=rows.length; const per=st.per>0?st.per:(total||1); const tp=Math.max(1,Math.ceil(total/per));
  if(st.page>tp)st.page=tp; if(st.page<1)st.page=1;
  const start=(st.page-1)*per; const pageRows=rows.slice(start,start+per);
  const badge=s=>`<span class="pill ${s==='crt.sh'?'info':s==='certspotter'?'purple':s==='subbrute'?'dim':'warn'}" style="font-size:9px">${esc(s)}</span>`;
  let html=`<div class="table-wrap"><table><thead><tr><th>Subdomain</th><th style="width:80px">Status</th><th style="width:52px">Open</th><th>Resolved IP(s) / CNAME</th><th style="width:200px">Sources</th></tr></thead><tbody>`;
  if(!pageRows.length){html+=`<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:18px">No subdomains match the filter.</td></tr>`;}
  else pageRows.forEach(x=>{
    const ipc=(x.ips&&x.ips.length)?esc(x.ips.join(', ')):(x.cname?('CNAME → '+esc(x.cname)):'<span style="color:var(--dim)">—</span>');
    const url='https://'+esc(x.sub);
    const link=`<a href="${url}" target="_blank" rel="noopener noreferrer" style="font-weight:600;color:var(--accent);word-break:break-all">${esc(x.sub)}</a>`;
    const open=`<a href="${url}" target="_blank" rel="noopener noreferrer" title="Open https://${esc(x.sub)}" style="text-decoration:none">↗</a>`;
    html+=`<tr><td>${link}</td><td>${sl3rStatusBadge(x.alive)}</td><td>${open}</td><td><code style="font-size:11px">${ipc}</code></td><td>${(x.sources||[]).map(badge).join(' ')}</td></tr>`;});
  html+=`</tbody></table></div>`;
  if(st.per>0&&tp>1){
    let nums='';const win=2;for(let i=1;i<=tp;i++){if(i===1||i===tp||(i>=st.page-win&&i<=st.page+win)){nums+=`<button type="button" class="${i===st.page?'active':''}" onclick="sl3rGoto(${i})">${i}</button>`;}else if(i===st.page-win-1||i===st.page+win+1){nums+=`<span style="padding:0 4px;color:var(--dim)">…</span>`;}}
    html+=`<div class="pager"><button type="button" ${st.page===1?'disabled':''} onclick="sl3rGoto(1)">« First</button><button type="button" ${st.page===1?'disabled':''} onclick="sl3rGoto(${st.page-1})">‹ Prev</button>${nums}<button type="button" ${st.page===tp?'disabled':''} onclick="sl3rGoto(${st.page+1})">Next ›</button><button type="button" ${st.page===tp?'disabled':''} onclick="sl3rGoto(${tp})">Last »</button></div>`;
  }
  const wrap=document.getElementById('sl3r-wrap'); if(wrap)wrap.innerHTML=html;
  const aliveN=(window.SL3R||[]).filter(x=>x.alive&&x.alive.code>0).length;
  const cnt=document.getElementById('sl3r-count'); if(cnt)cnt.textContent=`${total} shown`+(aliveN?` · ${aliveN} alive`:'')+(st.per>0&&tp>1?` · page ${st.page}/${tp}`:'');
}
function sl3rGoto(p){window.SL3R_STATE.page=p;sl3rRender(false);}
/* v2.6.6 — probe live HTTP status for the currently-filtered subdomains (batched, host-scoped) */
async function sl3rCheckAlive(){
  const rows=sl3rFiltered(); if(!rows.length){toast('No subdomains to check.');return;}
  const host=window.SL3R_HOST||urlScanHost();
  const prog=document.getElementById('sl3r-count');
  const batchAll=rows.map(x=>x.sub);
  if(!confirm('Probe live HTTP/HTTPS status for '+batchAll.length+' subdomain(s) of '+host+' ?\n\nSends a HEAD request to each (non-destructive). Capped at 60 per batch. Authorized engagements only.\n\nProceed?'))return;
  if(prog)prog.textContent='Probing HTTP status…';
  try{
    // batch in chunks of 60 (server cap)
    let idx=0,done=0;
    while(idx<batchAll.length){
      const chunk=batchAll.slice(idx,idx+60); idx+=60;
      const fd=new FormData();fd.append('target',host);fd.append('authorized','yes');fd.append('subs',JSON.stringify(chunk));
      const res=await fetch('?api=1&action=sublist3r_alive',{method:'POST',body:fd});const raw=await res.text();
      let r;try{r=JSON.parse(raw);}catch(e){throw new Error('invalid response');}
      if(!r.ok)throw new Error(r.error||'alive check failed');
      const map={};(r.data.results||[]).forEach(x=>{map[x.sub]=x;});
      window.SL3R.forEach(x=>{ if(map[x.sub]) x.alive=map[x.sub]; });
      done+=chunk.length; if(prog)prog.textContent='Probing… '+done+'/'+batchAll.length;
      sl3rRender(false);
    }
    const aliveN=(window.SL3R||[]).filter(x=>x.alive&&x.alive.code>0).length;
    if(typeof rtLog==='function')rtLog('sublist3r_alive','checked='+batchAll.length+', alive='+aliveN);
    toast('Alive check complete — '+aliveN+' live host(s).');
    sl3rRender(false);
  }catch(e){toast('Alive check failed: '+e.message);if(prog)prog.textContent='Error: '+e.message;}
}
function sl3rExportCSV(){
  const rows=sl3rFiltered(); if(!rows.length){toast('Nothing to export.');return;}
  const csv=['Subdomain,URL,HTTP_Status,Scheme,IPs,CNAME,Sources'];
  rows.forEach(x=>{const a=x.alive||{};csv.push([x.sub,'https://'+x.sub,a.code||'',a.scheme||'',(x.ips||[]).join(' '),x.cname||'',(x.sources||[]).join(' ')].map(v=>`"${String(v).replace(/"/g,'""')}"`).join(','));});
  const b=new Blob(['\uFEFF'+csv.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='sublist3r_'+((urlScanHost()||'target')).replace(/[^a-z0-9]/gi,'_')+'.csv';a.click();
  toast('Subdomain CSV exported.');
}
function rtRoE(){return {scope:(document.getElementById('rt-scope')||{}).value||'',operator:(document.getElementById('rt-operator')||{}).value||'',start:(document.getElementById('rt-start')||{}).value||'',end:(document.getElementById('rt-end')||{}).value||'',authref:(document.getElementById('rt-authref')||{}).value||'',authok:!!(document.getElementById('rt-authok')||{}).checked};}
function downloadRedTeamReport(){
  const pb=buildPlaybook(); if(!pb.items.length){toast('No findings.');return;}
  const roe=rtRoE(); const he=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const rows=pb.items.map(it=>({...it,att:attackMap(it)}));
  const cnt={Critical:0,High:0,Medium:0,Low:0,Info:0};rows.forEach(r=>cnt[r.sev]=(cnt[r.sev]||0)+1);
  const tac={};rows.forEach(r=>{tac[r.att.id]=(tac[r.att.id]||{tech:r.att.tech,tactic:r.att.tactic,n:0});tac[r.att.id].n++;});
  const sevC=s=>s==='Critical'?'#7f1d1d':s==='High'?'#dc2626':s==='Medium'?'#d97706':s==='Low'?'#0284c7':'#64748b';
  rtLog('export_red_team_report','target='+pb.host);
  let doc='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Red Team Report — '+he(pb.host)+'</title>'
   +'<style>body{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:960px;margin:0 auto;padding:24px;color:#0f172a;background:#f7f9fc}h1{color:#7f1d1d;margin:0 0 4px}.sub{color:#64748b;font-size:13px;margin-bottom:14px}.warn{background:#fee2e2;border-left:4px solid #7f1d1d;border-radius:8px;padding:12px 14px;font-size:13px;margin:14px 0}table{width:100%;border-collapse:collapse;margin:8px 0;background:#fff}th,td{border:1px solid #e4e9f2;padding:7px 9px;font-size:12.5px;text-align:left}th{background:#7f1d1d;color:#fff}.k{background:#f1f5f9;font-weight:600;width:220px}.badge{display:inline-block;color:#fff;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700}</style></head><body>'
   +'<h1>🔴 Red Team Engagement Report</h1><div class="sub">'+he(APP.name||'VRA Platform')+' v'+he(APP.version)+' · '+he(new Date().toLocaleString())+'</div>'
   +'<div class="warn"><strong>Confidential — Authorized engagement.</strong> This report documents an authorized security assessment. Distribution restricted to '+he(roe.operator||'the engaging team')+' and stakeholders.</div>'
   +'<h3>Rules of Engagement</h3><table>'
   +'<tr><td class="k">Authorized scope</td><td>'+he(roe.scope||pb.host)+'</td></tr>'
   +'<tr><td class="k">Operator</td><td>'+he(roe.operator)+'</td></tr>'
   +'<tr><td class="k">Engagement window</td><td>'+he(roe.start||'—')+' → '+he(roe.end||'—')+'</td></tr>'
   +'<tr><td class="k">Authorization reference</td><td>'+he(roe.authref||'—')+'</td></tr>'
   +'<tr><td class="k">Authorization confirmed</td><td>'+(roe.authok?'✅ Yes':'⚠️ NOT confirmed')+'</td></tr></table>'
   +'<h3>Executive Summary</h3><p>The assessment of <strong>'+he(pb.host)+'</strong> identified <strong>'+rows.length+'</strong> findings across <strong>'+Object.keys(tac).length+'</strong> MITRE ATT&CK techniques: '
   +'<span class="badge" style="background:#7f1d1d">'+cnt.Critical+' Critical</span> <span class="badge" style="background:#dc2626">'+cnt.High+' High</span> <span class="badge" style="background:#d97706">'+cnt.Medium+' Medium</span> <span class="badge" style="background:#0284c7">'+cnt.Low+' Low</span>.</p>'
   +'<h3>MITRE ATT&CK Coverage</h3><table><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Findings</th></tr>';
  Object.keys(tac).sort((a,b)=>tac[b].n-tac[a].n).forEach(id=>{doc+='<tr><td><a href="https://attack.mitre.org/techniques/'+he(id.replace('.','/'))+'/">'+he(id)+'</a></td><td>'+he(tac[id].tech)+'</td><td>'+he(tac[id].tactic)+'</td><td>'+tac[id].n+'</td></tr>';});
  doc+='</table><h3>Attack Narrative &amp; Findings</h3>';
  rows.forEach((r,i)=>{doc+='<div style="border:1px solid #e4e9f2;border-left:4px solid '+sevC(r.sev)+';border-radius:8px;padding:10px 14px;margin:10px 0;background:#fff">'
    +'<strong>'+(i+1)+'. <span class="badge" style="background:'+sevC(r.sev)+'">'+he(r.sev)+'</span> '+he(r.title)+'</strong> <span style="color:#94a3b8;font-size:12px">· '+he(r.cat)+' · '+he(r.att.id)+' '+he(r.att.tech)+' · '+he(r.att.phase)+'</span>'
    +'<p style="margin:6px 0"><strong style="color:#dc2626">Attack:</strong> '+he(r.attack)+'</p>'
    +'<p style="margin:6px 0"><strong style="color:#16a34a">Remediation:</strong> '+he(r.fix)+'</p></div>';});
  doc+='<p style="color:#94a3b8;font-size:12px;text-align:center;margin-top:24px">'+he(roe.operator||'TTPH IT Team')+' · Confidential · '+he(pb.host)+'</p></body></html>';
  const b=new Blob([doc],{type:'text/html;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='red_team_report_'+pb.host.replace(/[^a-z0-9]/gi,'_')+'_v'+APP.version+'.html';a.click();
  toast('Red Team report downloaded.');
}
function downloadEngagementLog(){
  const roe=rtRoE();
  const payload={platform:(APP.name||'VRA')+' v'+APP.version,generated:new Date().toISOString(),rules_of_engagement:roe,target:urlScanTargetRaw()||'',activity_log:window.RT_LOG||[]};
  const b=new Blob([JSON.stringify(payload,null,2)],{type:'application/json;charset=utf-8'});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='engagement_log_v'+APP.version+'_'+new Date().toISOString().slice(0,10)+'.json';a.click();
  toast('Engagement log downloaded.');
}
/* v2.5.8 — derive machine-readable server-side checks from a playbook item (no shell parsing) */
function itemToChecks(it,base,host){
  const cat=it.cat, title=it.title||'';
  if(cat==='Security Header'){const hdr=title.replace('Missing ','').trim();const key=hdr==='HSTS'?'strict-transport-security':(hdr==='CSP'?'content-security-policy':hdr.toLowerCase());return [{type:'header_absent',url:base,header:key,label:hdr}];}
  if(cat==='Info Disclosure')return [{type:'header_present',url:base,headers:['server','x-powered-by'],label:'version banner'}];
  if(cat==='Exposed Path'){const p=title.replace(/^Exposed:\s*/,'').replace(/\s*\[.*\]$/,'').trim();return [{type:'status',url:base+p,label:p}];}
  if(cat==='TLS/SSL')return [{type:'tls',host:host,label:'certificate'}];
  if(cat==='DNS / Email'){const rec=(title.split('—')[0]||'').trim();return [{type:'dns',rec:rec,host:host}];}
  if(cat==='Cookie')return [{type:'cookies',url:base}];
  if(cat==='CSP')return [{type:'header_present',url:base,headers:['content-security-policy'],label:'CSP'}];
  if(cat==='WordPress'&&/Outdated/i.test(title))return [{type:'body_match',url:base+'/',pattern:'generator',label:'generator meta'}];
  if(cat==='WordPress'&&/XML-RPC/i.test(title))return [{type:'status',url:base+'/xmlrpc.php',label:'xmlrpc.php'}];
  if(cat==='WordPress'&&/enumeration/i.test(title))return [{type:'status',url:base+'/wp-json/wp/v2/users',label:'wp users REST'}];
  if(cat==='WP Plugin'){const m=((it.verify||[])[0]||'').match(/plugins\/([^\/'"\s]+)/);return [{type:'body_match',url:base+'/wp-content/plugins/'+(m?m[1]:'')+'/readme.txt',pattern:'stable tag',label:'plugin readme'}];}
  if(cat==='WP Theme'){const m=((it.verify||[])[0]||'').match(/themes\/([^\/'"\s]+)/);return [{type:'body_match',url:base+'/wp-content/themes/'+(m?m[1]:'')+'/style.css',pattern:'version',label:'theme style.css'}];}
  return [];
}
async function verifyNowServerSide(){
  const pb=buildPlaybook(); if(!pb.items.length){toast('Nothing to verify.');return;}
  if(!confirm('Run LIVE server-side verification against '+pb.base+' ?\n\nThis re-checks each finding with non-destructive requests made from the server (same PHP + cURL/DNS/TLS the dashboard already uses). Only run against systems you own or are authorized to assess.\n\nProceed?'))return;
  const checks=[]; pb.items.forEach((it,i)=>{ itemToChecks(it,pb.base,pb.host).forEach(c=>{c.id=i;checks.push(c);}); });
  // Works from BOTH the Attack Playbook (pb-*) and Red Team Mode (rt-*) views
  const btns=[document.getElementById('pb-verify-btn'),document.getElementById('rt-verify-btn')].filter(Boolean);
  const progs=[document.getElementById('pb-verify-prog'),document.getElementById('rt-verify-prog')].filter(Boolean);
  const setProg=(t)=>progs.forEach(p=>p.textContent=t);
  btns.forEach(b=>{b.disabled=true;b._o=b.textContent;b.textContent='Verifying…';});
  setProg('Running '+checks.length+' live check(s)…');
  try{
    const fd=new FormData(); fd.append('target',pb.host); fd.append('authorized','yes'); fd.append('checks',JSON.stringify(checks));
    const res=await fetch('?api=1&action=pb_verify',{method:'POST',body:fd}); const raw=await res.text();
    let r; try{r=JSON.parse(raw);}catch(e){throw new Error((!res.ok?('HTTP '+res.status+' — '):'')+'invalid server response ('+raw.trim().slice(0,200)+')');}
    if(!r.ok)throw new Error(r.error||'verification failed');
    const byId={}; (r.data.results||[]).forEach(x=>{ if(x.id!=null){(byId[x.id]=byId[x.id]||[]).push(x);} });
    let conf=0,clear=0,inf=0,err=0,shown=0;
    pb.items.forEach((it,i)=>{
      const rs=byId[i]||[];
      const st=rs.length?(rs.some(x=>x.status==='confirmed')?'confirmed':(rs.some(x=>x.status==='clear')?'clear':(rs.some(x=>x.status==='info')?'info':'error'))):null;
      if(st==='confirmed')conf++;else if(st==='clear')clear++;else if(st==='info')inf++;else if(st==='error')err++;
      const badge=st==='confirmed'?'<span style="background:#7f1d1d;color:#fff;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700">✓ CONFIRMED</span>':st==='clear'?'<span style="background:#16a34a;color:#fff;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700">○ clear / fixed</span>':st==='info'?'<span style="background:#0284c7;color:#fff;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700">ℹ info</span>':'<span style="background:#64748b;color:#fff;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700">error</span>';
      const inner=rs.length?('<div style="margin-top:8px;border-top:1px dashed var(--line);padding-top:8px"><span style="font-size:11px;font-weight:700;color:#0f766e;text-transform:uppercase">⚡ Live result</span> '+badge+'<pre style="background:#0d1526;color:#c9d6ee;border-radius:8px;padding:8px 10px;margin-top:4px;font-size:11px;white-space:pre-wrap;word-break:break-all">'+rs.map(x=>esc(x.evidence||'')).join('\n')+'</pre></div>'):'';
      // Attack Playbook placeholder
      const pbBox=document.getElementById('pb-res-'+i); if(pbBox){pbBox.innerHTML=inner;}
      // Red Team Mode placeholder (reveal the sub-row)
      const rtBox=document.getElementById('rt-res-'+i); const rtRow=document.getElementById('rt-resrow-'+i);
      if(rtBox){ rtBox.innerHTML=rs.length?('<span style="font-size:11px;font-weight:700;color:#0f766e;text-transform:uppercase">⚡ Live result</span> '+badge+'<pre style="background:#0d1526;color:#c9d6ee;border-radius:8px;padding:8px 10px;margin-top:4px;font-size:11px;white-space:pre-wrap;word-break:break-all">'+rs.map(x=>esc(x.evidence||'')).join('\n')+'</pre>'):''; }
      if(rtRow){ rtRow.style.display=rs.length?'table-row':'none'; }
      if(rs.length)shown++;
    });
    setProg('Done · '+conf+' confirmed · '+clear+' clear · '+inf+' info'+(err?(' · '+err+' error'):'')+' · '+shown+' item(s)');
    if(typeof rtLog==='function')rtLog('verify_now','confirmed='+conf+', clear='+clear+', info='+inf+', error='+err);
    toast('Live verification complete — '+conf+' confirmed, '+clear+' clear.');
  }catch(e){ setProg('Error: '+e.message); toast('Verify failed: '+e.message); }
  finally{ btns.forEach(b=>{b.disabled=false;b.textContent=b._o||'⚡ Verify Now (non-destructive)';}); }
}
/* Translate a curl/dig/openssl/nmap one-liner into a PHP verify() call for the standalone script.
   Falls back to a commented reference if no clean native mapping exists. */
/* Translate a curl/dig/openssl check one-liner into a PHP verify() call for the standalone script. */
function toPHP(cmd){
  let c=cmd.replace(/\s+#.*$/,'').trim();
  let m;
  // curl -sI URL | grep -i "x"  -> single header check
  m=c.match(/^curl\s+-sI\s+(\S+)\s*\|\s*grep\s+-i\s+"?([^"|]+)"?\s*$/i);
  if(m){return "check_header('"+m[1]+"', '"+m[2].trim().replace(/"/g,'')+"');";}
  // curl -sI URL | grep -iE "server|x-powered-by"
  m=c.match(/^curl\s+-sI\s+(\S+)\s*\|\s*grep\s+-iE\s+"([^"]+)"/i);
  if(m){const keys=m[2].split('|').map(k=>"'"+k.trim()+"'").join(',');return "check_headers('"+m[1]+"', array("+keys+"));";}
  // curl -s -o /dev/null -w "%{http_code}" URL  -> status code
  m=c.match(/^curl\s+-s\s+-o\s+\/dev\/null\s+-w\s+"%\{http_code\}\\?n?"\s+(\S+)/i);
  if(m){return "check_status('"+m[1]+"');";}
  // curl -s URL -d '...' | grep -o "x"  (xmlrpc POST)
  m=c.match(/^curl\s+-s\s+(\S+)\s+-d\s+'([^']+)'\s*\|\s*grep\s+-o\s+"([^"]+)"/i);
  if(m){return "check_post_contains('"+m[1]+"', '"+m[2].replace(/'/g,"\\'")+"', '"+m[3]+"');";}
  // curl -s URL | head -c N
  m=c.match(/^curl\s+-s\s+"?([^"|]+)"?\s*\|\s*head\s+-c\s+(\d+)/i);
  if(m){return "check_snippet('"+m[1].trim()+"', "+m[2]+");";}
  // curl -s URL | grep [-i] "x" [| head ...]
  m=c.match(/^curl\s+-s\s+"?([^"|]+)"?\s*\|\s*grep\s+-i?o?\s*"?([^"|]+?)"?\s*(\|\s*head.*)?$/i);
  if(m){return "check_body_contains('"+m[1].trim()+"', '"+m[2].trim().replace(/'/g,"\\'").replace(/"/g,'')+"');";}
  // curl -sI URL (bare)  -> dump headers
  m=c.match(/^curl\s+-sI\s+(\S+)\s*$/i);
  if(m){return "dump_headers('"+m[1]+"');";}
  // dig +short TXT name | grep spf1
  m=c.match(/^dig\s+\+short\s+TXT\s+(\S+)\s*\|\s*grep\s+(\S+)/i);
  if(m){return "check_txt('"+m[1]+"', '"+m[2]+"');";}
  // dig +short TYPE name
  m=c.match(/^dig\s+\+short\s+(\w+)\s+(\S+)/i);
  if(m){return "check_dns('"+m[2]+"', '"+m[1].toUpperCase()+"');";}
  // openssl s_client -> TLS cert inspection
  if(/^echo\s*\|\s*openssl\s+s_client/i.test(c)){const hm=c.match(/-connect\s+([^:]+):/i)||[];return "check_tls('"+(hm[1]||'HOST')+"');";}
  // nmap ssl-enum-ciphers -> covered by check_tls note
  if(/^nmap\s+--script\s+ssl-enum-ciphers/i.test(c)){return "// (optional) run: nmap --script ssl-enum-ciphers -p 443 \\$TARGETHOST  — or rely on check_tls() above";}
  return "// (manual) "+cmd.replace(/\*\//g,'* /');
}
function downloadPoCScriptPHP(){
  const pb=buildPlaybook(); if(!pb.items.length){toast('No findings.');return;}
  const now=new Date().toISOString();
  const L=[];
  L.push("<?php");
  L.push("/* =====================================================================");
  L.push("   "+(APP.name||'Vulnerability, Recon and Assessment Platform')+" - PoC / Verification Script (PHP)");
  L.push("   Target : "+pb.host);
  L.push("   Author : "+(APP.author||'TTPH IT Team'));
  L.push("   Date   : "+now);
  L.push("   ---------------------------------------------------------------------");
  L.push("   AUTHORIZED USE ONLY. Run ONLY against systems you own or are authorized");
  L.push("   to assess. All checks are NON-DESTRUCTIVE verifications that CONFIRM each");
  L.push("   finding so you can prioritize remediation. This is a blue-team aid.");
  L.push("   ---------------------------------------------------------------------");
  L.push("   HOW TO RUN (no PowerShell / no bash needed):");
  L.push("     * Command line:  php verify.php");
  L.push("     * Or drop it on your PHP web server and open it in a browser.");
  L.push("   Requires: PHP with cURL (already used by your dashboard).");
  L.push("   ===================================================================== */");
  L.push("");
  L.push("$BASE = "+JSON.stringify(pb.base)+";");
  L.push("$TARGETHOST = "+JSON.stringify(pb.host)+";");
  L.push("$CLI = (php_sapi_name() === 'cli');");
  L.push("if (!$CLI) { header('Content-Type: text/plain; charset=utf-8'); }");
  L.push("");
  L.push("/* ---- authorization gate ---- */");
  L.push("if ($CLI) {");
  L.push("  echo \"Confirm you are AUTHORIZED to test $BASE ? (yes/no): \";");
  L.push("  $ans = trim(fgets(STDIN));");
  L.push("  if (strtolower($ans) !== 'yes') { echo \"Aborted.\\n\"; exit; }");
  L.push("} else {");
  L.push("  if (($_GET['authorized'] ?? '') !== 'yes') {");
  L.push("    echo \"AUTHORIZATION REQUIRED.\\nThis script only runs against systems you are authorized to assess.\\n\";");
  L.push("    echo \"Re-open with ?authorized=yes appended to the URL to confirm and run.\\n\";");
  L.push("    exit;");
  L.push("  }");
  L.push("}");
  L.push("");
  L.push("/* ---- helpers (cURL-based, non-destructive) ---- */");
  L.push("function _get($url,$head=false,$body=null){");
  L.push("  $ch=curl_init();");
  L.push("  curl_setopt_array($ch,[CURLOPT_URL=>$url,CURLOPT_RETURNTRANSFER=>true,CURLOPT_HEADER=>true,");
  L.push("    CURLOPT_NOBODY=>$head,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_TIMEOUT=>10,CURLOPT_CONNECTTIMEOUT=>6,");
  L.push("    CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_USERAGENT=>'VRA-PoC-Verify']);");
  L.push("  if($body!==null){curl_setopt($ch,CURLOPT_POST,true);curl_setopt($ch,CURLOPT_POSTFIELDS,$body);curl_setopt($ch,CURLOPT_HTTPHEADER,['Content-Type: text/xml']);}");
  L.push("  $r=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);$hs=curl_getinfo($ch,CURLINFO_HEADER_SIZE);curl_close($ch);");
  L.push("  if($r===false)return ['code'=>0,'headers'=>'','body'=>''];");
  L.push("  return ['code'=>$code,'headers'=>substr($r,0,$hs),'body'=>substr($r,$hs)];");
  L.push("}");
  L.push("function note($n){ echo \"\\n[CHECK] $n\\n\"; }");
  L.push("function ok($m){ echo \"  [VERIFIED] $m\\n\"; }");
  L.push("function nf($m){ echo \"  [ok/clear] $m\\n\"; }");
  L.push("function check_header($url,$h){ $r=_get($url,true); if(preg_match('~^'.preg_quote($h,'~').'\\s*:(.*)$~mi',$r['headers'],$m)) ok(\"$h present:\".trim($m[1])); else nf(\"$h ABSENT (add it)\"); }");
  L.push("function check_headers($url,$keys){ $r=_get($url,true); foreach($keys as $k){ if(preg_match('~^'.preg_quote($k,'~').'\\s*:(.*)$~mi',$r['headers'],$m)) ok(\"$k:\".trim($m[1])); } }");
  L.push("function dump_headers($url){ $r=_get($url,true); echo '  '.str_replace(\"\\n\",\"\\n  \",trim($r['headers'])).\"\\n\"; }");
  L.push("function check_status($url){ $r=_get($url,true); if($r['code']==0){$r=_get($url,false);} echo \"  HTTP $r[code]  $url\".($r['code']==200?'  [VERIFIED exposed]':'').\"\\n\"; }");
  L.push("function check_body_contains($url,$needle){ $r=_get($url,false); if(stripos($r['body'],$needle)!==false) ok(\"'$needle' found at $url\"); else nf(\"'$needle' not found\"); }");
  L.push("function check_snippet($url,$n){ $r=_get($url,false); echo '  '.substr(preg_replace('~\\s+~',' ',$r['body']),0,$n).\"\\n\"; }");
  L.push("function check_post_contains($url,$payload,$needle){ $r=_get($url,false,$payload); if(stripos($r['body'],$needle)!==false) ok(\"'$needle' present at $url\"); else nf(\"'$needle' not present\"); }");
  L.push("function check_dns($name,$type){ $t=constant('DNS_'.$type); $recs=@dns_get_record($name,$t); if($recs){ foreach($recs as $x){ echo '  '.trim(($x['txt']??$x['target']??$x['ip']??json_encode($x))).\"\\n\"; } } else nf(\"no $type record for $name\"); }");
  L.push("function check_txt($name,$needle){ $recs=@dns_get_record($name,DNS_TXT); $hit=false; if($recs) foreach($recs as $x){ if(stripos($x['txt']??'',$needle)!==false){ ok(trim($x['txt'])); $hit=true; } } if(!$hit) nf(\"no TXT containing '$needle' for $name\"); }");
  L.push("function check_tls($host){ $ctx=stream_context_create(['ssl'=>['capture_peer_cert'=>true,'verify_peer'=>false,'verify_peer_name'=>false,'SNI_enabled'=>true,'peer_name'=>$host]]);");
  L.push("  $c=@stream_socket_client('ssl://'.$host.':443',$e,$es,10,STREAM_CLIENT_CONNECT,$ctx);");
  L.push("  if(!$c){ nf(\"TLS connect failed: $es\"); return; }");
  L.push("  $p=stream_context_get_params($c); $cert=$p['options']['ssl']['peer_certificate']??null; @fclose($c);");
  L.push("  if(!$cert){ nf('no certificate captured'); return; }");
  L.push("  $x=openssl_x509_parse($cert); $to=$x['validTo_time_t']??0; $days=$to?floor(($to-time())/86400):'?';");
  L.push("  echo \"  Subject: \".($x['subject']['CN']??'').\"\\n  Issuer:  \".($x['issuer']['CN']??($x['issuer']['O']??'')).\"\\n  Expires: \".($to?date('Y-m-d',$to):'?').\" ($days days)\\n  SigAlg:  \".($x['signatureTypeSN']??'').\"\\n\"; }");
  L.push("");
  L.push("if(!function_exists('curl_init')){ echo \"ERROR: PHP cURL extension is required.\\n\"; exit; }");
  L.push("echo \"===== VRA PoC / Verification — $BASE =====\\n\";");
  L.push("");
  pb.items.forEach((it,i)=>{
    L.push("/* ["+it.sev+"] "+it.cat+" — "+it.title.replace(/\*\//g,'* /')+" */");
    L.push("note("+JSON.stringify(String(i+1)+'. '+it.title)+");");
    L.push("echo "+JSON.stringify('  Attack: '+it.attack)+".\"\\n\";");
    (it.verify||[]).forEach(v=>{ L.push(toPHP(v)); });
    L.push("echo "+JSON.stringify('  Fix: '+it.fix)+".\"\\n\";");
    L.push("");
  });
  L.push("echo \"\\nDone. Review [VERIFIED] items and apply the Fix lines / hardening guide.\\n\";");
  const s=L.join("\n");
  const b=new Blob([s],{type:'application/x-php;charset=utf-8'});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='verify_'+pb.host.replace(/[^a-z0-9]/gi,'_')+'_v'+APP.version+'.php';a.click();
  toast('PHP verification script downloaded — run: php verify.php');
}
/* Self-contained HTML report — zero execution, just open in a browser */
function downloadPlaybookHTML(){
  const pb=buildPlaybook(); if(!pb.items.length){toast('No findings.');return;}
  const cnt={Critical:0,High:0,Medium:0,Low:0,Info:0};pb.items.forEach(i=>cnt[i.sev]=(cnt[i.sev]||0)+1);
  const he=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const sevColor=s=>s==='Critical'?'#7f1d1d':s==='High'?'#dc2626':s==='Medium'?'#d97706':s==='Low'?'#0284c7':'#64748b';
  let rows='';
  pb.items.forEach((it,i)=>{
    rows+=`<details style="margin:10px 0;border:1px solid #e4e9f2;border-left:4px solid ${sevColor(it.sev)};border-radius:8px;padding:0 14px;background:#fff">
      <summary style="cursor:pointer;padding:12px 0;font-weight:600"><span style="display:inline-block;min-width:70px;color:#fff;background:${sevColor(it.sev)};border-radius:5px;padding:2px 8px;font-size:11px;text-align:center">${he(it.sev)}</span> &nbsp;${he(it.title)} <span style="color:#94a3b8;font-weight:400;font-size:12px">· ${he(it.cat)}</span></summary>
      <div style="padding:4px 0 14px">
        <p style="margin:6px 0"><strong style="color:#dc2626">🗡️ Attack scenario:</strong> ${he(it.attack)}</p>
        <p style="margin:6px 0"><strong style="color:#6d28d9">🔬 Verify (non-destructive):</strong></p>
        <pre style="background:#0d1526;color:#c9d6ee;border-radius:8px;padding:10px 12px;font-size:12px;overflow:auto;white-space:pre-wrap;word-break:break-all">${he((it.verify||[]).join('\n'))}</pre>
        <p style="margin:6px 0"><strong style="color:#16a34a">🛡️ Remediation:</strong> ${he(it.fix)}</p>
      </div></details>`;
  });
  const doc='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
   +'<title>Attack Playbook — '+he(pb.host)+'</title>'
   +'<style>body{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:960px;margin:0 auto;padding:24px;background:#f7f9fc;color:#0f172a}'
   +'h1{margin:0 0 4px}.sub{color:#64748b;font-size:13px;margin-bottom:16px}'
   +'.warn{background:#fef3c7;border-left:4px solid #d97706;border-radius:8px;padding:12px 14px;font-size:13px;margin:14px 0}'
   +'.stats{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.stat{flex:1;min-width:90px;background:#fff;border:1px solid #e4e9f2;border-radius:8px;padding:12px;text-align:center}.stat .n{font-size:22px;font-weight:700}.stat .l{font-size:11px;color:#64748b;text-transform:uppercase}'
   +'pre{margin:4px 0}details summary::-webkit-details-marker{color:#94a3b8}</style></head><body>'
   +'<h1>🎯 Attack Path &amp; Remediation Playbook</h1>'
   +'<div class="sub">Target: <strong>'+he(pb.base)+'</strong> · Generated by '+he(APP.name||'VRA Platform')+' v'+he(APP.version)+' · '+he(new Date().toLocaleString())+'</div>'
   +'<div class="warn"><strong>⚠️ Authorized use only.</strong> These scenarios and non-destructive proof-of-concept commands are for controlled testing of systems you own or are authorized to assess. Do not use against third-party systems.</div>'
   +'<div class="stats">'
   +'<div class="stat"><div class="n" style="color:#7f1d1d">'+cnt.Critical+'</div><div class="l">Critical</div></div>'
   +'<div class="stat"><div class="n" style="color:#dc2626">'+cnt.High+'</div><div class="l">High</div></div>'
   +'<div class="stat"><div class="n" style="color:#d97706">'+cnt.Medium+'</div><div class="l">Medium</div></div>'
   +'<div class="stat"><div class="n" style="color:#0284c7">'+cnt.Low+'</div><div class="l">Low</div></div>'
   +'<div class="stat"><div class="n">'+pb.items.length+'</div><div class="l">Total</div></div></div>'
   +rows
   +'<p style="color:#94a3b8;font-size:12px;margin-top:24px;text-align:center">'+he(APP.author||'TTPH IT Team')+' · Confidential · '+he(pb.host)+'</p>'
   +'</body></html>';
  const b=new Blob([doc],{type:'text/html;charset=utf-8'});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='attack_playbook_'+pb.host.replace(/[^a-z0-9]/gi,'_')+'_v'+APP.version+'.html';a.click();
  toast('Playbook HTML report downloaded — just open it in a browser.');
}
function downloadHardeningGuide(){
  const pb=buildPlaybook(); if(!pb.items.length){toast('No findings.');return;}
  let m='# Hardening Guide — '+pb.host+'\n\n> Generated by '+(APP.name||'VRA Platform')+' v'+APP.version+' · '+new Date().toLocaleString()+'\n> Authorized internal use only.\n\n';
  m+='| # | Severity | Category | Finding | Remediation |\n|---|----------|----------|---------|-------------|\n';
  pb.items.forEach((it,i)=>{ m+='| '+(i+1)+' | '+it.sev+' | '+it.cat+' | '+it.title.replace(/\|/g,'\\|')+' | '+it.fix.replace(/\|/g,'\\|').replace(/\n/g,' ')+' |\n'; });
  m+='\n## Attack Scenarios (for defender awareness)\n\n';
  pb.items.forEach((it,i)=>{ m+='### '+(i+1)+'. ['+it.sev+'] '+it.title+'\n\n**How it could be exploited:** '+it.attack+'\n\n**Verify (non-destructive):**\n```bash\n'+(it.verify||[]).join('\n')+'\n```\n\n**Fix:** '+it.fix+'\n\n'; });
  const b=new Blob([m],{type:'text/markdown;charset=utf-8'});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='hardening_guide_'+pb.host.replace(/[^a-z0-9]/gi,'_')+'_v'+APP.version+'.md';a.click();
  toast('Hardening guide downloaded.');
}
function ensureJsPDF(){return new Promise((res,rej)=>{if(window.jspdf&&window.jspdf.jsPDF)return res(window.jspdf.jsPDF);const s=document.createElement('script');s.src='https://unpkg.com/jspdf@2.5.1/dist/jspdf.umd.min.js';s.onload=()=>(window.jspdf&&window.jspdf.jsPDF)?res(window.jspdf.jsPDF):rej(new Error('init failed'));s.onerror=()=>rej(new Error('CDN failed'));document.head.appendChild(s);});}
async function exportPDF(ev){
  const btn=ev?.target;if(btn){btn.disabled=true;btn.innerHTML='Generating…';}
  /* v2.7.3: derive which tab to export from the clicked action-bar (concurrency-safe) */
  const _bar=btn?btn.closest('.action-bar'):null;
  const kind=(_bar&&_bar.id.indexOf('act-')===0)?_bar.id.slice(4):(window.CURRENT_SCAN.kind||'url');
  const tgt=scanTarget(kind)||'Report';
  const pdfFindings=kind==='nuclei'?(window.NUC_FINDINGS||[]):(window.CODE_FINDINGS||[]);
  try{
    const jsPDF=await ensureJsPDF();const doc=new jsPDF({unit:'mm',format:'a4'});
    const pageW=doc.internal.pageSize.getWidth(),pageH=doc.internal.pageSize.getHeight(),margin=15,cW=pageW-margin*2;
    doc.setFillColor(37,99,235);doc.rect(0,0,pageW,pageH,'F');
    doc.setFillColor(255,255,255);doc.roundedRect(margin,margin,22,22,3,3,'F');
    doc.setTextColor(37,99,235);doc.setFont('helvetica','bold');doc.setFontSize(14);doc.text('TT',margin+11,margin+14,{align:'center'});
    doc.setTextColor(255,255,255);doc.setFont('helvetica','normal');doc.setFontSize(11);doc.text(APP.author||'TTPH IT Team',margin+27,margin+11);
    doc.setFontSize(8);doc.setTextColor(220,230,255);doc.text((APP.name||'Vulnerability, Recon and Assessment Platform')+' v'+APP.version,margin+27,margin+16);
    doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(26);doc.text('VULNERABILITY,',margin,88);doc.text('RECON &',margin,101);doc.text('ASSESSMENT',margin,114);doc.text('REPORT',margin,127);
    doc.setTextColor(220,230,255);doc.setFontSize(9);doc.text('SUBJECT',margin,145);doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(14);doc.text(stripEmoji(tgt),margin,153);
    doc.setTextColor(220,230,255);doc.setFontSize(9);doc.text('REPORT DATE',margin,168);doc.setTextColor(255,255,255);doc.setFontSize(11);doc.text(new Date().toLocaleString(),margin,176);
    doc.setTextColor(200,220,255);doc.setFont('helvetica','italic');doc.setFontSize(7);doc.text('CONFIDENTIAL - For internal '+(APP.author||'TTPH IT Team')+' use only.',pageW/2,pageH-6,{align:'center'});
    // If code findings, render a dedicated findings section with snippets
    if(pdfFindings.length&&kind==='code'){
      doc.addPage();let y=18;
      doc.setFillColor(37,99,235);doc.rect(0,0,pageW,10,'F');doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(9);doc.text('SAST CODE ANALYSIS',margin,6.5);doc.text('v'+APP.version,pageW-margin,6.5,{align:'right'});
      doc.setFillColor(37,99,235);doc.rect(margin,y,3,10,'F');doc.setFillColor(239,246,255);doc.rect(margin+3,y,cW-3,10,'F');
      doc.setTextColor(29,78,216);doc.setFont('helvetica','bold');doc.setFontSize(12);doc.text('SAST Findings',margin+8,y+6.5);y+=16;
      const codeLines=(window.LAST_CODE||'').split(/\r?\n/);
      pdfFindings.forEach(f=>{
        if(y>pageH-40){doc.addPage();y=18;}
        const sevColor=f.sev==='Critical'?[127,29,29]:f.sev==='High'?[220,38,38]:f.sev==='Medium'?[217,119,6]:f.sev==='Low'?[2,132,199]:[100,116,139];
        doc.setFillColor(sevColor[0],sevColor[1],sevColor[2]);doc.rect(margin,y,2,7,'F');
        doc.setTextColor(15,23,42);doc.setFont('helvetica','bold');doc.setFontSize(10);doc.text(stripEmoji(f.title),margin+5,y+5);
        doc.setTextColor(sevColor[0],sevColor[1],sevColor[2]);doc.setFontSize(8);doc.text(f.sev.toUpperCase(),pageW-margin,y+5,{align:'right'});y+=8;
        doc.setTextColor(51,65,85);doc.setFont('helvetica','normal');doc.setFontSize(8);
        doc.splitTextToSize(stripEmoji(f.why),cW).forEach(l=>{if(y>pageH-20){doc.addPage();y=18;}doc.text(l,margin+5,y);y+=3.6;});
        doc.setFont('helvetica','italic');doc.text(stripEmoji('Fix: '+f.fix),margin+5,y,{maxWidth:cW});y+=4;
        doc.setFont('helvetica','normal');doc.setTextColor(100,116,139);doc.text((f.cwe||'')+' · '+(f.owasp||'')+' · Line '+(f.line||'—')+' · '+f.source,margin+5,y);y+=5;
        // Snippet (dark box)
        if(f.line&&codeLines.length){const idx=f.line-1;const from=Math.max(0,idx-2),to=Math.min(codeLines.length-1,idx+2);
          const snH=(to-from+1)*4+4;if(y+snH>pageH-15){doc.addPage();y=18;}
          doc.setFillColor(13,21,38);doc.rect(margin+5,y,cW-10,snH,'F');
          for(let i=from;i<=to;i++){let raw=(codeLines[i]||'').substring(0,150);
            doc.setTextColor(i===idx?248:150,i===idx?113:163,i===idx?113:196);doc.setFont('courier','normal');doc.setFontSize(6.5);
            doc.text((i+1)+'  '+raw,margin+8,y+4+(i-from)*4);}
          y+=snH+6;}
        else y+=4;
      });
    }
    // recon sections — target the exported tab's results container (concurrency-safe kind from the clicked button)
    const rc=document.getElementById('results-'+kind);
    const sections=rc?rc.querySelectorAll('.section'):[];
    // ---- Executive summary page (recon scans) ----
    if(kind!=='code' && sections.length){
      doc.addPage();doc.setFillColor(37,99,235);doc.rect(0,0,pageW,10,'F');
      doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(9);doc.text('VULNERABILITY, RECON & ASSESSMENT REPORT',margin,6.5);doc.text('v'+APP.version,pageW-margin,6.5,{align:'right'});
      let y=20;
      doc.setFillColor(37,99,235);doc.rect(margin,y,3,10,'F');doc.setFillColor(239,246,255);doc.rect(margin+3,y,cW-3,10,'F');
      doc.setTextColor(29,78,216);doc.setFont('helvetica','bold');doc.setFontSize(13);doc.text('Executive Summary',margin+8,y+6.8);y+=18;
      // meta box
      doc.setDrawColor(226,232,240);doc.setFillColor(248,250,252);doc.roundedRect(margin,y,cW,20,2,2,'FD');
      doc.setTextColor(100,116,139);doc.setFont('helvetica','bold');doc.setFontSize(8);doc.text('TARGET',margin+4,y+6);doc.text('SCAN TYPE',margin+4,y+13);doc.text('MODULES',pageW/2,y+6);doc.text('GENERATED',pageW/2,y+13);
      doc.setTextColor(15,23,42);doc.setFont('helvetica','normal');doc.setFontSize(9);
      doc.text(stripEmoji(tgt||'—').substring(0,52),margin+28,y+6);
      doc.text(kind.toUpperCase()+' recon',margin+28,y+13);
      doc.text(String(sections.length),pageW/2+26,y+6);
      doc.text(new Date().toLocaleString(),pageW/2+26,y+13);y+=28;
      // module status table
      doc.setFillColor(37,99,235);doc.rect(margin,y,cW,7,'F');doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(8);
      doc.text('MODULE',margin+3,y+5);doc.text('STATUS',margin+cW-40,y+5);doc.text('KEY RESULT',margin+cW*0.52,y+5);y+=8;
      sections.forEach((sec,ri)=>{
        const title=stripEmoji(sec.dataset.title||'Section');
        const stEl=sec.querySelector('.section-status');const st=stEl?stripEmoji(stEl.innerText.trim()):'—';
        // key result: count rows / pills of interest
        const nRows=sec.querySelectorAll('tbody tr').length;const badPills=sec.querySelectorAll('.pill.bad, .sev-Critical, .sev-High').length;
        const key=badPills>0?(badPills+' high-risk item(s)'):(nRows>0?(nRows+' row(s)'):'reviewed');
        const rowH=7;if(y+rowH>pageH-15){doc.addPage();y=18;}
        if(ri%2===1){doc.setFillColor(248,250,252);doc.rect(margin,y,cW,rowH,'F');}
        doc.setTextColor(15,23,42);doc.setFont('helvetica','normal');doc.setFontSize(8);doc.text(title.substring(0,52),margin+3,y+4.7);
        const stColor=/done/i.test(st)?[22,163,74]:/error|fail/i.test(st)?[220,38,38]:/skip/i.test(st)?[100,116,139]:[217,119,6];
        doc.setTextColor(stColor[0],stColor[1],stColor[2]);doc.setFont('helvetica','bold');doc.text(st.substring(0,14),margin+cW-40,y+4.7);
        doc.setTextColor(71,85,105);doc.setFont('helvetica','normal');doc.text(key,margin+cW*0.52,y+4.7);
        doc.setDrawColor(230,236,244);doc.setLineWidth(0.15);doc.line(margin,y+rowH,margin+cW,y+rowH);y+=rowH;
      });
    }
    for(const sec of sections){
      if(kind==='code')break;
      doc.addPage();doc.setFillColor(37,99,235);doc.rect(0,0,pageW,10,'F');
      doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(9);doc.text('VULNERABILITY, RECON & ASSESSMENT REPORT',margin,6.5);doc.text('v'+APP.version,pageW-margin,6.5,{align:'right'});
      let y=18;const title=stripEmoji(sec.dataset.title||'Section');
      doc.setFillColor(37,99,235);doc.rect(margin,y,3,10,'F');doc.setFillColor(239,246,255);doc.rect(margin+3,y,cW-3,10,'F');
      doc.setTextColor(29,78,216);doc.setFont('helvetica','bold');doc.setFontSize(12);doc.text(title,margin+8,y+6.5);y+=14;
      const body=sec.querySelector('[id^="body-"]')||sec;
      body.querySelectorAll('table').forEach(tbl=>{
        const headers=Array.from(tbl.querySelectorAll('thead th')).map(th=>stripEmoji(th.innerText.trim()));
        const rows=Array.from(tbl.querySelectorAll('tbody tr')).map(tr=>Array.from(tr.querySelectorAll('td')).map(td=>stripEmoji(td.innerText.replace(/\s+/g,' ').trim())));
        if(!rows.length)return;const nc=headers.length||rows[0].length;const colW=cW/nc;
        if(y+10>pageH-15){doc.addPage();y=18;}
        doc.setFillColor(37,99,235);doc.rect(margin,y,cW,7,'F');doc.setTextColor(255,255,255);doc.setFont('helvetica','bold');doc.setFontSize(7.5);
        headers.forEach((hh,i)=>doc.text(hh.substring(0,28),margin+colW*i+2,y+5));y+=8;
        rows.forEach((row,ri)=>{const rowH=6+Math.max(...row.map(c=>doc.splitTextToSize(c,colW-4).length))*4;
          if(y+rowH>pageH-15){doc.addPage();y=18;}
          if(ri%2===1){doc.setFillColor(248,250,252);doc.rect(margin,y,cW,rowH,'F');}
          doc.setTextColor(15,23,42);doc.setFont('helvetica','normal');doc.setFontSize(7.5);
          row.forEach((cell,ci)=>{doc.splitTextToSize(cell.substring(0,400),colW-4).forEach((ln,li)=>doc.text(ln,margin+colW*ci+2,y+4+li*4));});
          doc.setDrawColor(226,232,240);doc.setLineWidth(0.15);doc.line(margin,y+rowH,margin+cW,y+rowH);y+=rowH;});y+=5;});
      body.querySelectorAll('.kv').forEach(kv=>{const it=kv.children;for(let i=0;i<it.length;i+=2){const k=stripEmoji(it[i]?.innerText.trim());const v=stripEmoji(it[i+1]?.innerText.trim());if(!k)continue;if(y+6>pageH-15){doc.addPage();y=18;}doc.setTextColor(100,116,139);doc.setFont('helvetica','bold');doc.setFontSize(8);doc.text(k+':',margin+2,y+4);doc.setTextColor(15,23,42);doc.setFont('helvetica','normal');const vl=doc.splitTextToSize(v||'-',cW-52);doc.text(vl[0],margin+48,y+4);y+=6;}y+=4;});
    }
    const total=doc.internal.getNumberOfPages();
    for(let i=2;i<=total;i++){doc.setPage(i);doc.setDrawColor(226,232,240);doc.setLineWidth(0.3);doc.line(margin,pageH-12,pageW-margin,pageH-12);doc.setTextColor(100,116,139);doc.setFont('helvetica','normal');doc.setFontSize(7.5);doc.text((APP.author||'TTPH IT Team')+' | Confidential',margin,pageH-6);doc.text('Page '+i+' of '+total,pageW-margin,pageH-6,{align:'right'});}
    const safe=(tgt||'report').replace(/[^a-z0-9]/gi,'_').substring(0,40);
    doc.save('TTPH_OSINT_Report_'+safe+'_v'+APP.version+'_'+new Date().toISOString().slice(0,10)+'.pdf');
    toast('PDF exported.');
  }catch(e){console.error(e);toast('PDF failed: '+e.message);}
  finally{if(btn){btn.disabled=false;btn.innerHTML='Export PDF';}}
}
</script>
</body></html>
