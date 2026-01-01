# Security context

**IoT Environment:**  
My proposed IoT Toolkit was developed to support organisations infrastructure and the deployment of Internet of Things devices (popular examples include smart home appliances, industrial sensors, or medical devices). Almost 100% of them communicate over networks and may control critical operations. As noted by recent research, IoT applications are now integral to a significant percentage of critical sectors like healthcare and transportation, meaning breaches can have severe consequences and catastrophic impacts. In this context, security lapses can compromise personal data, service availability, or even physical safety.

**Threat Landscape:**  
IoT devices notably lack rigorous security controls. Industry sources report a surge in cybercrime targeting IoT, owing to easily exploited flaws like weak authentication, unencrypted services, and poor update mechanisms permitting breaches to be easily systemically configured. For example, OWASP’s IoT Top 10 identifies weak credentials (I1) and insecure network services (I2) as top risks. The vast majority of attackers tend to exploit these to gain unauthorised access, launch attacks, or pivot into internal networks. The business setting might be a manufacturing plant using connected sensors or a smart office with networked cameras, implying that in all cases, exposing a vulnerability could lead to data theft or downtime.

**Regulatory and Standards Considerations:**  
Standards like NIST’s IoT Cybersecurity guidance emphasise that securing IoT requires specialised tools and processes. Similarly, compliance frameworks (e.g., the EU Cybersecurity Act) mandate that connected devices undergo security evaluation. Thus, the organisational need is a systematic way to assess device security posture before deployment. During my endeavour of developing the toolkit, I will opt to address these challenges by providing automated checks aligned with such standards (e.g., verifying firmware integrity, scanning for known vulnerabilities) to help meet compliance and reduce risk.

---

# Project Milestones and Deliverables Table

| Phase | Timeframe | Objectives | Key Activities | Deliverables | Validation & Evidence |
|------|-----------|------------|----------------|--------------|----------------------|
| Project Initiation & Scope Definition | 09 Oct – 15 Oct 2025 | Define problem, constraints, and success criteria | Identified common IoT security failures (weak credentials, insecure services, unsigned firmware). Defined ethical and safety constraints (local-only testing, non-destructive scans). Finalised core feature set. | Project scope definition, feature list, ethical constraints | Initial project notes; documented assumptions referenced later in reflection |
| Architecture Design & Tool Selection | 16 Oct – 22 Oct 2025 | Design modular architecture and select appropriate techniques | Designed scanner/auditor/pentest module separation. Chose TCP connect scanning, banner grabbing, JSON-based vulnerability DB, and hash-based firmware checks for feasibility. | High-level architecture plan; module breakdown | Directory structure in src/ reflects planned architecture |
| Network Discovery & Fingerprinting | 23 Oct – 29 Oct 2025 | Implement safe and efficient service discovery | Developed concurrent port scanner with timeouts and capped thread pool. Implemented basic banner grabbing and HTTP probing. Added safeguards to prevent scanning non-private hosts. | port_scanner.py, iot_fingerprint.py | Successful local scans; unit tests for open/closed port detection |
| Vulnerability Correlation Engine | 30 Oct – 06 Nov 2025 | Map discovered services to known vulnerabilities | Designed lightweight vulnerability schema. Implemented signature and port-based matching logic. Prioritised explainable results over exhaustive CVE coverage. | vuln_scanner.py, known_vulnerabilities.json | Findings visible in generated reports |
| Configuration & Policy Auditing | 07 Nov – 13 Nov 2025 | Detect insecure configuration patterns | Implemented configuration checks (Telnet enabled, admin HTTP access, debug flags). Created password policy checks for weak/default credentials. | config_auditor.py, password_policy.py | Issues correctly flagged in demo device scans |
| Firmware Integrity Verification | 14 Nov – 20 Nov 2025 | Assess firmware authenticity and update security | Implemented hash-based firmware verification and unsigned firmware detection. Documented limitations compared to signature-based verification. | firmware_checker.py, firmware_hashes.json | Firmware-related findings (FW-001) in report |
| Safe Pentesting Simulations | 21 Nov – 28 Nov 2025 | Simulate common attack vectors without device damage | Developed reflected XSS detection, insecure update metadata checks, and rate-limited brute-force simulation restricted to localhost. | pentesting/ modules | Tests confirm detection without destructive behaviour |
| Reporting & Evidence Generation | 29 Nov – 05 Dec 2025 | Produce audit-ready outputs | Implemented structured JSON report with severity scoring. Added atomic file writes and NDJSON run logging for traceability. | full_report.json, run_log.ndjson | Timestamped artifacts generated consistently |
| Testing, Refinement & Validation | 06 Dec – 21 Dec 2025 | Validate correctness and reliability | Wrote unit and integration tests. Refined scoring weights and report clarity. Verified reproducibility of results. | tests/ directory, final artifacts | All tests pass; consistent output across runs |
| Final Review & Documentation | 22 Dec – 31 Dec 2025 | Prepare submission-ready deliverable | Finalised logbook, reflections, limitations, and future work. Ensured alignment with marking criteria and industry terminology. | Completed logbook and appendices |  |

---

# Needs Analysis and Research

**Identify Vulnerabilities:**  
Uncovering commonly encountered device vulnerabilities remains a fundamental starting point, as indicated by the threat research. Among them are default or weak login credentials, not to mention open network services (including ones like telnet and HTTP) that could potentially be inadequately configured or left unpatched. When trying to determine conveniently unsecured points of access, the system has to inspect device ports along with trying to log in.

**Firmware Integrity Verification:**  
By comparing cryptographic hashes and signing metadata to a trusted firmware database, the system will independently verify embedded firmware while flagging any unsigned, modified, in addition to unaccounted for firmware, as a significant supply-chain risk (OWASP IoT I4).

**Vulnerability correlation:**  
Scans alone aren’t enough, so I map discovered services and banners to known CVEs. By matching port/service fingerprints and banner signatures against a CVE database, I can estimate severity (using base CVSS scores) and prioritise the findings. That way, an open port that’s exposed but low-risk doesn’t drown out a critical, exploitable vulnerability.

**Secure update and patch detection:**  
I check how devices update. If a device exposes update metadata endpoints (for example, `/.well-known/firmware`) or advertises unsigned/outdated firmware, therefore it could potentially open the door to man-in-the-middle and downgrade attacks. The toolkit reports whether update channels are authenticated and whether images support rollback protection.

**Ethical and safe testing:**  
I only run non-destructive and permission-bound tests. My tooling simulates attacks in a controlled environment with safe credential checks, passive captures, and limited, consented login attempts, and as a result, never performs noisy or destructive actions. Logging everything so any testing activity is auditable, while avoiding actions that could trigger denial of service.

**Usability and reporting:**  
Results have to be useful. Findings as clear lists (open ports, banners, matched CVEs, and identified weaknesses) plus practical remediation steps so engineers and managers can act. The output includes a risk priority and an explanation of why each issue matters, not just a raw scan dump.

**Justification against industry frameworks:**  
These requirements aren’t arbitrary — they map directly to OWASP IoT and NIST guidance, which emphasise verifying credentials, services, and update mechanisms. By focusing on these checks, I ensure basic IoT hygiene and give teams actionable insight to reduce risk before deployment.

---

# Solution Design

## Firmware Checker  
Loads a JSON-formatted reference database of known firmware versions. A vendor, version, bound to SHA-256 hash, followed by whether or not the firmware itself has been signed, are among the information contained within each entry. The system computes a hash leveraging those particular firmware parameters extracted from the unit; in the event of a hash value match, it reports successfully. Failing leads to flagged unsigned hashes going to further evaluation. To prevent tampering, the code fits closely to the "verify firmware authenticity" urged practice.

## Port Scanner  
Operates on a thread pool and Python sockets for establishing concurrent TCP port scanning (via `concurrent.futures`). The scanner's algorithm initiates connections with a timeout subsequent to picking up the desired IP and an extensive set of ports. The program retrieves any banner data if a port is currently open. Device services could be verified by picking up vendor banners, which might include "OpenSSH", "mosquitto", and "lighttpd". My approach embraced variable rate caps followed by dynamic timeouts, which guarantee that our response was both lightning-fast and mindful regarding the targeted resources.

## Brute-Force HTTP Login  
This component uses the `requests` library to submit credential attempts to a device’s HTTP login endpoint. It iterates over a supplied password list with optional delays and can stop on the first successful login if configured. Small delays and early termination are used to reduce the risk of causing account lockouts, simulating a controlled penetration test.

## Exploit Simulator
1. **Reflected XSS Test:** The application features a test payload to a search endpoint query parameter and looks to acquire an unescaped reflection of that payload in the response. An examination signifies how the device's web interface could potentially be highly susceptible to cross-site scripting.  
2. **Insecure Update Check:** This instrument retrieves firmware update metadata from a widely used endpoint (for instance, `/.well-known/firmware`) especially highlights the update mechanism if `signed: false` displays in the metadata. Each screening yields a record string and a confidence score.

## Vulnerability Matcher  
We built a JSON-based vulnerability database where each entry contains a vendor/product name, signature keywords (used to match banners), applicable port numbers, and associated CVE identifiers with base scores. The matcher examines the port scanner’s output: when a banner contains signature keywords and the port matches, the vendor is considered identified and any associated CVEs are reported. A composite risk score (for example, a sum or average of base scores) is calculated to quantify risk. The JSON format makes it straightforward to add new signatures or CVEs.

## Workflow and Integration  
Typical usage chains the components: run the port scanner, pass results to the vulnerability matcher, attempt brute-force login against HTTP or telnet ports, perform firmware verification via HTTP or API, and run the exploit simulations. Modules communicate via minimal interfaces (for example, the scanner returns a list of `{port, open, banner}` dictionaries that downstream modules consume), therefore it facilitates independent development and testing.

---

# Architecture and Quality

The design complies with the security architecture principles of defence-in-depth by performing various checks, separation of concerns (scanning versus analysis), and robust operation logging for transparency. I leveraged Python's built-in modules for concurrency, data management (JSON), and networking (`socket`, `http.server`), as well as linting for improving the code's quality. The way it operates embraces both NIST and OWASP guidelines where feasible.

Containers, reference databases, artefact sinks, and safety controls have been highlighted as components. For the purpose of making traceability clear, additionally it annotates the interactions with data types.


---

# Security Testing

## Authorisation & Scope  
**Assumptions used for the record**  
Only local/demo endpoints (`127.0.0.1` / `localhost`) were executed during testing. This is strictly regulated by the logic in `src/pentesting/brute_force.py` which employs `ALLOWED_HOSTS =="127.0.0.1", "localhost"`, followed by `run_full_audit()` (`is_private_host` guard in `src/utils/helpers.py`) checks. A secure simulated device can be generated by the demo mode (`src/main.py: demo_start_simulated_device`). Every individual pentest simulation has been optimised for lab applications and additionally remains non-invasive. Timelines and verification are derived solely from made artefacts.

<img width="14727" height="5658" alt="Arch" src="https://github.com/user-attachments/assets/b2cb3da1-ea07-4f13-b15d-1bef94997514" />

## Boundaries  
**In scope:** port 8080, scan/pentest events generated from `run_full_audit()` and its associated elements, including the local/demo device functionality set up with `demo_start_simulated_device()` (HTTP endpoints `/config.json`, `/search`, `/.well-known/firmware`, `/login`).  
**Out of scope:** public internet access hosts along with external devices

## Methodology

### Reconnaissance and discovery  
`scan_ports()` (file `src/scanner/port_scanner.py`) serves as a concurrent TCP connect scan that relies on gentle HTTP HEAD probe (function `httpprobe`) in addition to banner captures. `DEFAULT_PORTS` defines the set of default ports. List of dictionaries `[{ "port": ..., "open": bool, "banner": str, "latency": ... }, ...]` is the output. Safety: Unless individually permitted, `helpers.is_private_host()` preserves that scans default to local/private ranges.

### Correlation with known vulnerabilities  
`match_vulns_to_scan()` (file `src/scanner/vuln_scanner.py`) compares `data/known_vulnerabilities.json` with ports that are open along with banners. Scoring: base CVSS-like `base_score`, port weight, signature weight, and confidence weight are brought together by `computescore()`.

### Configuration and firmware audit  
`audit_config()` (file `src/auditing/config_auditor.py`) invokes `check_firmware_hash()` (`src/auditing/firmware_checker.py`) to compare firmware hashes to `data/firmware_hashes.json` and searches for potentially dangerous toggles (telnet, admin_http, debug) and weak/default credentials (`_looks_like_default_passwords()`).

### Pentest simulations (non-exploitative, safe)  
To identify reflected input markers and unsigned firmware metadata, respectively, depend on `simulate_reflected_xss()` and `simulate_insecure_update()` in the `src/pentesting/exploit_simulator.py` probe (marker-based detection). Leveraging the `ALLOWED_HOSTS` guard and additional successful detection heuristics in `issuccess_response()`, `brute_force_http_login()` (file `src/pentesting/brute_force.py`) results in a strictly local, rate-limited login attempt loop.

## Reporting  
In `src/scanner/reporting.py`, `create_full_report()` and `generate_html_report()` normalise, followed by archiving the findings to `artifacts/full_report.json` and `artifacts/full_report.html`. The report calls `severity_from_score()` to convert computed_score to text severity.




