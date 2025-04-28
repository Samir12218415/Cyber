# Cyber
Cyber Security Mini Projects
->GhosMap
GhostMap is a simple yet effective Python script designed for stealthy network scanning and host discovery.
It allows security researchers and students to:

Identify active hosts on a network

Scan open TCP ports

Collect basic service information

GhostMap was built to strengthen fundamental cybersecurity skills by demonstrating how basic reconnaissance is performed at a low footprint level.

Intended strictly for ethical testing in controlled environments.

⚙️ Requirements
Python 3.7+

scapy (for packet crafting)

socket (standard library)

argparse (standard library)



->keylog
Purpose
This project simulates a basic keylogger in a controlled virtual lab environment.
Its main purpose is to enhance detection skills, understand malware behavior, and develop defensive countermeasures like a real-world cybersecurity professional.

This is for EDUCATIONAL and ETHICAL testing ONLY.
Do NOT deploy or run this tool outside of an isolated, personal, and authorized environment.

Requirements
Virtual Machine (VM) running Windows (XP, 7, 10 — depending on your test case)

Python installed on the VM (if using a Python-based logger)

Administrative rights (optional but recommended for persistence tests)

Windows Defender active for detection trials

Setup
Clone/Download the source code into your test VM.

Ensure network isolation:
Your VM must not have access to external internet unless necessary for updates.

Configure the keylogger payload (if applicable) inside the script:

Output file location

Logging intervals

Optional stealth features (like window hiding)

Usage
Run the script or compiled executable inside the VM.

Monitor its behavior manually:

Use Task Manager to try detecting it.

Use Windows Event Viewer.

Try catching it with Windows Defender, Sysmon, Process Explorer, etc.

Practice detection and removal techniques:

Signature-based detection

Heuristic-based detection

Behavioral analysis

Log your findings:

What behaviors alerted you?

Was it detectable by antivirus?

What forensics artifacts were left behind?

Important Notes
Persistence techniques are NOT enabled by default. If you manually test persistence (e.g., startup folder, scheduled tasks), document and remove all traces afterward.

This tool does NOT attempt to exfiltrate any data.

Always follow the old-school rule:
"Know thy enemy, but harm none."

Disclaimer
This tool is provided solely for educational and lawful purposes.
Any misuse outside controlled and consented environments is strictly forbidden and punishable by law.

