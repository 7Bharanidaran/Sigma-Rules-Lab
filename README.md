# Sigma Rules Lab

A cybersecurity mini project focused on developing and validating a custom Sigma rule to detect suspicious PowerShell encoded command execution. The project demonstrates fundamental concepts in detection engineering and the translation of platform-independent detection logic into SIEM-compatible queries.

---

## Overview

Sigma Rules Lab showcases the creation of a custom Sigma rule designed to identify PowerShell commands executed with encoded payloads. Such techniques are commonly associated with malicious activity and are frequently observed during attack campaigns.

The rule is validated using Sigma CLI and converted into a Splunk-compatible query, illustrating how Sigma enables portable and standardized detection content across security platforms.

---

## Objectives

* Develop a custom Sigma rule for Windows environments.
* Detect suspicious PowerShell encoded command execution.
* Validate rule syntax using Sigma CLI.
* Convert Sigma detection logic into a SIEM-compatible query.
* Demonstrate foundational detection engineering concepts.

---

## Project Structure

```text
Sigma-Rules-Lab
│
├── README.md
├── sigma_rules
│   └── suspicious_powershell.yml
│
├── screenshots
│   ├── folder_structure.png
│   ├── rule_creation.png
│   ├── sigma_installation.png
│   ├── rule_validation.png
│   └── github_repo.png
│
└── venv
```

---

## Technologies Used

* Sigma Rules
* Sigma CLI
* Python
* YAML
* Kali Linux
* GitHub
* Visual Studio Code

---

## Sigma Rule

```yaml
title: Suspicious PowerShell Encoded Command

id: 123e4567-e89b-12d3-a456-426614174000

status: experimental

description: Detects PowerShell commands executed with Base64 encoding.

author: Bharanidaran

logsource:
  product: windows

detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'

  condition: selection

level: high
```

---

## Validation

The rule was successfully validated using Sigma CLI:

```bash
sigma convert -t splunk --without-pipeline sigma_rules/suspicious_powershell.yml
```

### Generated Query

```text
CommandLine IN ("*-enc*", "*-EncodedCommand*")
```

---

## Detection Workflow

```text
Windows Event Logs
        ↓
Custom Sigma Rule
        ↓
Sigma CLI
        ↓
Splunk Query Conversion
        ↓
Alert Generation
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique  |
| ------------ | ---------- |
| T1059.001    | PowerShell |

---

## Applications

* Detection Engineering
* Threat Hunting
* Security Monitoring
* SIEM Rule Development
* Incident Response

---

## Screenshots

The repository includes screenshots demonstrating:

* Project structure
* Sigma rule implementation
* Sigma CLI validation
* Query conversion output
* Repository organization

---

## Future Enhancements

* Expand the repository with additional Sigma rules.
* Support multiple SIEM backends.
* Increase coverage of MITRE ATT&CK techniques.
* Develop a broader collection of detection content for common attack scenarios.

---

## Author

**Bharanidaran S**

---

## References

* SigmaHQ
* pySigma
* MITRE ATT&CK Framework
* Splunk Documentation
