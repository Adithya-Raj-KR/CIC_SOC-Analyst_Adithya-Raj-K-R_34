# Detection Engineering Assessment

## Enterprise Security Detection Design & Monitoring Framework

**Prepared By:** Adithya Raj K R  
**Role:** SOC Analyst Intern  
**Project:** Detection Engineering Assessment

---

## Executive Summary

This project focuses on designing enterprise-grade security detections to improve Security Operations Center (SOC) monitoring, reduce attacker dwell time, and enhance incident response capabilities.

The assessment addresses critical threats including:

- Suspicious PowerShell Execution
- Brute Force Authentication Attacks
- Privilege Escalation Activities
- Data Exfiltration Attempts
- Ransomware Behavior

The detection use cases are aligned with the MITRE ATT&CK Framework and include detection logic, severity classification, response actions, false positive analysis, and tuning recommendations.

---

## Business Scenario

The organization has experienced:

- Increased ransomware activity
- Credential theft attempts
- Suspicious PowerShell executions
- Privilege abuse incidents
- Potential insider threats

The SOC team requires improved visibility and detection coverage to identify threats quickly and respond effectively.

### Goals

- Reduce Mean Time to Detect (MTTD)
- Reduce Mean Time to Respond (MTTR)
- Improve detection accuracy
- Strengthen security monitoring
- Enhance incident response

---

## Detection Catalogue

| ID | Detection Use Case | Severity | MITRE ATT&CK |
|----|-------------------|-----------|-------------|
| UC-01 | Suspicious PowerShell Execution | High | T1059.001 |
| UC-02 | Brute Force Authentication Attack | High | T1110 |
| UC-03 | Privilege Escalation Activity | Critical | T1078, T1098 |
| UC-04 | Data Exfiltration Attempt | Critical | T1041 |
| UC-05 | Ransomware Behavior Detection | Critical | T1486 |

---

## MITRE ATT&CK Mapping

| Use Case | Tactic | Technique ID |
|-----------|---------|-------------|
| Suspicious PowerShell | Execution | T1059.001 |
| Brute Force Attack | Credential Access | T1110 |
| Privilege Escalation | Privilege Escalation | T1078 |
| Account Manipulation | Persistence | T1098 |
| Data Exfiltration | Exfiltration | T1041 |
| Ransomware | Impact | T1486 |

---

## Detection Use Cases

### 1. Suspicious PowerShell Execution

**Description:**  
Detects malicious PowerShell commands commonly used for malware execution and persistence.

**Threat Scenario:**
- Phishing compromise
- Encoded PowerShell execution
- Malware download

**Detection Logic**

```text
IF PowerShell contains:
- EncodedCommand
- IEX
- DownloadString
- Invoke-WebRequest

THEN Generate Alert
```

**Severity:** High

**Response Actions**
- Review command execution
- Investigate user activity
- Isolate affected endpoint
- Block malicious domains

---

### 2. Brute Force Authentication Attack

**Description:**  
Detects repeated failed login attempts against user accounts.

**Threat Scenario:**
- Password spraying
- Credential stuffing
- VPN brute force attacks

**Detection Logic**

```text
IF Failed Logins > 10
AND Time Window < 5 Minutes
AND Source IP External

THEN Generate Alert
```

**Severity:** High

**Response Actions**
- Lock account
- Block source IP
- Reset password
- Review authentication logs

---

### 3. Privilege Escalation Activity

**Description:**  
Detects unauthorized privilege assignments and administrative access changes.

**Threat Scenario:**
- Domain Admin addition
- Unauthorized permission changes
- Account takeover

**Detection Logic**

```text
IF User Added To Domain Admins
OR Privileged Group Modified

THEN Generate Alert
```

**Severity:** Critical

**Response Actions**
- Validate authorization
- Remove unauthorized privileges
- Investigate account activity

---

### 4. Data Exfiltration Attempt

**Description:**  
Detects unauthorized transfer of sensitive data outside the organization.

**Threat Scenario:**
- Insider threat
- Compromised account
- Data theft

**Detection Logic**

```text
IF Data Transfer > 5GB
AND Destination External

THEN Generate Alert
```

**Severity:** Critical

**Response Actions**
- Block transfer
- Disable account
- Review accessed files
- Investigate network activity

---

### 5. Ransomware Behavior Detection

**Description:**  
Detects ransomware activity through file encryption and backup deletion behavior.

**Threat Scenario:**
- File encryption
- Backup deletion
- Mass file modification

**Detection Logic**

```text
IF Modified Files > 1000
AND Backup Services Disabled

THEN Generate Alert
```

**Severity:** Critical

**Response Actions**
- Isolate endpoint
- Disable compromised accounts
- Preserve forensic evidence
- Begin recovery process

---

## Alert Triage Guide

| Severity | Action | Response Time |
|-----------|----------|--------------|
| Low | Monitor | 24 Hours |
| Medium | Investigate | 8 Hours |
| High | Escalate to L2 | 1 Hour |
| Critical | Immediate Response | 15 Minutes |

---

## False Positive Analysis

| Use Case | Possible False Positives |
|-----------|------------------------|
| PowerShell | Administrative scripts |
| Brute Force | Forgotten passwords |
| Privilege Escalation | Approved admin changes |
| Data Exfiltration | Legitimate file transfers |
| Ransomware | Backup operations |

### Reduction Strategies

- Baselining
- Threat Intelligence Correlation
- User Risk Scoring
- Asset Criticality Awareness
- Whitelisting Approved Activities

---

## Tuning Recommendations

### Phase 1
- Baseline user activity
- Identify normal administrative behavior

### Phase 2
- Integrate Threat Intelligence
- Enable UEBA correlation

### Phase 3
- Implement SOAR automation
- Risk-based alerting

### Phase 4
- Continuous rule validation
- Monthly tuning reviews

---

## Final SOC Recommendations

The organization should prioritize:

- Advanced PowerShell Monitoring
- Privileged Account Monitoring
- Ransomware Detection
- Data Exfiltration Monitoring
- Identity Threat Detection
- SIEM and EDR Integration
- Threat Intelligence Enrichment
- SOAR Automation

### Expected Benefits

- Reduced attacker dwell time
- Improved detection accuracy
- Faster incident response
- Enhanced threat visibility
- Improved ransomware resilience

---

## Evaluation Criteria

| Criteria | Weightage |
|-----------|-----------|
| Detection Quality | 30% |
| MITRE ATT&CK Mapping | 20% |
| SOC Practicality | 20% |
| False Positive Analysis | 15% |
| Reporting Quality | 15% |

---

## Conclusion

This Detection Engineering Assessment provides enterprise-grade detection use cases focused on ransomware, credential attacks, privilege escalation, data exfiltration, and malicious PowerShell activity.

By implementing these detections, organizations can improve threat visibility, strengthen incident response, reduce attacker dwell time, and enhance overall cybersecurity resilience while aligning with MITRE ATT&CK and SOC best practices.

---
  Detection Engineering Assessment

  # Author
  Adithya Raj K R
