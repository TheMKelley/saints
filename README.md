# SAINTS
### Super Advanced Intelligent Network Threat Scanner

**AI-Assisted Network Monitoring, Anomaly Detection, and Device Discovery**

SAINTS (Super Advanced Intelligent Network Threat Scanner) is a network security platform designed to help users identify devices, monitor network traffic, establish behavioral baselines, and detect potentially suspicious activity. Designed to operate on dedicated SAINTS hardware, the platform aims to make network security more accessible by translating complex network activity into actionable alerts that both technical and non-technical users can understand.

By combining network discovery, packet analysis, and AI-assisted behavioral analysis, SAINTS helps users understand what is happening on their networks and identify activity that deviates from expected behavior.

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [How It Works](#how-it-works)
- [System Architecture](#system-architecture)
- [Threat Detection](#threat-detection)
- [Alerts and Notifications](#alerts-and-notifications)
- [Hardware Integration](#hardware-integration)
- [Installation](#installation)
- [Configuration](#configuration)
- [Security and Privacy](#security-and-privacy)
- [Project Roadmap](#project-roadmap)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Modern networks contain a constantly changing collection of devices, connections, and communication patterns. Traditional security tools can be difficult to configure, interpret, and maintain, particularly for users without a dedicated cybersecurity background.

SAINTS is designed to address this challenge by providing continuous network visibility and intelligent anomaly detection through a dedicated hardware module.

The platform focuses on three primary objectives:

1. **Network visibility:** Identify devices connected to a monitored network and provide insight into their network activity.
2. **Behavioral analysis:** Analyze observed packet activity to establish a baseline of normal network behavior.
3. **Threat awareness:** Identify unexpected devices, unusual traffic patterns, and other potential security concerns, then notify the user in understandable language.

SAINTS is intended to function as a network monitoring and early-warning solution that complements existing security controls.

## Core Features

### 1. Network Device Discovery

Discover and maintain an inventory of devices observed on the monitored network.

Planned capabilities include:

- Identify devices using available network information, including IP and MAC addresses.
- Track newly observed and previously known devices.
- Maintain a list of devices and their observed activity.
- Identify devices that appear unexpectedly.
- Detect changes in device attributes or network presence when sufficient information is available.
- Present discovered devices through a centralized interface.

### 2. Packet and Traffic Analysis

Observe network traffic to understand communication patterns and identify potentially suspicious behavior.

Planned capabilities include:

- Capture or ingest network packet metadata.
- Analyze source and destination addresses.
- Inspect available protocol and port information.
- Track communication frequency and traffic volume.
- Identify unusual connection patterns.
- Maintain records of relevant network events.
- Support packet trace review for troubleshooting and security analysis.

*Note: Visibility into packet contents depends on capture permissions, network topology, encryption, and the hardware's access to the relevant traffic.*

### 3. AI-Assisted Behavioral Baseline

SAINTS is designed to learn the typical behavior of a monitored network over time.

During an initial observation period, the system collects information about known devices, communication patterns, protocols, and traffic characteristics. This information is used to establish a baseline against which future activity can be evaluated.

Baseline analysis may include:

- Commonly observed devices.
- Typical communication destinations.
- Expected protocols and ports.
- Normal traffic volumes and connection frequencies.
- Recurring communication patterns.
- Time-based variations in network activity.

As additional data becomes available, the baseline can be updated to reflect legitimate changes in network behavior.

### 4. Anomaly Detection

SAINTS compares observed activity against established behavioral patterns to identify deviations that may warrant investigation.

Potential detections include:

- Previously unseen devices.
- Unexpected outbound connections.
- Unusual increases in traffic volume.
- New or uncommon communication patterns.
- Abnormal connection frequencies.
- Unexpected protocol or port usage.
- Changes in the behavior of previously known devices.
- Repeated connection attempts that may indicate scanning or other suspicious activity.

An anomaly does not automatically indicate an attack. SAINTS is intended to help users identify events that deserve closer examination.

### 5. Intelligent Alerts

SAINTS aims to make security events understandable and actionable rather than presenting users with unexplained technical data.

Notifications may include:

- **Event:** What happened.
- **Device:** Which device was involved, when identifiable.
- **Severity:** The estimated level of concern.
- **Reason:** Why the activity differs from the established baseline.
- **Evidence:** Relevant traffic metadata and supporting observations.
- **Recommended action:** Suggested steps for investigation.

Example alert:

> **Unexpected Device Detected**
>
> A previously unobserved device has appeared on your network.
>
> **Device IP:** `192.168.1.47`  
> **Detection:** Device not present in the current known-device inventory  
> **Severity:** Medium  
> **Recommended action:** Verify that the device belongs to you or an authorized network user.

This example illustrates the intended alert format and is not a report of an actual detection.

---

## How It Works

SAINTS is designed around a continuous monitoring and analysis workflow.

1. **Observe:** Collect available network traffic information and device metadata.
2. **Discover:** Identify devices and record their observed network characteristics.
3. **Establish a baseline:** Learn common traffic patterns and expected device behavior.
4. **Analyze:** Compare new observations against the current baseline and configured detection rules.
5. **Evaluate:** Determine whether deviations warrant an alert based on their characteristics and context.
6. **Notify:** Present relevant findings and recommended investigative actions.
7. **Adapt:** Incorporate verified changes into the baseline under appropriate controls.

### Monitoring Lifecycle

```text
+---------------------------+
|   Network Traffic Input   |
+-------------+-------------+
              |
              v
+---------------------------+
| Device Discovery &        |
| Traffic Metadata Analysis |
+-------------+-------------+
              |
              v
+---------------------------+
| Behavioral Baseline       |
| & Historical Observations |
+-------------+-------------+
              |
              v
+---------------------------+
| Anomaly Detection Engine  |
+-------------+-------------+
              |
              v
+---------------------------+
| Event Evaluation &        |
| Severity Assessment      |
+-------------+-------------+
              |
              v
+---------------------------+
| User Alerts & Event Logs  |
+---------------------------+
```

The diagram represents the intended processing workflow. Actual implementation details may vary as the software develops.

---

## System Architecture

SAINTS is intended to operate as software deployed on a dedicated hardware module. Its architecture can be organized into the following logical components.

| Component | Responsibility |
|---|---|
| Network Interface | Provides access to the monitored network and available traffic observations. |
| Device Discovery Module | Identifies and tracks observed network devices. |
| Packet Analysis Module | Extracts relevant information from packet traces and network traffic. |
| Data Collection Module | Organizes observations into a consistent format for downstream analysis. |
| Baseline Engine | Maintains a model of typical network behavior. |
| AI and Anomaly Detection Engine | Evaluates traffic patterns and identifies potentially suspicious deviations. |
| Alert Management Module | Assigns event context and severity, and generates notifications. |
| Logging and Storage Module | Records device observations, events, and relevant historical information. |
| User Interface | Displays network status, device inventories, alerts, and supporting evidence. |

These components describe the intended software architecture and do not imply that every component is fully implemented.

---

## Threat Detection

SAINTS focuses on identifying indicators of potentially suspicious behavior through observed network activity.

| Detection Category | Example Behavior |
|---|---|
| Unknown Devices | A device appears that is not in the known-device inventory. |
| Traffic Anomalies | A device generates substantially more traffic than its baseline. |
| Connection Anomalies | A device begins communicating with unusual destinations. |
| Port and Protocol Changes | A device uses communication patterns not previously observed. |
| Scanning Indicators | Repeated connection attempts target numerous hosts or ports. |
| Behavioral Changes | A known device exhibits a significant change in its communication patterns. |

Detection quality depends on the available network telemetry, the baseline's accuracy, and the detection methods implemented.

SAINTS should not be treated as a guarantee that all malicious activity will be detected. Some threats may resemble legitimate activity, while legitimate network changes may trigger false positives.

---

## Alerts and Notifications

The goal of the SAINTS notification system is to make potential security incidents understandable without requiring users to interpret raw packet data.

A proposed severity model includes:

- **Informational:** A noteworthy event with no immediate indication of malicious activity.
- **Low:** A minor deviation that may warrant review.
- **Medium:** An unusual event that should be investigated.
- **High:** A significant deviation or combination of indicators that requires prompt attention.
- **Critical:** An event meeting configured criteria for an urgent security concern.

Severity levels are intended to communicate investigative priority, not to prove that an attack has occurred.

Future notification channels may include an on-device dashboard, visual alerts, email, or other configurable delivery methods.

---

## Hardware Integration

SAINTS is designed to run on a dedicated hardware device that monitors network activity and processes observations through its software stack.

Hardware integration will depend on the selected network interfaces, processing capabilities, storage capacity, and supported operating environment.

Important considerations include:

- Network interface compatibility.
- Access to traffic on the intended network segment.
- CPU and memory requirements for packet processing and analysis.
- Storage requirements for event history and baseline data.
- Secure configuration and software updates.
- Reliable operation during network interruptions.
- Protection of captured traffic and stored information.

The exact hardware requirements and supported platforms will be documented as the implementation is finalized.

---

## Installation

Installation instructions will depend on the finalized hardware platform, operating system, dependencies, and deployment method.

### Prerequisites

Before deploying SAINTS, ensure that you have:

- A supported SAINTS hardware module or development environment.
- The required runtime and software dependencies.
- A compatible network interface or authorized traffic source.
- Appropriate permissions to observe network traffic.
- Sufficient resources for packet processing, event storage, and analysis.

### Development Setup

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd SAINTS
   ```

2. Install the project dependencies according to the instructions for the implemented software stack.

3. Configure the appropriate network interface and traffic collection settings.

4. Configure storage, baseline initialization, and notification preferences.

5. Start the application using the project's designated entry point.

**Note:** The commands above provide a repository setup example. The final dependency installation and startup commands should be added once the project's directory structure and runtime are established.

---

## Configuration

SAINTS should provide configurable settings for its monitoring and analysis behavior.

Potential configuration options include:

| Setting | Purpose |
|---|---|
| Network Interface | Selects the interface or traffic source to monitor. |
| Baseline Learning Period | Defines the initial period used to learn typical network activity. |
| Alert Sensitivity | Adjusts how readily deviations generate alerts. |
| Known Devices | Allows users to review and identify authorized devices. |
| Notification Preferences | Controls which events trigger notifications and how they are delivered. |
| Event Retention | Defines how long event records and relevant metadata are retained. |
| Trusted Changes | Supports the review and approval of legitimate changes to network behavior. |

Configuration names and available options will depend on the final implementation.

---

## Security and Privacy

Because SAINTS processes network-related information, security and privacy must be considered core design requirements.

Recommended safeguards include:

- **Least privilege:** Grant only the permissions required for monitoring.
- **Data minimization:** Collect and retain only the information necessary for the intended security functions.
- **Secure storage:** Protect event records and configuration data against unauthorized access.
- **Access control:** Restrict access to sensitive monitoring information.
- **Transparent monitoring:** Clearly identify the network and interfaces being monitored.
- **Retention controls:** Provide appropriate limits on stored traffic data and event history.
- **Secure updates:** Verify software updates and protect the update process.
- **Responsible AI:** Provide explanations and supporting evidence for alerts wherever possible.

Network monitoring should be performed only on networks and systems for which the operator has appropriate authorization.

---

## Project Roadmap

The following roadmap outlines potential development milestones.

- [ ] Establish the software architecture and hardware interface.
- [ ] Implement network device discovery.
- [ ] Implement packet metadata collection and parsing.
- [ ] Develop a searchable inventory of observed devices.
- [ ] Create event logging and historical storage.
- [ ] Implement initial behavioral baseline generation.
- [ ] Develop anomaly detection and event scoring.
- [ ] Implement unknown-device and unusual-traffic alerts.
- [ ] Build a user-friendly monitoring dashboard.
- [ ] Add configurable notification channels.
- [ ] Add controls for baseline review and trusted-device management.
- [ ] Test detection accuracy and false-positive rates.
- [ ] Evaluate resource usage on the target hardware.
- [ ] Document deployment, maintenance, and troubleshooting procedures.

Roadmap items should be marked complete as they are implemented and validated.

---

## Disclaimer

SAINTS is intended to support network visibility, security monitoring, and anomaly investigation. Alerts indicate activity that may warrant review and should not be interpreted as definitive proof of malicious behavior.

The effectiveness of SAINTS depends on its implementation, available network visibility, configuration, and detection models. It is not a substitute for comprehensive security practices, including secure device configuration, patch management, access controls, firewalls, and incident response procedures.

Users are responsible for ensuring that their monitoring activities comply with applicable laws, policies, and authorization requirements.

---

## Contributing

Contributions that improve detection quality, reliability, usability, documentation, and security are welcome.

Before contributing:

1. Review the existing architecture and coding conventions.
2. Describe the problem or proposed enhancement.
3. Include tests for new functionality where practical.
4. Document changes to configuration and deployment requirements.
5. Avoid submitting credentials, private network captures, or other sensitive data.

Please submit bugs and feature requests through the repository's issue tracker.

---

## License

The project's license has not yet been specified. Add a `LICENSE` file and update this section before distributing SAINTS publicly.

---

**SAINTS - Making Network Security More Intelligent, Accessible, and Actionable.**
