# Guide for Completing the Detection Rule Template

This guide provides detailed instructions on how to fill out the Detection Rule Template to ensure comprehensive and effective rule documentation.

## Basic Information

- **Author:** [Author's Name]
  - *Why:* Identifies the creator of the rule for accountability and contact purposes.
- **Creation Date:** [YYYY-MM-DD]
  - *Why:* Helps track when the rule was initially created and aids in version control.
- **Maturity:** [Development / Testing / Production]
  - *Why:* Indicates the development stage of the rule, helping users understand its readiness and stability.
- **Reference:** [URL or Document Reference]
  - *Why:* Provides a source for additional information or the origin of the rule, such as a threat report or research paper.

## Naming

- **Name:** [Descriptive Name of the Rule]
  - *Why:* A clear, descriptive name helps users quickly understand the rule’s purpose.
- **Description:** [Brief but Comprehensive Description]
  - *Why:* Explains what the rule does, the threat it addresses, or the behavior it detects, providing context for users.

## Technical Details

- **Tags:** [Keywords or Categories]
  - *Why:* Tags help in classifying and searching for the rule based on key themes or characteristics.
- **Data Source:** [Logs, Events, Network Traffic, etc.]
  - *Why:* Specifies the type of data or source that the rule applies to, aiding in its correct implementation.

## Rule Implementation

- **Rule Implementation**
  - *Why:* The actual code/script for the rule. Written in YAML or another relevant format, this is the core component that will be implemented in security tools.

```yaml
[Insert Rule Code Here]
```


- **Response:** [Recommended Response Procedures or Actions]
  - *Why:* Guides users on what to do when the rule is triggered, such as alerting, blocking actions, or further investigation steps.
- **False Positive:** [Known False Positives and Handling Instructions]
  - *Why:* Helps users understand situations where the rule might trigger incorrectly and how to handle such cases.
- **Severity:** [Low / Medium / High / Critical]
  - *Why:* Indicates the importance or impact level of the detected issue, aiding in prioritization of responses.
- **Confidence:** [Percentage or Low / Medium / High]
  - *Why:* Reflects how reliable the rule is in accurately detecting the intended threat or behavior.