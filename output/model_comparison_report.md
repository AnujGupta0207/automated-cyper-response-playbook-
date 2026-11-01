# Cybersecurity LLM Model Benchmark & Evaluation Report
**Generated:** 2026-11-02 03:02:20  
**Evaluation Incidents:** 10  

## Executive Summary

This benchmark compares the performance of evaluated Large Language Models on defensive cybersecurity incident response playbook generation. Metrics measure JSON structural conformance, rule-based security validation, independent risk consistency, MITRE ATT&CK technique identification accuracy, and generation latency.

## Performance Leaderboard

| Rank | Model ID | Model Name | Composite Score | Validation Rate | MITRE F1 | Risk Sync | JSON Valid | Avg Latency |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| 🥇 1 | `llama3.2` | Llama 3.2 (3B) | **100.0/100** | 100.0% | 100.0% | 100.0% | 100.0% | 11.5s |
| 🥈 2 | `gemma2:2b` | Gemma 2 (2B) | **100.0/100** | 100.0% | 100.0% | 100.0% | 100.0% | 9.46s |
| 🥉 3 | `qwen2.5:1.5b` | Qwen 2.5 (1.5B) | **98.83/100** | 100.0% | 96.67% | 100.0% | 100.0% | 4.62s |
| 4 | `gpt-4o-mini` | GPT-4o Mini | **0.0/100** | 0.0% | 0.0% | 0.0% | 0.0% | 0.0s |
| 5 | `gpt-4o` | GPT-4o | **0.0/100** | 0.0% | 0.0% | 0.0% | 0.0% | 0.0s |

## Metric Definitions

- **Composite Score**: Weighted aggregate benchmark (35% MITRE F1 + 30% Validation Pass + 20% Risk Consistency + 15% JSON Validity).
- **Validation Rate**: Percentage of playbooks adhering strictly to required schemas, non-empty defensive actions, and zero prohibited/dangerous operations.
- **MITRE F1**: Harmonic mean of Precision and Recall in identifying the correct MITRE ATT&CK technique IDs for the incident.
- **Risk Sync**: Ability of the LLM to strictly preserve deterministic independent risk scores without hallucinating its own assessment.
- **Avg Latency**: End-to-end response generation time per incident.
