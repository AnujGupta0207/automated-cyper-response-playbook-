# CyberResponse AI - Automated Cybersecurity Incident Response with Multi-LLM Evaluation

CyberResponse AI is an intelligent security operations system that analyzes cybersecurity incidents, calculates deterministic independent risk scores, retrieves MITRE ATT&CK defensive intelligence via RAG, and generates structured defensive playbooks using Large Language Models (LLMs).

This project features a **Multi-Model Architecture and Benchmarking System** allowing security teams to compare and evaluate multiple LLMs on identical security incidents.

---

## Key Features

1. **Multi-Model LLM Support**:
   - Seamlessly switch between local models (Ollama: **Llama 3.2 (3B)**, **Qwen 2.5 (1.5B)**, **Gemma 2 (2B)**, **Phi-3 Mini**, **Mistral 7B**) and cloud models (**GPT-4o Mini**, **GPT-4o**).
   - Unified provider interface (`llm_provider.py`) with automatic fallback, clean JSON extraction, and model status detection.

2. **Model Benchmark & Score Comparison Engine (`compare_models.py`)**:
   - Evaluates multiple models against real-world incidents.
   - Calculates key metrics:
     - **JSON Validity Rate (%)**: Structural conformance to schema.
     - **Playbook Validation Pass Rate (%)**: Rule-based checks (required fields, non-empty defensive actions, zero hazardous commands).
     - **MITRE ATT&CK Precision, Recall & F1 Score (%)**: Accuracy in mapping attacks to proper MITRE techniques.
     - **Deterministic Risk Consistency (%)**: Strict alignment with independent risk engine values without hallucination.
     - **Generation Latency (seconds)**: Inference response speed.
     - **Composite Benchmark Score (0–100)**: Weighted index combining accuracy, validation, and consistency.

3. **Interactive SOC Dashboard (Flask Web UI)**:
   - Select any incident and choose the active LLM from a dynamic model dropdown.
   - Visual **Model Benchmark & Scores Dashboard** (`/compare`) featuring real-time performance leaderboards, side-by-side metric comparison bars, and custom benchmark triggers.
   - Incident history with model tracking and simulated SOAR execution approval workflow.

4. **Multi-Stage Ablation Experiments (`experiment.py`)**:
   - Compare "LLM Only" vs "LLM + RAG" vs "LLM + RAG + Risk" vs "Full System" across any evaluated model.

---

## Architecture Pipeline

```
[ Security Incident ]
         │
         ├───► [ Independent Deterministic Risk Engine ] (risk.py)
         │                       │
         ├───► [ MITRE ATT&CK RAG Retrieval ] (rag.py - MiniLM-L6-v2)
         │                       │
         ▼                       ▼
   [ Selected LLM Model ] (Llama 3.2 / Qwen 2.5 / Gemma 2 / GPT-4o)
         │
         ▼
   [ Structured Playbook JSON ]
         │
         ▼
   [ Rule-Based Safety Validator ] (validator.py)
         │
         ▼
   [ Human-in-the-Loop SOAR Approval ] (approval.py / app.py)
```

---

## Quick Start

### 1. Prerequisites & Installation

Activate the virtual environment and install dependencies:

```bash
# Windows PowerShell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Ollama Local Models

Make sure [Ollama](https://ollama.ai) is running. To pull models:

```bash
ollama pull llama3.2
ollama pull qwen2.5:1.5b
ollama pull gemma2:2b
```

To configure OpenAI models, add your key to `.env`:

```env
OPENAI_API_KEY=your_key_here
```

---

## Usage Guide

### A. Run Multi-Model Score Comparison

Compare models and generate the benchmark leaderboard:

```bash
# Compare installed models on a 10-incident sample
python compare_models.py --models llama3.2,qwen2.5:1.5b,gemma2:2b --limit 10

# Compare on full 30-incident research dataset
python compare_models.py --models llama3.2,qwen2.5:1.5b,gemma2:2b

# Compare all ready models automatically
python compare_models.py
```

Generated outputs:
- `output/model_comparison_results.json`: Complete benchmark matrix and metrics.
- `output/model_comparison_report.md`: Markdown leaderboard report.
- `output/evaluation_<model>.json`: Individual model evaluation logs.

### B. Single Model Evaluation

Evaluate one model on the research dataset:

```bash
python evaluate.py --model qwen2.5:1.5b
python evaluate.py --model llama3.2
```

### C. Run Ablation Experiment

Test ablation stages (LLM Only vs RAG vs Risk vs Full System) on any model:

```bash
python experiment.py --model qwen2.5:1.5b
```

### D. Single Incident CLI

Run a single incident through the full pipeline with a chosen model:

```bash
python main.py --model qwen2.5:1.5b
```

### E. Web Dashboard

Launch the Flask SOC web application:

```bash
python app.py
```

Open your browser to:
- **Incident Dashboard**: `http://127.0.0.1:5000/` (select incident & model)
- **Model Benchmark & Scores**: `http://127.0.0.1:5000/compare` (view comparative scores, rankings, and run tests)
- **Incident History**: `http://127.0.0.1:5000/history` (view historical runs with model metadata)

---

## Benchmark Metrics

| Metric | Target | Description |
|:---|:---:|:---|
| **Composite Score** | 0–100 | Weighted overall score (35% MITRE F1 + 30% Validation + 20% Risk Sync + 15% JSON) |
| **Validation Rate** | 100% | Percentage of playbooks passing all security & safety rules |
| **MITRE F1** | >90% | Harmonic mean of precision and recall in MITRE ATT&CK technique identification |
| **Risk Sync** | 100% | Verification that the LLM faithfully kept independent risk score without hallucination |
| **JSON Validity** | 100% | Syntactically correct JSON parsing without markdown wrappers |
| **Avg Latency** | < 5s | Average generation response time per playbook |
