"""
Multi-Model Evaluation & Score Comparison Engine for CyberResponse AI.
Evaluates and benchmarks multiple LLM models across cybersecurity incidents.
"""

import argparse
import json
import os
import time
from typing import Dict, List, Any, Optional

from llm_provider import (
    generate_llm_completion,
    extract_json_from_text,
    SUPPORTED_MODELS,
    get_installed_ollama_models,
    is_model_ready
)
from rag import retrieve_knowledge
from risk import calculate_risk
from validator import validate_playbook


def generate_playbook_for_model(
    incident: Dict[str, Any],
    risk_score: int,
    risk_level: str,
    knowledge_context: str,
    model: str = "llama3.2"
) -> str:
    """Generate defensive playbook using the specified model."""
    prompt = f"""
You are a cybersecurity incident response assistant.

Analyze this security incident:

{json.dumps(incident, indent=2)}

Independent Risk Assessment:
Risk Score: {risk_score}/100
Risk Level: {risk_level}

Use the following retrieved cybersecurity knowledge:

{knowledge_context}

Generate a defensive cybersecurity response playbook.

IMPORTANT:
- Do not change the risk score.
- Do not change the risk level.
- Use the retrieved knowledge.
- Recommend defensive response actions.
- Select the MITRE ATT&CK technique that best matches the incident.

Return ONLY valid JSON:

{{
    "incident_id": "{incident.get('incident_id', 'INC-000')}",
    "incident_type": "{incident.get('type', 'Unknown')}",
    "risk_score": {risk_score},
    "risk_level": "{risk_level}",
    "mitre_techniques": [
        {{
            "technique_id": "...",
            "technique_name": "..."
        }}
    ],
    "actions": [
        {{
            "action": "...",
            "reason": "..."
        }}
    ]
}}

Do not include markdown.
Do not include text outside the JSON.
"""
    return generate_llm_completion(prompt, model=model)


def evaluate_single_incident(
    incident: Dict[str, Any],
    model: str = "llama3.2"
) -> Dict[str, Any]:
    """Evaluate one incident using the chosen model."""
    start_time = time.time()

    # 1. Independent deterministic risk assessment
    risk_score, risk_level = calculate_risk(incident)

    # 2. RAG retrieval
    query = f"""
    {incident.get('type', '')}
    {incident.get('description', '')}
    Target: {incident.get('target', '')}
    Failed attempts: {incident.get('failed_attempts', 0)}
    """
    retrieved = retrieve_knowledge(query, top_k=2)
    knowledge_context = "\n\n".join(retrieved)

    # 3. Model generation
    raw_result = generate_playbook_for_model(
        incident,
        risk_score,
        risk_level,
        knowledge_context,
        model=model
    )
    generation_time = time.time() - start_time

    # 4. JSON validity
    cleaned_json = extract_json_from_text(raw_result)
    try:
        playbook = json.loads(cleaned_json)
        json_valid = True
    except (json.JSONDecodeError, TypeError):
        return {
            "incident_id": incident.get("incident_id"),
            "incident_type": incident.get("type"),
            "model": model,
            "json_valid": False,
            "validation_passed": False,
            "risk_consistent": False,
            "mitre_exact_match": False,
            "mitre_precision": 0.0,
            "mitre_recall": 0.0,
            "mitre_f1": 0.0,
            "generation_time_seconds": round(generation_time, 2),
            "errors": ["Invalid JSON output"]
        }

    # 5. Playbook validation against rules
    errors, warnings = validate_playbook(playbook, risk_score, risk_level)
    validation_passed = (len(errors) == 0)

    # 6. Risk consistency
    risk_consistent = (
        playbook.get("risk_score") == risk_score
        and playbook.get("risk_level") == risk_level
    )

    # 7. MITRE Technique accuracy & F1
    expected_techniques = set(incident.get("expected_mitre_techniques", []))
    generated_techniques = set()
    for item in playbook.get("mitre_techniques", []):
        if isinstance(item, dict) and item.get("technique_id"):
            generated_techniques.add(item["technique_id"])
        elif isinstance(item, str):
            generated_techniques.add(item)

    mitre_exact_match = (
        generated_techniques == expected_techniques
        if expected_techniques else False
    )

    # Precision & Recall
    if len(generated_techniques) > 0:
        mitre_precision = len(generated_techniques.intersection(expected_techniques)) / len(generated_techniques)
    else:
        mitre_precision = 0.0

    if len(expected_techniques) > 0:
        mitre_recall = len(generated_techniques.intersection(expected_techniques)) / len(expected_techniques)
    else:
        mitre_recall = 0.0

    if (mitre_precision + mitre_recall) > 0:
        mitre_f1 = (2 * mitre_precision * mitre_recall) / (mitre_precision + mitre_recall)
    else:
        mitre_f1 = 0.0

    return {
        "incident_id": incident.get("incident_id"),
        "incident_type": incident.get("type"),
        "model": model,
        "json_valid": json_valid,
        "validation_passed": validation_passed,
        "risk_consistent": risk_consistent,
        "mitre_exact_match": mitre_exact_match,
        "mitre_precision": round(mitre_precision * 100, 2),
        "mitre_recall": round(mitre_recall * 100, 2),
        "mitre_f1": round(mitre_f1 * 100, 2),
        "generation_time_seconds": round(generation_time, 2),
        "errors": errors,
        "warnings": warnings,
        "actions_count": len(playbook.get("actions", [])),
        "mitre_techniques_count": len(playbook.get("mitre_techniques", []))
    }


def evaluate_model_on_dataset(
    model: str,
    incidents: List[Dict[str, Any]],
    verbose: bool = True
) -> Dict[str, Any]:
    """Run evaluation for a single model across a dataset of incidents."""
    if verbose:
        print(f"\n---> Evaluating model: [{model}] on {len(incidents)} incidents...")

    results = []
    for i, incident in enumerate(incidents, start=1):
        if verbose:
            print(f"  [{i}/{len(incidents)}] {incident.get('incident_id')} ({incident.get('type')})...", end="", flush=True)

        try:
            res = evaluate_single_incident(incident, model=model)
            results.append(res)
            if verbose:
                status = "PASS" if res.get("validation_passed") else "FAIL"
                print(f" JSON:{res['json_valid']} | F1:{res['mitre_f1']}% | {status} ({res['generation_time_seconds']}s)")
        except Exception as e:
            if verbose:
                print(f" ERROR: {e}")
            results.append({
                "incident_id": incident.get("incident_id"),
                "incident_type": incident.get("type"),
                "model": model,
                "json_valid": False,
                "validation_passed": False,
                "risk_consistent": False,
                "mitre_exact_match": False,
                "mitre_precision": 0.0,
                "mitre_recall": 0.0,
                "mitre_f1": 0.0,
                "generation_time_seconds": 0.0,
                "errors": [str(e)]
            })

    total = len(results)
    if total == 0:
        return {"total": 0}

    json_valid_count = sum(1 for r in results if r["json_valid"])
    validation_pass_count = sum(1 for r in results if r["validation_passed"])
    risk_consistent_count = sum(1 for r in results if r["risk_consistent"])
    mitre_exact_count = sum(1 for r in results if r["mitre_exact_match"])
    mitre_avg_f1 = sum(r["mitre_f1"] for r in results) / total
    mitre_avg_precision = sum(r["mitre_precision"] for r in results) / total
    mitre_avg_recall = sum(r["mitre_recall"] for r in results) / total
    avg_latency = sum(r["generation_time_seconds"] for r in results) / total

    json_rate = round(json_valid_count / total * 100, 2)
    val_rate = round(validation_pass_count / total * 100, 2)
    risk_rate = round(risk_consistent_count / total * 100, 2)
    exact_acc = round(mitre_exact_count / total * 100, 2)
    avg_f1 = round(mitre_avg_f1, 2)

    # Composite Benchmark Score (0-100)
    # Weights: Validation 30%, MITRE F1 35%, Risk Consistency 20%, JSON Validity 15%
    composite_score = round(
        (val_rate * 0.30) +
        (avg_f1 * 0.35) +
        (risk_rate * 0.20) +
        (json_rate * 0.15),
        2
    )

    metrics = {
        "model_id": model,
        "model_name": SUPPORTED_MODELS.get(model, {}).get("name", model),
        "provider": SUPPORTED_MODELS.get(model, {}).get("provider", "ollama"),
        "incidents_evaluated": total,
        "json_validity_rate": json_rate,
        "validation_pass_rate": val_rate,
        "risk_consistency_rate": risk_rate,
        "mitre_exact_accuracy": exact_acc,
        "mitre_average_f1": avg_f1,
        "mitre_average_precision": round(mitre_avg_precision, 2),
        "mitre_average_recall": round(mitre_avg_recall, 2),
        "average_latency_seconds": round(avg_latency, 2),
        "composite_score": composite_score
    }

    return {
        "metrics": metrics,
        "individual_results": results
    }


def compare_models(
    models: List[str],
    dataset_path: str = "dataset/incidents.json",
    limit: Optional[int] = None,
    output_dir: str = "output",
    verbose: bool = True
) -> Dict[str, Any]:
    """Run comparative evaluation on multiple models and output leaderboard."""
    os.makedirs(output_dir, exist_ok=True)

    with open(dataset_path, "r") as f:
        incidents = json.load(f)

    if limit and limit > 0:
        incidents = incidents[:limit]

    print("\n" + "=" * 90)
    print("             CYBERRESPONSE AI - MULTI-MODEL BENCHMARK & COMPARISON")
    print("=" * 90)
    print(f"Dataset: {len(incidents)} incidents")
    print(f"Models to evaluate: {', '.join(models)}")
    print("=" * 90)

    comparison_summary: Dict[str, Any] = {}
    detailed_results: Dict[str, Any] = {}

    for model in models:
        ready, status = is_model_ready(model)
        if not ready:
            print(f"\n[WARNING] Skipping model '{model}': {status}")
            continue

        eval_data = evaluate_model_on_dataset(model, incidents, verbose=verbose)
        if "metrics" in eval_data:
            comparison_summary[model] = eval_data["metrics"]
            detailed_results[model] = eval_data["individual_results"]

            # Save individual model result
            safe_name = model.replace(":", "_").replace("/", "_")
            with open(os.path.join(output_dir, f"evaluation_{safe_name}.json"), "w") as f:
                json.dump(eval_data, f, indent=4)

    # Sort models by composite score descending
    ranked_models = sorted(
        comparison_summary.values(),
        key=lambda x: x["composite_score"],
        reverse=True
    )

    for rank, m in enumerate(ranked_models, start=1):
        m["rank"] = rank

    # Display comparison table
    print("\n")
    print("=" * 115)
    print("                              MODEL PERFORMANCE LEADERBOARD")
    print("=" * 115)
    print(f"{'Rank':<6}{'Model':<20}{'Composite':<12}{'Validation':<14}{'MITRE F1':<12}{'Risk Sync':<12}{'JSON OK':<12}{'Avg Latency':<12}")
    print("-" * 115)

    for m in ranked_models:
        rank_str = f"#{m['rank']}"
        print(
            f"{rank_str:<6}"
            f"{m['model_id']:<20}"
            f"{str(m['composite_score']) + '/100':<12}"
            f"{str(m['validation_pass_rate']) + '%':<14}"
            f"{str(m['mitre_average_f1']) + '%':<12}"
            f"{str(m['risk_consistency_rate']) + '%':<12}"
            f"{str(m['json_validity_rate']) + '%':<12}"
            f"{str(m['average_latency_seconds']) + 's':<12}"
        )
    print("=" * 115)

    # Save overall comparison JSON
    final_output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "incidents_count": len(incidents),
        "leaderboard": ranked_models,
        "models_summary": comparison_summary,
        "detailed_results": detailed_results
    }

    comparison_json_path = os.path.join(output_dir, "model_comparison_results.json")
    with open(comparison_json_path, "w") as f:
        json.dump(final_output, f, indent=4)

    # Generate Markdown Report
    report_md_path = os.path.join(output_dir, "model_comparison_report.md")
    generate_markdown_report(ranked_models, len(incidents), report_md_path)

    print(f"\n[OK] Comparison results saved to: {comparison_json_path}")
    print(f"[OK] Full report generated at: {report_md_path}\n")

    return final_output


def generate_markdown_report(ranked_models: List[Dict[str, Any]], dataset_size: int, output_path: str):
    """Write comprehensive markdown evaluation report."""
    md = [
        "# Cybersecurity LLM Model Benchmark & Evaluation Report",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Evaluation Incidents:** {dataset_size}  ",
        "",
        "## Executive Summary",
        "",
        "This benchmark compares the performance of evaluated Large Language Models on defensive cybersecurity incident response playbook generation. Metrics measure JSON structural conformance, rule-based security validation, independent risk consistency, MITRE ATT&CK technique identification accuracy, and generation latency.",
        "",
        "## Performance Leaderboard",
        "",
        "| Rank | Model ID | Model Name | Composite Score | Validation Rate | MITRE F1 | Risk Sync | JSON Valid | Avg Latency |",
        "|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|"
    ]

    for m in ranked_models:
        medal = "🥇 1" if m["rank"] == 1 else ("🥈 2" if m["rank"] == 2 else ("🥉 3" if m["rank"] == 3 else str(m["rank"])))
        md.append(
            f"| {medal} | `{m['model_id']}` | {m['model_name']} | **{m['composite_score']}/100** | {m['validation_pass_rate']}% | {m['mitre_average_f1']}% | {m['risk_consistency_rate']}% | {m['json_validity_rate']}% | {m['average_latency_seconds']}s |"
        )

    md.extend([
        "",
        "## Metric Definitions",
        "",
        "- **Composite Score**: Weighted aggregate benchmark (35% MITRE F1 + 30% Validation Pass + 20% Risk Consistency + 15% JSON Validity).",
        "- **Validation Rate**: Percentage of playbooks adhering strictly to required schemas, non-empty defensive actions, and zero prohibited/dangerous operations.",
        "- **MITRE F1**: Harmonic mean of Precision and Recall in identifying the correct MITRE ATT&CK technique IDs for the incident.",
        "- **Risk Sync**: Ability of the LLM to strictly preserve deterministic independent risk scores without hallucinating its own assessment.",
        "- **Avg Latency**: End-to-end response generation time per incident.",
        ""
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))


def load_cached_comparison_results(output_dir: str = "output") -> Optional[Dict[str, Any]]:
    """Load previously saved comparison results if available."""
    path = os.path.join(output_dir, "model_comparison_results.json")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def main():
    parser = argparse.ArgumentParser(description="Evaluate and compare LLM models on CyberResponse incidents.")
    parser.add_argument(
        "--models",
        type=str,
        default="",
        help="Comma-separated list of models to evaluate (e.g. 'llama3.2,qwen2.5:1.5b'). Default: all ready models."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of incidents evaluated per model (useful for quick benchmarking)."
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="dataset/incidents.json",
        help="Path to incidents dataset."
    )
    args = parser.parse_args()

    if args.models:
        model_list = [m.strip() for m in args.models.split(",") if m.strip()]
    else:
        # Auto-detect all ready Ollama models and defaults
        installed = get_installed_ollama_models()
        model_list = []
        for candidate in ["llama3.2", "qwen2.5:1.5b", "phi3:mini", "mistral", "gemma2:2b"]:
            if candidate in installed or any(m.startswith(candidate) for m in installed):
                model_list.append(candidate)
        if not model_list:
            model_list = ["llama3.2"]

    compare_models(model_list, dataset_path=args.dataset, limit=args.limit)


if __name__ == "__main__":
    main()
