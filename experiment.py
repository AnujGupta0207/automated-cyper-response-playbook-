import json
import time
import argparse
import os

from llm_provider import generate_llm_completion, extract_json_from_text, SUPPORTED_MODELS
from rag import retrieve_knowledge
from risk import calculate_risk
from validator import validate_playbook


# ============================================================
# LLM GENERATION
# ============================================================

def generate_llm_response(
    incident,
    knowledge_context="",
    risk_score=None,
    risk_level=None,
    model="llama3.2"
):

    prompt = f"""
You are a cybersecurity incident response assistant.

Analyze the following security incident:

{json.dumps(incident, indent=2)}
"""

    # Add deterministic risk information when enabled
    if risk_score is not None:
        prompt += f"""

Independent Risk Assessment:

Risk Score: {risk_score}/100
Risk Level: {risk_level}

IMPORTANT:
Use exactly this risk score and risk level in the generated playbook.
Do not change or invent the values.
"""

    # Add RAG context when enabled
    if knowledge_context:
        prompt += f"""

Retrieved Cybersecurity Knowledge:

{knowledge_context}

Use the retrieved knowledge to identify the most appropriate
MITRE ATT&CK technique and defensive response actions.
"""

    prompt += """

Generate a defensive cybersecurity response playbook.

IMPORTANT RULES:

1. Return ONLY valid JSON.
2. Do not use markdown.
3. Do not add explanations outside the JSON.
4. Recommend defensive and safe response actions.
5. Identify the most appropriate MITRE ATT&CK technique.
"""

    if risk_score is not None:
        prompt += f"""
6. The risk_score MUST be exactly {risk_score}.
7. The risk_level MUST be exactly "{risk_level}".
"""

    prompt += """

Return this JSON structure:

{
    "incident_id": "...",
    "incident_type": "...",
    "risk_score": 0,
    "risk_level": "...",
    "mitre_techniques": [
        {
            "technique_id": "...",
            "technique_name": "..."
        }
    ],
    "actions": [
        {
            "action": "...",
            "reason": "..."
        }
    ]
}
"""

    return generate_llm_completion(prompt, model=model)


# ============================================================
# EVALUATE ONE INCIDENT
# ============================================================

def evaluate_incident(incident, experiment, model="llama3.2"):

    start_time = time.time()

    # --------------------------------------------------------
    # STEP 1: Determine whether RAG is enabled
    # --------------------------------------------------------

    knowledge_context = ""

    if experiment in [
        "LLM + RAG",
        "LLM + RAG + Risk",
        "Full System"
    ]:

        query = f"""
        Incident Type: {incident['type']}
        Description: {incident['description']}
        Target: {incident['target']}
        Failed Attempts: {incident['failed_attempts']}
        """

        retrieved = retrieve_knowledge(
            query,
            top_k=2
        )

        knowledge_context = "\n\n".join(retrieved)

    # --------------------------------------------------------
    # STEP 2: Determine whether Risk Engine is enabled
    # --------------------------------------------------------

    risk_score = None
    risk_level = None

    if experiment in [
        "LLM + RAG + Risk",
        "Full System"
    ]:

        risk_score, risk_level = calculate_risk(
            incident
        )

    # --------------------------------------------------------
    # STEP 3: Generate LLM response
    # --------------------------------------------------------

    raw_result = generate_llm_response(
        incident,
        knowledge_context=knowledge_context,
        risk_score=risk_score,
        risk_level=risk_level,
        model=model
    )

    generation_time = time.time() - start_time

    # --------------------------------------------------------
    # STEP 4: Check JSON validity
    # --------------------------------------------------------

    cleaned_json = extract_json_from_text(raw_result)

    try:

        playbook = json.loads(cleaned_json)

        json_valid = True

    except (json.JSONDecodeError, TypeError):

        return {
            "json_valid": False,
            "mitre_exact_match": False,
            "mitre_precision": 0,
            "mitre_recall": 0,
            "mitre_f1": 0,
            "risk_consistent": None,
            "validation_passed": None,
            "generation_time": round(
                generation_time,
                2
            )
        }

    # --------------------------------------------------------
    # STEP 5: MITRE evaluation
    # --------------------------------------------------------

    expected_techniques = set(
        incident.get(
            "expected_mitre_techniques",
            []
        )
    )

    generated_techniques = set()

    for technique in playbook.get(
        "mitre_techniques",
        []
    ):

        technique_id = technique.get(
            "technique_id"
        )

        if technique_id:
            generated_techniques.add(
                technique_id
            )

    # Exact match
    mitre_exact_match = (
        generated_techniques
        == expected_techniques
    )

    # Precision
    if len(generated_techniques) > 0:

        mitre_precision = (
            len(
                generated_techniques
                .intersection(
                    expected_techniques
                )
            )
            /
            len(generated_techniques)
        )

    else:

        mitre_precision = 0

    # Recall
    if len(expected_techniques) > 0:

        mitre_recall = (
            len(
                generated_techniques
                .intersection(
                    expected_techniques
                )
            )
            /
            len(expected_techniques)
        )

    else:

        mitre_recall = 0

    # F1
    if (
        mitre_precision
        + mitre_recall
    ) > 0:

        mitre_f1 = (
            2
            * mitre_precision
            * mitre_recall
            /
            (
                mitre_precision
                + mitre_recall
            )
        )

    else:

        mitre_f1 = 0

    # --------------------------------------------------------
    # STEP 6: Risk consistency
    # --------------------------------------------------------

    risk_consistent = None

    if risk_score is not None:

        risk_consistent = (
            playbook.get(
                "risk_score"
            )
            == risk_score
            and
            playbook.get(
                "risk_level"
            )
            == risk_level
        )

    # --------------------------------------------------------
    # STEP 7: Full System validation
    # --------------------------------------------------------

    validation_passed = None

    if experiment == "Full System":

        # ----------------------------------------------------
        # Deterministic risk fields
        #
        # This ensures the final system never relies on the
        # LLM to calculate the official risk score.
        # ----------------------------------------------------

        playbook["risk_score"] = risk_score
        playbook["risk_level"] = risk_level

        errors, warnings = validate_playbook(
            playbook,
            risk_score,
            risk_level
        )

        validation_passed = (
            len(errors) == 0
        )

    # --------------------------------------------------------
    # STEP 8: Return results
    # --------------------------------------------------------

    return {
        "json_valid": json_valid,

        "mitre_exact_match":
            mitre_exact_match,

        "mitre_precision":
            round(
                mitre_precision * 100,
                2
            ),

        "mitre_recall":
            round(
                mitre_recall * 100,
                2
            ),

        "mitre_f1":
            round(
                mitre_f1 * 100,
                2
            ),

        "risk_consistent":
            risk_consistent,

        "validation_passed":
            validation_passed,

        "generation_time":
            round(
                generation_time,
                2
            )
    }


# ============================================================
# MAIN EXPERIMENT
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Run Cybersecurity Ablation Experiment on an LLM model.")
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.2",
        help="LLM model to use for ablation (e.g. 'llama3.2', 'qwen2.5:1.5b', 'gemma2:2b'). Default: llama3.2"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of incidents evaluated."
    )
    args = parser.parse_args()
    model = args.model

    print("\n" + "=" * 90)
    print(
        "          CYBERSECURITY ABLATION EXPERIMENT"
    )
    print(f"          Model: {model}")
    print("=" * 90)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    with open(
        "dataset/incidents.json",
        "r"
    ) as file:

        incidents = json.load(file)

    if args.limit and args.limit > 0:
        incidents = incidents[:args.limit]

    print(
        f"\nDataset size: {len(incidents)} incidents"
    )

    # --------------------------------------------------------
    # Experiments
    # --------------------------------------------------------

    experiments = [
        "LLM Only",
        "LLM + RAG",
        "LLM + RAG + Risk",
        "Full System"
    ]

    all_results = {}

    # --------------------------------------------------------
    # Run experiments
    # --------------------------------------------------------

    for experiment in experiments:

        print("\n")
        print("=" * 90)

        print(
            "EXPERIMENT:",
            experiment
        )

        print("=" * 90)

        results = []

        for i, incident in enumerate(
            incidents,
            start=1
        ):

            print(
                f"[{i}/{len(incidents)}] "
                f"{incident['incident_id']} "
                f"- "
                f"{incident['type']}"
            )

            try:

                result = evaluate_incident(
                    incident,
                    experiment,
                    model=model
                )

                results.append(result)

                print(
                    f"  JSON: "
                    f"{result['json_valid']} | "
                    f"MITRE: "
                    f"{result['mitre_exact_match']}"
                )

            except Exception as e:

                print(
                    "  ERROR:",
                    e
                )

                results.append({
                    "json_valid": False,
                    "mitre_exact_match": False,
                    "mitre_precision": 0,
                    "mitre_recall": 0,
                    "mitre_f1": 0,
                    "risk_consistent": None,
                    "validation_passed": None,
                    "generation_time": 0
                })

        all_results[experiment] = results

    # ========================================================
    # SUMMARY
    # ========================================================

    summary = {}

    for experiment in experiments:

        results = all_results[
            experiment
        ]

        total = len(results)

        # ----------------------------------------------------
        # JSON validity
        # ----------------------------------------------------

        json_validity = (
            sum(
                r["json_valid"]
                for r in results
            )
            /
            total
            *
            100
        )

        # ----------------------------------------------------
        # MITRE exact accuracy
        # ----------------------------------------------------

        mitre_accuracy = (
            sum(
                r["mitre_exact_match"]
                for r in results
            )
            /
            total
            *
            100
        )

        # ----------------------------------------------------
        # Average MITRE F1
        # ----------------------------------------------------

        average_f1 = (
            sum(
                r["mitre_f1"]
                for r in results
            )
            /
            total
        )

        # ----------------------------------------------------
        # Risk consistency
        # ----------------------------------------------------

        risk_results = [
            r["risk_consistent"]
            for r in results
            if r["risk_consistent"]
            is not None
        ]

        if risk_results:

            risk_consistency = (
                sum(risk_results)
                /
                len(risk_results)
                *
                100
            )

        else:

            risk_consistency = None

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        validation_results = [
            r["validation_passed"]
            for r in results
            if r["validation_passed"]
            is not None
        ]

        if validation_results:

            validation_rate = (
                sum(validation_results)
                /
                len(validation_results)
                *
                100
            )

        else:

            validation_rate = None

        # ----------------------------------------------------
        # Average generation time
        # ----------------------------------------------------

        average_time = (
            sum(
                r["generation_time"]
                for r in results
            )
            /
            total
        )

        # ----------------------------------------------------
        # Save summary
        # ----------------------------------------------------

        summary[experiment] = {

            "json_validity":
                round(
                    json_validity,
                    2
                ),

            "mitre_exact_accuracy":
                round(
                    mitre_accuracy,
                    2
                ),

            "average_mitre_f1":
                round(
                    average_f1,
                    2
                ),

            "risk_consistency":
                (
                    round(
                        risk_consistency,
                        2
                    )
                    if risk_consistency
                    is not None
                    else "N/A"
                ),

            "validation_rate":
                (
                    round(
                        validation_rate,
                        2
                    )
                    if validation_rate
                    is not None
                    else "N/A"
                ),

            "average_generation_time":
                round(
                    average_time,
                    2
                )
        }

    # ========================================================
    # PRINT FINAL TABLE
    # ========================================================

    print("\n")

    print("=" * 110)

    print(
        "                         EXPERIMENT COMPARISON"
    )

    print("=" * 110)

    print(
        f"{'Experiment':<25}"
        f"{'JSON':<12}"
        f"{'MITRE':<12}"
        f"{'F1':<12}"
        f"{'Risk':<12}"
        f"{'Validation':<15}"
        f"{'Time':<10}"
    )

    print("-" * 110)

    for experiment in experiments:

        data = summary[
            experiment
        ]

        risk_value = (
            str(
                data["risk_consistency"]
            )
            if data["risk_consistency"]
            != "N/A"
            else "N/A"
        )

        validation_value = (
            str(
                data["validation_rate"]
            )
            if data["validation_rate"]
            != "N/A"
            else "N/A"
        )

        print(
            f"{experiment:<25}"
            f"{str(data['json_validity']) + '%':<12}"
            f"{str(data['mitre_exact_accuracy']) + '%':<12}"
            f"{str(data['average_mitre_f1']) + '%':<12}"
            f"{risk_value + '%' if risk_value != 'N/A' else 'N/A':<12}"
            f"{validation_value + '%' if validation_value != 'N/A' else 'N/A':<15}"
            f"{str(data['average_generation_time']) + 's':<10}"
        )

    print("=" * 110)

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    output = {

        "dataset_size":
            len(incidents),

        "experiments":
            summary,

        "individual_results":
            all_results
    }

    os.makedirs("output", exist_ok=True)
    with open(
        "output/experiment_results.json",
        "w"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    safe_model = model.replace(":", "_").replace("/", "_")
    with open(
        f"output/experiment_{safe_model}.json",
        "w"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print(
        "\nResults saved to:"
    )

    print(
        "output/experiment_results.json"
    )

    print(
        "\nExperiment completed."
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()