import json
import time
import argparse
import os

from llm_provider import generate_llm_completion, extract_json_from_text, SUPPORTED_MODELS
from rag import retrieve_knowledge
from risk import calculate_risk
from validator import validate_playbook


def generate_playbook(incident, risk_score, risk_level, knowledge_context, model="llama3.2"):

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
    "incident_id": "...",
    "incident_type": "...",
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
"""

    return generate_llm_completion(prompt, model=model)


def evaluate_incident(incident, model="llama3.2"):

    start_time = time.time()

    # --------------------------------------------------
    # 1. Calculate independent risk
    # --------------------------------------------------

    risk_score, risk_level = calculate_risk(incident)


    # --------------------------------------------------
    # 2. Retrieve cybersecurity knowledge using RAG
    # --------------------------------------------------

    query = f"""
    {incident['type']}
    {incident['description']}
    Target: {incident['target']}
    Failed attempts: {incident['failed_attempts']}
    """

    retrieved = retrieve_knowledge(
        query,
        top_k=2
    )

    knowledge_context = "\n\n".join(retrieved)


    # --------------------------------------------------
    # 3. Generate playbook using Ollama LLM
    # --------------------------------------------------

    raw_result = generate_playbook(
        incident,
        risk_score,
        risk_level,
        knowledge_context,
        model=model
    )

    generation_time = time.time() - start_time


    # --------------------------------------------------
    # 4. Check whether generated output is valid JSON
    # --------------------------------------------------

    cleaned_json = extract_json_from_text(raw_result)

    try:

        playbook = json.loads(cleaned_json)

        json_valid = True

    except (json.JSONDecodeError, TypeError):

        return {
            "incident_id": incident["incident_id"],
            "incident_type": incident["type"],
            "model": model,
            "json_valid": False,
            "validation_passed": False,
            "risk_consistent": False,
            "mitre_correct": False,
            "generation_time_seconds": round(
                generation_time,
                2
            )
        }


    # --------------------------------------------------
    # 5. Validate generated playbook
    # --------------------------------------------------

    errors, warnings = validate_playbook(
        playbook,
        risk_score,
        risk_level
    )

    validation_passed = len(errors) == 0


    # --------------------------------------------------
    # 6. Check risk consistency
    # --------------------------------------------------

    risk_consistent = (
        playbook.get("risk_score") == risk_score
        and
        playbook.get("risk_level") == risk_level
    )


    # --------------------------------------------------
    # 7. Check MITRE ATT&CK technique accuracy
    # --------------------------------------------------

    expected_techniques = set(
        incident.get(
            "expected_mitre_techniques",
            []
        )
    )

    generated_techniques = set(
        technique.get("technique_id")
        for technique in playbook.get(
            "mitre_techniques",
            []
        )
    )

    mitre_correct = (
        len(
            expected_techniques.intersection(
                generated_techniques
            )
        ) > 0
    )


    # --------------------------------------------------
    # 8. Return evaluation result
    # --------------------------------------------------

    return {

        "incident_id": incident["incident_id"],

        "incident_type": incident["type"],

        "json_valid": json_valid,

        "validation_passed": validation_passed,

        "risk_consistent": risk_consistent,

        "mitre_correct": mitre_correct,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "num_actions": len(
            playbook.get(
                "actions",
                []
            )
        ),

        "num_mitre_techniques": len(
            playbook.get(
                "mitre_techniques",
                []
            )
        ),

        "generation_time_seconds": round(
            generation_time,
            2
        ),

        "validation_errors": errors,

        "warnings": warnings
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate CyberResponse AI incident response on research dataset.")
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.2",
        help="Model to evaluate (e.g. 'llama3.2', 'qwen2.5:1.5b', 'gemma2:2b'). Default: llama3.2"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of incidents evaluated."
    )
    args = parser.parse_args()
    model = args.model

    print("\n" + "=" * 60)

    print(
        "       CYBERSECURITY SYSTEM EVALUATION"
    )
    print(f"       Model: {model}")

    print("=" * 60)


    # --------------------------------------------------
    # Load research dataset
    # --------------------------------------------------

    with open(
        "dataset/incidents.json",
        "r"
    ) as file:

        incidents = json.load(file)

    if args.limit and args.limit > 0:
        incidents = incidents[:args.limit]


    results = []


    print(
        f"\nTotal incidents: {len(incidents)}"
    )


    # --------------------------------------------------
    # Evaluate every incident
    # --------------------------------------------------

    for i, incident in enumerate(
        incidents,
        start=1
    ):

        print(
            f"\n[{i}/{len(incidents)}] "
            f"Processing "
            f"{incident['incident_id']} "
            f"- {incident['type']}"
        )


        try:

            result = evaluate_incident(
                incident,
                model=model
            )

            results.append(result)


            print(
                "JSON valid:",
                result["json_valid"]
            )

            print(
                "Validation:",
                result["validation_passed"]
            )

            print(
                "Risk consistent:",
                result["risk_consistent"]
            )

            print(
                "MITRE correct:",
                result["mitre_correct"]
            )

            print(
                "Generation time:",
                result["generation_time_seconds"],
                "seconds"
            )


        except Exception as e:

            print(
                "ERROR:",
                e
            )

            results.append({

                "incident_id":
                    incident["incident_id"],

                "incident_type":
                    incident["type"],

                "error":
                    str(e)
            })


    # --------------------------------------------------
    # Save individual results
    # --------------------------------------------------

    os.makedirs("output", exist_ok=True)
    with open(
        "output/evaluation_results.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    safe_model = model.replace(":", "_").replace("/", "_")
    with open(
        f"output/evaluation_{safe_model}.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )


    # --------------------------------------------------
    # Calculate overall metrics
    # --------------------------------------------------

    successful = [

        r

        for r in results

        if "error" not in r

    ]


    if successful:

        # JSON validity

        json_valid_count = sum(

            r["json_valid"]

            for r in successful

        )


        # Validation pass rate

        validation_count = sum(

            r["validation_passed"]

            for r in successful

        )


        # Risk consistency

        risk_consistent_count = sum(

            r["risk_consistent"]

            for r in successful

        )


        # MITRE technique accuracy

        mitre_correct_count = sum(

            r["mitre_correct"]

            for r in successful

        )


        # Average generation time

        average_time = (

            sum(
                r["generation_time_seconds"]
                for r in successful
            )
            /
            len(successful)
        )


        total = len(successful)


        # --------------------------------------------------
        # Display final results
        # --------------------------------------------------

        print(
            "\n" + "=" * 60
        )

        print(
            "              EVALUATION RESULTS"
        )

        print(
            "=" * 60
        )


        print(
            f"\nSuccessful incidents: "
            f"{total}/{len(incidents)}"
        )


        print(
            f"JSON validity: "
            f"{json_valid_count / total * 100:.2f}%"
        )


        print(
            f"Validation pass rate: "
            f"{validation_count / total * 100:.2f}%"
        )


        print(
            f"Risk consistency: "
            f"{risk_consistent_count / total * 100:.2f}%"
        )


        print(
            f"MITRE technique accuracy: "
            f"{mitre_correct_count / total * 100:.2f}%"
        )


        print(
            f"Average generation time: "
            f"{average_time:.2f} seconds"
        )


        print(
            "\nResults saved to:"
        )

        print(
            "output/evaluation_results.json"
        )


if __name__ == "__main__":

    main()