import json
import sys
import argparse

from llm_provider import generate_llm_completion, extract_json_from_text, SUPPORTED_MODELS
from rag import retrieve_knowledge
from risk import calculate_risk
from validator import validate_playbook
from explain import generate_explanation
from approval import display_playbook, request_approval
from executor import execute_playbook


def generate_playbook(incident, risk_score, risk_level, knowledge_context, model="llama3.2"):

    prompt = f"""
You are a cybersecurity incident response assistant.

Analyze this security incident:

{json.dumps(incident, indent=2)}

Independent Risk Assessment:
Risk Score: {risk_score}/100
Risk Level: {risk_level}

Use the following MITRE ATT&CK knowledge:

{knowledge_context}

Generate a cybersecurity response playbook.

IMPORTANT:
- Do not change the risk score.
- Do not change the risk level.
- Use the retrieved MITRE knowledge.
- Recommend safe defensive response actions.

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
Do not include explanations outside the JSON.
"""

    result = generate_llm_completion(prompt, model=model)
    cleaned = extract_json_from_text(result)

    return json.loads(cleaned)


def main():
    parser = argparse.ArgumentParser(description="Run CyberResponse AI pipeline on an incident.")
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.2",
        help="LLM model to use (e.g. 'llama3.2', 'qwen2.5:1.5b', 'gpt-4o-mini'). Default: llama3.2"
    )
    args = parser.parse_args()
    model = args.model

    print("\n" + "=" * 60)
    print("       AI CYBERSECURITY RESPONSE SYSTEM")
    print(f"       Model: {model}")
    print("=" * 60)

    # ------------------------------------------------
    # 1. Load Incident
    # ------------------------------------------------

    with open("incidents/incident.json", "r") as file:
        incident = json.load(file)

    print("\n[1] Incident Loaded")
    print("Incident ID:", incident["incident_id"])
    print("Type:", incident["type"])

    # ------------------------------------------------
    # 2. Risk Assessment
    # ------------------------------------------------

    risk_score, risk_level = calculate_risk(incident)

    print("\n[2] Risk Assessment")
    print("Risk Score:", risk_score)
    print("Risk Level:", risk_level)

    # ------------------------------------------------
    # 3. RAG Retrieval
    # ------------------------------------------------

    query = f"""
    {incident['type']}
    {incident['description']}
    Target: {incident['target']}
    Failed attempts: {incident['failed_attempts']}
    """

    retrieved_knowledge = retrieve_knowledge(
        query,
        top_k=2
    )

    knowledge_context = "\n\n".join(
        retrieved_knowledge
    )

    print("\n[3] MITRE ATT&CK Knowledge Retrieved")

    for knowledge in retrieved_knowledge:

        first_line = knowledge.split("\n")[0]

        print("-", first_line)

    # ------------------------------------------------
    # 4. LLM Playbook Generation
    # ------------------------------------------------

    print(f"\n[4] Generating Response Playbook using [{model}]...")

    playbook = generate_playbook(
        incident,
        risk_score,
        risk_level,
        knowledge_context,
        model=model
    )

    # Save playbook
    with open("output/playbook.json", "w") as file:

        json.dump(
            playbook,
            file,
            indent=4
        )

    print("Playbook generated successfully.")

    # ------------------------------------------------
    # 5. Validation
    # ------------------------------------------------

    print("\n[5] Validating Playbook...")

    errors, warnings = validate_playbook(
        playbook,
        risk_score,
        risk_level
    )

    if len(errors) > 0:

        print("\nVALIDATION FAILED")

        for error in errors:
            print("ERROR:", error)

        return

    print("VALIDATION PASSED")

    if len(warnings) > 0:

        for warning in warnings:
            print("WARNING:", warning)

    # ------------------------------------------------
    # 6. Explainability
    # ------------------------------------------------

    print("\n[6] Generating Explanation...")

    explanations = generate_explanation(
        incident,
        playbook
    )

    with open("output/explanation.json", "w") as file:

        json.dump(
            explanations,
            file,
            indent=4
        )

    print("Explanation generated successfully.")

    # ------------------------------------------------
    # 7. Human Approval
    # ------------------------------------------------

    print("\n[7] Human Approval Required")

    display_playbook(playbook)

    approved = request_approval()

    if not approved:

        print("\nPLAYBOOK REJECTED")
        print("Execution cancelled.")

        return

    print("\nPLAYBOOK APPROVED")

    # ------------------------------------------------
    # 8. Simulated Execution
    # ------------------------------------------------

    print("\n[8] Starting Simulated SOAR Execution...")

    execution_log = execute_playbook(
        playbook
    )

    with open("output/execution_log.json", "w") as file:

        json.dump(
            execution_log,
            file,
            indent=4
        )

    print("\nExecution completed.")

    # ------------------------------------------------
    # 9. Final Result
    # ------------------------------------------------

    print("\n" + "=" * 60)
    print("             PIPELINE COMPLETED")
    print("=" * 60)

    print("\nGenerated files:")

    print("✓ output/playbook.json")
    print("✓ output/explanation.json")
    print("✓ output/execution_log.json")


if __name__ == "__main__":
    main()