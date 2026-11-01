import json


def generate_explanation(incident, playbook):

    explanations = []

    risk_score = playbook["risk_score"]
    risk_level = playbook["risk_level"]

    # Explain overall risk
    explanations.append({
        "factor": "Risk Assessment",
        "explanation": (
            f"The incident received a risk score of {risk_score}/100 "
            f"and was classified as {risk_level} risk."
        )
    })

    # Explain incident characteristics
    if incident.get("failed_attempts", 0) >= 100:

        explanations.append({
            "factor": "High Number of Failed Attempts",
            "explanation": (
                f"{incident['failed_attempts']} failed login attempts "
                "indicate a strong brute force pattern."
            )
        })

    # Explain privileged target
    if "admin" in incident.get("target", "").lower():

        explanations.append({
            "factor": "Administrator Account",
            "explanation": (
                "The targeted account has administrative privileges, "
                "which increases the potential impact of compromise."
            )
        })

    # Explain MITRE techniques
    for technique in playbook.get("mitre_techniques", []):

        explanations.append({
            "factor": "MITRE ATT&CK Technique",
            "explanation": (
                f"The incident was associated with "
                f"{technique['technique_id']} - "
                f"{technique['technique_name']}."
            )
        })

    return explanations


if __name__ == "__main__":

    with open("incidents/incident.json", "r") as file:
        incident = json.load(file)

    with open("output/playbook.json", "r") as file:
        playbook = json.load(file)

    explanations = generate_explanation(
        incident,
        playbook
    )

    print("\nIncident Explanation")
    print("--------------------")

    for item in explanations:

        print("\n" + item["factor"])
        print(item["explanation"])

    with open("output/explanation.json", "w") as file:

        json.dump(
            explanations,
            file,
            indent=4
        )

    print("\nExplanation saved successfully.")