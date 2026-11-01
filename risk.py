def calculate_risk(incident):

    score = 0

    # Severity score
    severity_scores = {
        "Low": 10,
        "Medium": 25,
        "High": 40,
        "Critical": 50
    }

    score += severity_scores.get(
        incident.get("severity", "Low"),
        10
    )

    # Failed login attempts
    failed_attempts = incident.get("failed_attempts", 0)

    if failed_attempts >= 100:
        score += 30
    elif failed_attempts >= 50:
        score += 20
    elif failed_attempts >= 10:
        score += 10

    # Administrator account is more sensitive
    target = incident.get("target", "").lower()

    if "admin" in target:
        score += 20

    # Maximum score = 100
    score = min(score, 100)

    # Convert score to risk level
    if score >= 75:
        risk_level = "Critical"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return score, risk_level


if __name__ == "__main__":

    import json

    with open("incidents/incident.json", "r") as file:
        incident = json.load(file)

    score, risk_level = calculate_risk(incident)

    print("Risk Score:", score)
    print("Risk Level:", risk_level)