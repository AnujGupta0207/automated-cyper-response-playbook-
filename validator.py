import json


def validate_playbook(playbook, expected_risk_score, expected_risk_level):

    errors = []
    warnings = []

    # 1. Required fields
    required_fields = [
        "incident_id",
        "incident_type",
        "risk_score",
        "risk_level",
        "mitre_techniques",
        "actions"
    ]

    for field in required_fields:
        if field not in playbook:
            errors.append(f"Missing field: {field}")

    # 2. Risk score validation
    if "risk_score" in playbook:

        if not isinstance(playbook["risk_score"], (int, float)):
            errors.append("Risk score must be a number")

        elif not 0 <= playbook["risk_score"] <= 100:
            errors.append("Risk score must be between 0 and 100")

        elif playbook["risk_score"] != expected_risk_score:
            errors.append(
                f"Risk score mismatch: "
                f"Expected {expected_risk_score}, "
                f"Got {playbook['risk_score']}"
            )

    # 3. Risk level validation
    valid_risk_levels = [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]

    if "risk_level" in playbook:

        if playbook["risk_level"] not in valid_risk_levels:
            errors.append("Invalid risk level")

        elif playbook["risk_level"] != expected_risk_level:
            errors.append(
                f"Risk level mismatch: "
                f"Expected {expected_risk_level}, "
                f"Got {playbook['risk_level']}"
            )

    # 4. MITRE technique validation
    if "mitre_techniques" in playbook:

        if not isinstance(playbook["mitre_techniques"], list):
            errors.append("MITRE techniques must be a list")

        elif len(playbook["mitre_techniques"]) == 0:
            errors.append("No MITRE techniques provided")

    # 5. Action validation
    if "actions" in playbook:

        if not isinstance(playbook["actions"], list):
            errors.append("Actions must be a list")

        elif len(playbook["actions"]) == 0:
            errors.append("No response actions provided")

        else:

            for action in playbook["actions"]:

                if "action" not in action:
                    errors.append("Action missing action field")

                if "reason" not in action:
                    errors.append("Action missing reason field")

    # 6. Dangerous action detection
    dangerous_keywords = [
        "delete",
        "destroy",
        "format",
        "shutdown",
        "wipe",
        "erase",
        "disable all",
        "remove all"
    ]

    if "actions" in playbook:

        for action in playbook["actions"]:

            action_text = action.get("action", "").lower()

            for keyword in dangerous_keywords:

                if keyword in action_text:

                    warnings.append(
                        f"Potentially dangerous action detected: {action.get('action')}"
                    )

    return errors, warnings


if __name__ == "__main__":

    try:

        with open("output/playbook.json", "r") as file:
            playbook = json.load(file)

        # These values come from our independent risk engine
        with open("incidents/incident.json", "r") as file:
            incident = json.load(file)

        # Import the same risk engine used by app.py
        from risk import calculate_risk

        expected_score, expected_level = calculate_risk(incident)

        errors, warnings = validate_playbook(
            playbook,
            expected_score,
            expected_level
        )

        print("\nPlaybook Validation")
        print("-------------------")

        if len(errors) == 0:
            print("VALIDATION PASSED")
        else:
            print("VALIDATION FAILED")

            for error in errors:
                print("ERROR:", error)

        if len(warnings) > 0:

            print("\nWarnings:")

            for warning in warnings:
                print("WARNING:", warning)

        else:
            print("No dangerous actions detected.")

    except json.JSONDecodeError:

        print("VALIDATION FAILED")
        print("Playbook is not valid JSON.")