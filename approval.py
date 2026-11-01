import json


def display_playbook(playbook):

    print("\n" + "=" * 50)
    print("       CYBERSECURITY RESPONSE APPROVAL")
    print("=" * 50)

    print(f"\nIncident ID : {playbook['incident_id']}")
    print(f"Incident    : {playbook['incident_type']}")
    print(f"Risk Score  : {playbook['risk_score']}/100")
    print(f"Risk Level  : {playbook['risk_level']}")

    print("\nMITRE ATT&CK Techniques:")

    for technique in playbook["mitre_techniques"]:
        print(
            f"- {technique['technique_id']} "
            f"{technique['technique_name']}"
        )

    print("\nRecommended Actions:")

    for i, action in enumerate(playbook["actions"], 1):

        print(f"\n{i}. {action['action']}")
        print(f"   Reason: {action['reason']}")

    print("\n" + "=" * 50)


def request_approval():

    while True:

        choice = input(
            "\nDo you approve this playbook? (yes/no): "
        ).strip().lower()

        if choice in ["yes", "y"]:
            return True

        if choice in ["no", "n"]:
            return False

        print("Please enter yes or no.")


if __name__ == "__main__":

    with open("output/playbook.json", "r") as file:
        playbook = json.load(file)

    display_playbook(playbook)

    approved = request_approval()

    print()

    if approved:

        print("PLAYBOOK APPROVED")
        print("Ready for simulated execution.")

    else:

        print("PLAYBOOK REJECTED")
        print("No actions will be executed.")