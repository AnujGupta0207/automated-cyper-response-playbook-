import json
from datetime import datetime


def simulate_action(action):

    action_text = action["action"].lower()

    print("\n[SIMULATION] Executing:")
    print(action["action"])
    print("Reason:", action["reason"])

    if "lock" in action_text:
        print("[SIMULATION] Account would be temporarily restricted.")

    elif "monitor" in action_text:
        print("[SIMULATION] Monitoring would be enabled.")

    elif "investigate" in action_text:
        print("[SIMULATION] Security logs would be investigated.")

    elif "reset" in action_text:
        print("[SIMULATION] Credentials would be reset.")

    elif "multi-factor" in action_text:
        print("[SIMULATION] MFA enforcement would be enabled.")

    elif "password" in action_text:
        print("[SIMULATION] Password security policy would be applied.")

    else:
        print("[SIMULATION] Action recorded for analyst review.")


def execute_playbook(playbook):

    execution_log = []

    print("\n" + "=" * 50)
    print("       SIMULATED SOAR EXECUTION")
    print("=" * 50)

    for action in playbook["actions"]:

        simulate_action(action)

        execution_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action["action"],
            "status": "SIMULATED"
        })

    return execution_log


if __name__ == "__main__":

    with open("output/playbook.json", "r") as file:
        playbook = json.load(file)

    execution_log = execute_playbook(playbook)

    with open("output/execution_log.json", "w") as file:

        json.dump(
            execution_log,
            file,
            indent=4
        )

    print("\n" + "=" * 50)
    print("SIMULATION COMPLETED")
    print("=" * 50)

    print("\nExecution log saved to:")
    print("output/execution_log.json")