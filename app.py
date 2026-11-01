import json
import os
from datetime import datetime

from flask import Flask, render_template, request, redirect

from main import generate_playbook
from rag import retrieve_knowledge
from risk import calculate_risk
from validator import validate_playbook
from explain import generate_explanation
from executor import execute_playbook
from llm_provider import list_models_with_status, SUPPORTED_MODELS, is_model_ready
from compare_models import compare_models, load_cached_comparison_results


app = Flask(__name__)


# ============================================================
# HISTORY FILE
# ============================================================

HISTORY_FILE = "output/incident_history.json"


def ensure_output_folder():

    os.makedirs(
        "output",
        exist_ok=True
    )


def load_history():

    ensure_output_folder()

    if not os.path.exists(HISTORY_FILE):

        return []

    try:

        with open(
            HISTORY_FILE,
            "r"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, FileNotFoundError):

        return []


def save_history(history):

    ensure_output_folder()

    with open(
        HISTORY_FILE,
        "w"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def add_history_record(
    incident,
    risk_score,
    risk_level,
    playbook,
    validation_passed,
    model_used="llama3.2"
):

    history = load_history()

    techniques = []

    for technique in playbook.get(
        "mitre_techniques",
        []
    ):

        techniques.append(
            technique.get(
                "technique_id",
                "Unknown"
            )
        )

    record = {

        "history_id":
            len(history) + 1,

        "incident_id":
            incident.get(
                "incident_id",
                "Unknown"
            ),

        "incident_type":
            incident.get(
                "type",
                "Unknown"
            ),

        "severity":
            incident.get(
                "severity",
                "Unknown"
            ),

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "model_used":
            model_used,

        "mitre_techniques":
            techniques,

        "action_count":
            len(
                playbook.get(
                    "actions",
                    []
                )
            ),

        "validation_status":
            "PASSED"
            if validation_passed
            else "FAILED",

        "human_decision":
            "PENDING",

        "execution_status":
            "NOT EXECUTED",

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    }

    history.append(record)

    save_history(history)

    return record


def update_history_status(
    incident_id,
    human_decision=None,
    execution_status=None
):

    history = load_history()

    # Find the latest record for this incident
    for record in reversed(history):

        if record["incident_id"] == incident_id:

            if human_decision is not None:

                record[
                    "human_decision"
                ] = human_decision

            if execution_status is not None:

                record[
                    "execution_status"
                ] = execution_status

            break

    save_history(history)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def index():

    with open(
        "dataset/incidents.json",
        "r"
    ) as file:

        incidents = json.load(file)

    models = list_models_with_status()

    return render_template(
        "index.html",
        incidents=incidents,
        models=models
    )


# ============================================================
# ANALYZE INCIDENT
# ============================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    ensure_output_folder()

    # --------------------------------------------------------
    # Get selected incident and model
    # --------------------------------------------------------

    selected_incident_id = request.form.get(
        "incident_id"
    )

    selected_model = request.form.get(
        "model",
        "llama3.2"
    )

    with open(
        "dataset/incidents.json",
        "r"
    ) as file:

        incidents = json.load(file)

    incident = None

    for item in incidents:

        if item["incident_id"] == selected_incident_id:

            incident = item

            break

    if incident is None:

        return "Incident not found", 404


    # --------------------------------------------------------
    # Risk assessment
    # --------------------------------------------------------

    risk_score, risk_level = calculate_risk(
        incident
    )


    # --------------------------------------------------------
    # RAG query
    # --------------------------------------------------------

    query = f"""
    {incident['type']}

    {incident['description']}

    Target:
    {incident.get('target', '')}

    Failed attempts:
    {incident.get('failed_attempts', 0)}
    """


    # --------------------------------------------------------
    # MITRE ATT&CK retrieval
    # --------------------------------------------------------

    retrieved_knowledge = retrieve_knowledge(
        query,
        top_k=2
    )

    knowledge_context = "\n\n".join(
        retrieved_knowledge
    )


    # --------------------------------------------------------
    # LLM playbook generation
    # --------------------------------------------------------

    playbook = generate_playbook(
        incident,
        risk_score,
        risk_level,
        knowledge_context,
        model=selected_model
    )


    # --------------------------------------------------------
    # Enforce independent risk result
    # --------------------------------------------------------

    playbook["risk_score"] = risk_score

    playbook["risk_level"] = risk_level


    # --------------------------------------------------------
    # Validate playbook
    # --------------------------------------------------------

    errors, warnings = validate_playbook(
        playbook,
        risk_score,
        risk_level
    )

    validation_passed = (
        len(errors) == 0
    )


    # --------------------------------------------------------
    # Generate explanation
    # --------------------------------------------------------

    explanation = generate_explanation(
        incident,
        playbook
    )


    # --------------------------------------------------------
    # Save latest playbook
    # --------------------------------------------------------

    with open(
        "output/playbook.json",
        "w"
    ) as file:

        json.dump(
            playbook,
            file,
            indent=4
        )


    # --------------------------------------------------------
    # Save explanation
    # --------------------------------------------------------

    with open(
        "output/explanation.json",
        "w"
    ) as file:

        json.dump(
            explanation,
            file,
            indent=4
        )


    # --------------------------------------------------------
    # Save current analysis
    # --------------------------------------------------------

    analysis = {

        "incident":
            incident,

        "model_used":
            selected_model,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "retrieved_knowledge":
            retrieved_knowledge,

        "playbook":
            playbook,

        "validation_passed":
            validation_passed,

        "validation_errors":
            errors,

        "validation_warnings":
            warnings,

        "explanation":
            explanation

    }


    with open(
        "output/current_analysis.json",
        "w"
    ) as file:

        json.dump(
            analysis,
            file,
            indent=4,
            default=str
        )


    # --------------------------------------------------------
    # Add incident to history
    # --------------------------------------------------------

    add_history_record(
        incident,
        risk_score,
        risk_level,
        playbook,
        validation_passed,
        model_used=selected_model
    )


    # --------------------------------------------------------
    # Display result page
    # --------------------------------------------------------

    return render_template(

        "result.html",

        incident=incident,

        model_used=selected_model,

        risk_score=risk_score,

        risk_level=risk_level,

        retrieved_knowledge=
            retrieved_knowledge,

        playbook=playbook,

        validation_passed=
            validation_passed,

        errors=errors,

        warnings=warnings,

        explanation=explanation

    )


# ============================================================
# APPROVE PLAYBOOK
# ============================================================

@app.route(
    "/approve",
    methods=["POST"]
)
def approve():

    ensure_output_folder()


    # --------------------------------------------------------
    # Load playbook
    # --------------------------------------------------------

    with open(
        "output/playbook.json",
        "r"
    ) as file:

        playbook = json.load(file)


    # --------------------------------------------------------
    # Execute simulated SOAR
    # --------------------------------------------------------

    execution_log = execute_playbook(
        playbook
    )


    # --------------------------------------------------------
    # Save execution log
    # --------------------------------------------------------

    with open(
        "output/execution_log.json",
        "w"
    ) as file:

        json.dump(
            execution_log,
            file,
            indent=4
        )


    # --------------------------------------------------------
    # Update history
    # --------------------------------------------------------

    update_history_status(

        playbook["incident_id"],

        human_decision="APPROVED",

        execution_status="EXECUTED"

    )


    # --------------------------------------------------------
    # Show execution page
    # --------------------------------------------------------

    return render_template(

        "execution.html",

        playbook=playbook,

        execution_log=execution_log,

        approved=True

    )


# ============================================================
# REJECT PLAYBOOK
# ============================================================

@app.route(
    "/reject",
    methods=["POST"]
)
def reject():

    # --------------------------------------------------------
    # Try to identify current incident
    # --------------------------------------------------------

    incident_id = None

    try:

        with open(
            "output/playbook.json",
            "r"
        ) as file:

            playbook = json.load(file)

            incident_id = playbook.get(
                "incident_id"
            )

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        pass


    # --------------------------------------------------------
    # Update history
    # --------------------------------------------------------

    if incident_id:

        update_history_status(

            incident_id,

            human_decision="REJECTED",

            execution_status="NOT EXECUTED"

        )


    # --------------------------------------------------------
    # Show rejection page
    # --------------------------------------------------------

    return render_template(

        "execution.html",

        playbook=None,

        execution_log=None,

        approved=False

    )


# ============================================================
# INCIDENT HISTORY
# ============================================================

@app.route("/history")
def history():

    history_records = load_history()

    # Show newest incidents first
    history_records.reverse()

    return render_template(

        "history.html",

        history=history_records

    )


# ============================================================
# MODEL BENCHMARK & COMPARISON
# ============================================================

@app.route("/compare")
def compare():
    models = list_models_with_status()
    comparison_data = load_cached_comparison_results()
    return render_template(
        "compare.html",
        models=models,
        comparison=comparison_data
    )


@app.route("/run_benchmark", methods=["POST"])
def run_benchmark():
    selected_models = request.form.getlist("models")
    limit_val = request.form.get("limit", "10")
    try:
        limit = int(limit_val) if limit_val else 10
    except ValueError:
        limit = 10

    if not selected_models:
        ready_models = [m["id"] for m in list_models_with_status() if m.get("ready")]
        selected_models = ready_models if ready_models else ["llama3.2"]

    compare_models(selected_models, limit=limit)
    return redirect("/compare")


# ============================================================
# RUN FLASK
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )