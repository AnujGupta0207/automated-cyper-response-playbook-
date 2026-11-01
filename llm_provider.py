"""
LLM Provider and Model Registry for CyberResponse AI.
Supports local models via Ollama and cloud models via OpenAI/compatible APIs.
"""

import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple, Any

import dotenv

dotenv.load_dotenv()

# Registry of supported models
SUPPORTED_MODELS: Dict[str, Dict[str, Any]] = {
    "llama3.2": {
        "id": "llama3.2",
        "name": "Llama 3.2 (3B)",
        "provider": "ollama",
        "params": "3B",
        "type": "Local (Ollama)",
        "context_window": "128k",
        "description": "Default compact model from Meta. Balanced speed and reasoning.",
        "default": True
    },
    "qwen2.5:1.5b": {
        "id": "qwen2.5:1.5b",
        "name": "Qwen 2.5 (1.5B)",
        "provider": "ollama",
        "params": "1.5B",
        "type": "Local (Ollama)",
        "context_window": "32k",
        "description": "Alibaba's ultra-lightweight reasoning model. Fast structured JSON generation.",
        "default": False
    },
    "phi3:mini": {
        "id": "phi3:mini",
        "name": "Phi-3 Mini (3.8B)",
        "provider": "ollama",
        "params": "3.8B",
        "type": "Local (Ollama)",
        "context_window": "128k",
        "description": "Microsoft compact model optimized for high-reasoning tasks.",
        "default": False
    },
    "mistral": {
        "id": "mistral",
        "name": "Mistral (7B)",
        "provider": "ollama",
        "params": "7B",
        "type": "Local (Ollama)",
        "context_window": "32k",
        "description": "Mistral AI 7B baseline. Strong zero-shot cybersecurity comprehension.",
        "default": False
    },
    "gemma2:2b": {
        "id": "gemma2:2b",
        "name": "Gemma 2 (2B)",
        "provider": "ollama",
        "params": "2B",
        "type": "Local (Ollama)",
        "context_window": "8k",
        "description": "Google's lightweight open model architecture.",
        "default": False
    },
    "gpt-4o-mini": {
        "id": "gpt-4o-mini",
        "name": "GPT-4o Mini",
        "provider": "openai",
        "params": "Cloud",
        "type": "Cloud API (OpenAI)",
        "context_window": "128k",
        "description": "Fast and intelligent flagship-mini model from OpenAI.",
        "default": False
    },
    "gpt-4o": {
        "id": "gpt-4o",
        "name": "GPT-4o",
        "provider": "openai",
        "params": "Cloud",
        "type": "Cloud API (OpenAI)",
        "context_window": "128k",
        "description": "State-of-the-art multimodal reasoning model from OpenAI.",
        "default": False
    }
}

DEFAULT_MODEL_ID = "llama3.2"


def get_installed_ollama_models() -> List[str]:
    """Return a list of model names currently pulled and available in Ollama."""
    try:
        import ollama
        resp = ollama.list()
        installed = []
        # Support both object and dict response structures across ollama versions
        models_data = getattr(resp, "models", None) or resp.get("models", [])
        for m in models_data:
            model_name = getattr(m, "model", None) or getattr(m, "name", None)
            if model_name is None and isinstance(m, dict):
                model_name = m.get("model") or m.get("name")
            if model_name:
                # Remove ":latest" suffix for cleaner matching if desired, but keep raw
                installed.append(str(model_name))
                if ":" in str(model_name):
                    base_name = str(model_name).split(":")[0]
                    if str(model_name).endswith(":latest"):
                        installed.append(base_name)
        return list(set(installed))
    except Exception as e:
        print(f"[LLM Provider] Warning: Failed to query Ollama models: {e}")
        return []


def is_model_ready(model_id: str) -> Tuple[bool, str]:
    """
    Check if a model is ready for inference.
    Returns (is_ready, status_message).
    """
    model_info = SUPPORTED_MODELS.get(model_id)
    if not model_info:
        # Check if it's an ad-hoc Ollama model installed locally
        installed = get_installed_ollama_models()
        if model_id in installed or f"{model_id}:latest" in installed:
            return True, "Installed in Ollama"
        return False, "Unknown model"

    provider = model_info.get("provider", "ollama")

    if provider == "ollama":
        installed = get_installed_ollama_models()
        if model_id in installed or f"{model_id}:latest" in installed or any(m.startswith(model_id) for m in installed):
            return True, "Ready (Installed locally)"
        return False, "Not downloaded (Run 'ollama pull <model>')"

    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return False, "Missing OPENAI_API_KEY in .env"
        return True, "Configured (Cloud API)"

    return False, "Unsupported provider"


def list_models_with_status() -> List[Dict[str, Any]]:
    """Return list of supported models with their current availability status."""
    result = []
    installed_ollama = get_installed_ollama_models()

    for model_id, info in SUPPORTED_MODELS.items():
        entry = dict(info)
        if entry["provider"] == "ollama":
            is_installed = (
                model_id in installed_ollama
                or f"{model_id}:latest" in installed_ollama
                or any(m.startswith(model_id) for m in installed_ollama)
            )
            entry["ready"] = is_installed
            entry["status"] = "Installed" if is_installed else "Not Installed"
        elif entry["provider"] == "openai":
            has_key = bool(os.getenv("OPENAI_API_KEY", "").strip())
            entry["ready"] = has_key
            entry["status"] = "Ready" if has_key else "Missing API Key"
        result.append(entry)

    # Also include any local Ollama models not in the predefined dictionary
    for m in installed_ollama:
        clean_id = m.replace(":latest", "")
        if clean_id not in SUPPORTED_MODELS and m not in SUPPORTED_MODELS:
            result.append({
                "id": m,
                "name": f"Ollama {m}",
                "provider": "ollama",
                "params": "Local",
                "type": "Local (Ollama)",
                "context_window": "Unknown",
                "description": "Discovered local model in Ollama",
                "default": False,
                "ready": True,
                "status": "Installed"
            })

    return result


def extract_json_from_text(text: str) -> str:
    """
    Robustly extract JSON content from raw LLM output,
    stripping markdown fences or surrounding explanations.
    """
    text = text.strip()
    if not text:
        return ""

    # 1. Match code blocks ```json ... ``` or ``` ... ```
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if code_block_match:
        candidate = code_block_match.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass

    # 2. Match outermost curly braces { ... }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace:last_brace + 1].strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            return candidate

    return text


def generate_llm_completion(
    prompt: str,
    model: str = DEFAULT_MODEL_ID,
    temperature: float = 0.1,
    timeout: int = 120
) -> str:
    """
    Unified completion generation across providers (Ollama, OpenAI).
    Returns the raw string output.
    """
    model_info = SUPPORTED_MODELS.get(model, {})
    provider = model_info.get("provider", "ollama")

    if provider == "ollama":
        import ollama
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": temperature}
        )
        if isinstance(response, dict):
            return response["message"]["content"]
        return getattr(response.message, "content", str(response))

    elif provider == "openai":
        from openai import OpenAI
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ValueError(f"OPENAI_API_KEY not configured for model '{model}'.")
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            timeout=timeout
        )
        return response.choices[0].message.content or ""

    else:
        raise ValueError(f"Unsupported provider '{provider}' for model '{model}'.")
