"""Boundary parsing for structured responses returned by language models."""

import json


def extract_json_object(response_text: str) -> dict:
    """Extract one JSON object from a raw or Markdown-wrapped model response."""
    if not response_text:
        raise ValueError("Empty response from LLM")

    try:
        decoded = json.loads(response_text)
        if not isinstance(decoded, dict):
            raise ValueError("LLM response must be a JSON object")
        return decoded
    except json.JSONDecodeError:
        pass

    cleaned = response_text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
        decoded = json.loads(cleaned)
        if not isinstance(decoded, dict):
            raise ValueError("LLM response must be a JSON object")
        return decoded
    except json.JSONDecodeError:
        pass

    start_index = cleaned.find("{")
    if start_index == -1:
        raise ValueError("No '{' found in response.")

    brace_count = 0
    in_string = False
    escape_next = False
    for index in range(start_index, len(cleaned)):
        character = cleaned[index]
        if escape_next:
            escape_next = False
            continue
        if character == "\\":
            escape_next = True
            continue
        if character == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if character == "{":
            brace_count += 1
        elif character == "}":
            brace_count -= 1
        if brace_count == 0:
            try:
                decoded = json.loads(cleaned[start_index:index + 1])
            except json.JSONDecodeError as exc:
                raise ValueError(f"Extracted JSON block is invalid: {exc}") from exc
            if not isinstance(decoded, dict):
                raise ValueError("LLM response must be a JSON object")
            return decoded

    raise ValueError("Could not find balanced JSON brackets in response.")