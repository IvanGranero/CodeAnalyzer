"""Boundary parsing for structured responses returned by language models."""

import json
import re


def _strip_trailing_commas(text: str) -> str:
    """Remove commas directly preceding '}' or ']' (a common LLM emission quirk)."""
    return re.sub(r",\s*([}\]])", r"\1", text)


def extract_json_object(response_text: str) -> dict:
    """Extract one JSON object from a raw or Markdown-wrapped model response."""
    if not isinstance(response_text, str) or not response_text.strip():
        raise ValueError("empty_response: model returned no structured content")

    def _decode(candidate: str) -> dict:
        candidate = candidate.strip()
        if not candidate:
            raise ValueError("empty response")
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            decoded = json.loads(_strip_trailing_commas(candidate))
        if not isinstance(decoded, dict):
            raise ValueError("LLM response must be a JSON object")
        return decoded

    try:
        return _decode(response_text)
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
        return _decode(cleaned)
    except (ValueError, json.JSONDecodeError):
        pass

    # Scan for every balanced {...} block and return the LAST one that decodes
    # to a JSON object. This avoids grabbing narrative "{" text that appears
    # before the real JSON payload, and skips reasoning/trailing prose blocks.
    brace_count = 0
    in_string = False
    escape_next = False
    start_index = None
    candidates = []
    for index in range(len(cleaned)):
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
            if brace_count == 0:
                start_index = index
            brace_count += 1
        elif character == "}":
            brace_count -= 1
            if brace_count == 0 and start_index is not None:
                candidates.append(cleaned[start_index:index + 1])
                start_index = None

    for candidate in reversed(candidates):
        try:
            return _decode(candidate)
        except (ValueError, json.JSONDecodeError):
            continue

    if not candidates:
        raise ValueError("No '{' found in response.")
    raise ValueError("Could not find a valid JSON object in response.")