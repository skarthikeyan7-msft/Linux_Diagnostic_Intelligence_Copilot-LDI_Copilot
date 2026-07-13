"""
Pluggable AI provider clients behind one common streaming chat interface.

Supported providers: OpenAI, Anthropic (Claude), Azure OpenAI, and Ollama
(local, fully offline). Each stream_xxx() function is a generator that
yields plain-text chunks as they arrive from the provider, so the
FastAPI layer can relay them to the browser via Server-Sent Events for
a responsive "typing" UI instead of a long silent wait.

Azure OpenAI supports two authentication methods, modeled as
"auth_types" in the PROVIDERS registry below:
  - "api_key": the classic `api-key` header.
  - "entra_id": Microsoft Entra ID (formerly Azure AD) app-registration
    (service principal) auth via the OAuth2 client-credentials flow -
    the standard way enterprise Azure deployments authenticate
    service-to-service calls when API keys are locked down by policy.
    A fresh access token is requested per call (tokens are short-lived
    and the token endpoint is fast, so no caching is attempted - this
    keeps the code simple and avoids any stale-token edge cases).

Deliberately implemented with only the Python standard library
(urllib.request) - no extra HTTP client dependency needed for this.

Privacy note: API keys, client secrets, and Entra ID tokens are passed
in per-call as plain function arguments and are never written to disk
or logged anywhere in this module. The caller (backend/app.py) is
responsible for not persisting them beyond the single request that
needs them.
"""
import json
import urllib.parse
import urllib.request
import urllib.error


class ProviderError(Exception):
    """Raised for any provider-side failure (auth, network, bad model
    name, rate limit, etc.) with a human-readable message safe to show
    in the UI."""
    pass


def _post_stream(url, headers, body, extract_fn, timeout=180):
    """POST body (dict) to url and stream the line-delimited / SSE
    response. extract_fn(parsed_json_obj) -> str|None text delta to
    yield for each received line."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                if line.startswith("data:"):
                    line = line[len("data:"):].strip()
                if line == "[DONE]":
                    break
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = extract_fn(obj)
                if text:
                    yield text
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error", {}).get("message", detail)
        except (json.JSONDecodeError, AttributeError):
            pass
        raise ProviderError(f"HTTP {e.code}: {detail[:500]}") from e
    except urllib.error.URLError as e:
        raise ProviderError(f"connection error: {e.reason}") from e
    except TimeoutError as e:
        raise ProviderError(f"request timed out: {e}") from e


def get_entra_id_token(tenant_id, client_id, client_secret, scope="https://cognitiveservices.azure.com/.default"):
    """OAuth2 client-credentials flow against the Microsoft identity
    platform v2 token endpoint. Returns a bearer access token to use as
    Authorization: Bearer <token> when calling Azure OpenAI. Requires
    the app registration to have been granted an appropriate RBAC role
    (e.g. "Cognitive Services OpenAI User") on the target resource -
    this function only handles authentication, not authorization; a
    successful token with insufficient RBAC will still fail with a 403
    on the actual chat-completions call, surfaced as a ProviderError
    from _post_stream()."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            obj = json.loads(resp.read().decode("utf-8"))
            token = obj.get("access_token")
            if not token:
                raise ProviderError("Entra ID token response did not contain an access_token")
            return token
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error_description", detail)
        except (json.JSONDecodeError, AttributeError):
            pass
        raise ProviderError(f"Entra ID token request failed (HTTP {e.code}): {detail[:500]}") from e
    except urllib.error.URLError as e:
        raise ProviderError(f"Entra ID token request connection error: {e.reason}") from e
    except TimeoutError as e:
        raise ProviderError(f"Entra ID token request timed out: {e}") from e


def stream_openai(api_key, model, messages, base_url="https://api.openai.com/v1"):
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {"model": model, "messages": messages, "stream": True, "temperature": 0.2}

    def extract(obj):
        choices = obj.get("choices") or []
        if not choices:
            return None
        return choices[0].get("delta", {}).get("content")

    yield from _post_stream(url, headers, body, extract)


def stream_azure_openai(endpoint, deployment, messages, api_version="2024-06-01", api_key=None, entra_token=None):
    """Calls Azure OpenAI chat completions. Provide exactly one of
    api_key (classic `api-key` header) or entra_token (a bearer access
    token obtained via get_entra_id_token(), sent as a standard OAuth2
    Authorization: Bearer header) - both are equally valid
    authentication methods against the same endpoint."""
    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    if entra_token:
        headers = {"Authorization": f"Bearer {entra_token}", "Content-Type": "application/json"}
    elif api_key:
        headers = {"api-key": api_key, "Content-Type": "application/json"}
    else:
        raise ProviderError("Azure OpenAI call requires either an api_key or an entra_token")
    body = {"messages": messages, "stream": True, "temperature": 0.2}

    def extract(obj):
        choices = obj.get("choices") or []
        if not choices:
            return None
        return choices[0].get("delta", {}).get("content")

    yield from _post_stream(url, headers, body, extract)


def stream_anthropic(api_key, model, messages, max_tokens=4096):
    # Anthropic's Messages API takes the system prompt as a top-level
    # field, not as a "system"-role entry inside messages[].
    system_msgs = [m["content"] for m in messages if m["role"] == "system"]
    convo = [m for m in messages if m["role"] != "system"]
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    body = {"model": model, "max_tokens": max_tokens, "stream": True, "messages": convo}
    if system_msgs:
        body["system"] = "\n\n".join(system_msgs)

    def extract(obj):
        if obj.get("type") == "content_block_delta":
            return obj.get("delta", {}).get("text")
        return None

    yield from _post_stream(url, headers, body, extract)


def stream_ollama(model, messages, base_url="http://localhost:11434"):
    url = f"{base_url.rstrip('/')}/api/chat"
    headers = {"Content-Type": "application/json"}
    body = {"model": model, "messages": messages, "stream": True}

    def extract(obj):
        return (obj.get("message") or {}).get("content")

    yield from _post_stream(url, headers, body, extract, timeout=600)  # local models on modest hardware can be slow


# Provider registry - drives the frontend's provider/model picker. Keys
# are stable identifiers used in API requests. Every provider exposes at
# least one entry under "auth_types" (keyed by an auth_type identifier);
# the frontend only shows an authentication-type selector when a
# provider has more than one option (currently just Azure OpenAI).
PROVIDERS = {
    "openai": {
        "label": "OpenAI",
        "auth_types": {
            "api_key": {"label": "API Key", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "gpt-4o",
        "model_hint": "e.g. gpt-4o, gpt-4o-mini, o3",
        "local": False,
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "auth_types": {
            "api_key": {"label": "API Key", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "claude-sonnet-4-5-20250929",
        "model_hint": "e.g. claude-sonnet-4-5-20250929, claude-opus-4-5",
        "local": False,
    },
    "azure_openai": {
        "label": "Azure OpenAI",
        "auth_types": {
            "api_key": {
                "label": "API Key",
                "fields": ["api_key", "endpoint", "deployment"],
            },
            "entra_id": {
                "label": "Microsoft Entra ID (app registration / service principal)",
                "fields": ["tenant_id", "client_id", "client_secret", "endpoint", "deployment"],
            },
        },
        "default_auth_type": "api_key",
        "default_model": "",
        "model_hint": "your Azure OpenAI deployment name (not the base model name)",
        "local": False,
    },
    "ollama": {
        "label": "Ollama (local, fully offline)",
        "auth_types": {
            "none": {"label": "None (local)", "fields": ["model", "base_url"]},
        },
        "default_auth_type": "none",
        "default_model": "llama3.1",
        "model_hint": "any model you've pulled locally, e.g. llama3.1, qwen2.5, mistral",
        "default_base_url": "http://localhost:11434",
        "local": True,
    },
}


def stream_chat(provider, messages, **kwargs):
    """Common entrypoint - dispatches to the right provider client.
    Required kwargs vary by provider and auth_type; see
    PROVIDERS[provider]['auth_types'][auth_type]['fields']. Yields text
    chunks. Raises ProviderError on failure."""
    if provider == "openai":
        yield from stream_openai(
            kwargs["api_key"], kwargs["model"], messages,
            kwargs.get("base_url") or "https://api.openai.com/v1",
        )
    elif provider == "anthropic":
        yield from stream_anthropic(kwargs["api_key"], kwargs["model"], messages)
    elif provider == "azure_openai":
        auth_type = kwargs.get("auth_type") or "api_key"
        api_version = kwargs.get("api_version") or "2024-06-01"
        if auth_type == "entra_id":
            token = get_entra_id_token(kwargs["tenant_id"], kwargs["client_id"], kwargs["client_secret"])
            yield from stream_azure_openai(kwargs["endpoint"], kwargs["deployment"], messages, api_version, entra_token=token)
        else:
            yield from stream_azure_openai(kwargs["endpoint"], kwargs["deployment"], messages, api_version, api_key=kwargs.get("api_key"))
    elif provider == "ollama":
        yield from stream_ollama(kwargs["model"], messages, kwargs.get("base_url") or "http://localhost:11434")
    else:
        raise ProviderError(f"unknown provider: {provider!r}")
