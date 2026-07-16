"""
Pluggable AI provider clients behind one common streaming chat interface.

Supported providers: OpenAI, Anthropic (Claude), Azure OpenAI, Mistral AI,
DeepSeek, GitHub Models (a single gateway covering OpenAI/Meta/Microsoft/
Mistral AI/DeepSeek/others behind one GitHub token), and Ollama (local,
fully offline). Each stream_xxx() function is a generator that yields
plain-text chunks as they arrive from the provider, so the FastAPI layer
can relay them to the browser via Server-Sent Events for a responsive
"typing" UI instead of a long silent wait.

Mistral AI and DeepSeek both expose an OpenAI-SDK-compatible chat
completions endpoint, so they're dispatched straight to stream_openai()
with their own base_url rather than duplicating near-identical HTTP
logic in dedicated functions - see stream_chat()'s dispatcher below.

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


def _is_unsupported_temperature_error(message):
    """True if a provider's error message indicates the model rejected
    a non-default temperature value. OpenAI's "reasoning" model family
    (o1, o3, o3-mini, o4-mini, ...) and their Azure OpenAI deployment
    equivalents only accept the default temperature (1) and reject any
    other value with an HTTP 400 - e.g. "Unsupported value:
    'temperature' does not support 0.2 with this model. Only the
    default (1) value is supported." Since Azure deployment names are
    user-defined, there's no reliable way to detect a reasoning model
    by name alone - reacting to the actual API error is more robust
    than trying to maintain a hardcoded list of model-name patterns."""
    msg = (message or "").lower()
    return "temperature" in msg and ("does not support" in msg or "unsupported value" in msg)


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


_AADSTS_HINTS = {
    "AADSTS53003": (
        "Your Entra ID tenant has a Conditional Access policy blocking this sign-in - this is "
        "your organization's security policy actively refusing the token, not a bug in this app. "
        "It's usually a Conditional Access policy scoped to \"Workload identities\" (service "
        "principals) requiring something an app-only client-credentials flow can never satisfy "
        "(MFA, a compliant device, a trusted network location, etc.). Ask your Entra ID admin to "
        "check Azure Portal -> Microsoft Entra ID -> Sign-in logs -> Service principal sign-ins "
        "(filter by the Trace ID/Correlation ID above) - that log entry names the exact policy "
        "that blocked it, and from there the admin can exclude this app registration's service "
        "principal or add your network to a trusted location. In the meantime, API key auth (if "
        "your org allows it) or a different AI provider both sidestep this entirely."
    ),
    "AADSTS7000215": (
        "The client secret was rejected as invalid - double check it was copied in full (secret "
        "*values* are only shown once at creation time in Azure Portal; the secret *ID* looks "
        "similar but won't work here) and that it hasn't been revoked."
    ),
    "AADSTS7000222": (
        "This client secret has expired. Generate a new one under your app registration's "
        "Certificates & secrets page and update it here."
    ),
    "AADSTS700016": (
        "This Application (client) ID wasn't found in the specified tenant. Double-check both "
        "the client ID and the tenant (directory) ID - a client ID from a different tenant will "
        "fail with exactly this error."
    ),
    "AADSTS90002": (
        "This tenant ID wasn't found. Double-check the Directory (tenant) ID from your app "
        "registration's Overview page."
    ),
}


def _explain_aadsts_error(detail):
    """Appends a plain-English hint for well-known AADSTS error codes -
    Entra ID's own error_description text is accurate but assumes the
    reader already knows Entra ID's internals; most people hitting this
    from an AI-provider connectivity test don't. Returns detail
    unchanged if no known code is recognized."""
    for code, hint in _AADSTS_HINTS.items():
        if code in detail:
            return f"{detail}\n\n💡 {hint}"
    return detail


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
        detail = _explain_aadsts_error(detail[:500])
        raise ProviderError(f"Entra ID token request failed (HTTP {e.code}): {detail}") from e
    except urllib.error.URLError as e:
        raise ProviderError(f"Entra ID token request connection error: {e.reason}") from e
    except TimeoutError as e:
        raise ProviderError(f"Entra ID token request timed out: {e}") from e


def stream_openai(api_key, model, messages, base_url="https://api.openai.com/v1"):
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def extract(obj):
        choices = obj.get("choices") or []
        if not choices:
            return None
        return choices[0].get("delta", {}).get("content")

    body = {"model": model, "messages": messages, "stream": True, "temperature": 0.2}
    try:
        yield from _post_stream(url, headers, body, extract)
    except ProviderError as e:
        if not _is_unsupported_temperature_error(str(e)):
            raise
        # "Reasoning" models (o1/o3/o3-mini/o4-mini/...) reject any
        # temperature other than the default (1) - retry once without
        # it. Safe to retry cleanly here: the API rejects invalid
        # parameters with an HTTP error before streaming any content,
        # so nothing has been yielded yet on this first attempt.
        body.pop("temperature", None)
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

    def extract(obj):
        choices = obj.get("choices") or []
        if not choices:
            return None
        return choices[0].get("delta", {}).get("content")

    body = {"messages": messages, "stream": True, "temperature": 0.2}
    try:
        yield from _post_stream(url, headers, body, extract)
    except ProviderError as e:
        if not _is_unsupported_temperature_error(str(e)):
            raise
        # Same reasoning-model retry as stream_openai() above - Azure
        # deployment names are user-defined, so there's no reliable way
        # to detect a reasoning-model deployment by name up front.
        body.pop("temperature", None)
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


def stream_github_models(token, model, messages):
    """GitHub Models (https://docs.github.com/en/rest/models) - a single
    gateway covering models from OpenAI, Meta (Llama), Microsoft (Phi),
    Mistral AI, DeepSeek, and others, all behind one GitHub personal
    access token (needs the `models: read` scope) rather than a
    separate account/key per vendor. `model` must be in the catalog's
    `{publisher}/{model_name}` ID format (e.g. "openai/gpt-4.1",
    "meta/Llama-3.3-70B-Instruct") - see list_models_github() /
    the "Check available models" button for the live, authoritative
    list, since publisher-defined naming/casing can change.

    Uses the personal (non-organization-attributed) inference endpoint;
    response shape matches the same choices[].delta.content structure
    as OpenAI's own streaming format, so this reuses the same
    _post_stream() extractor pattern as stream_openai()."""
    url = "https://models.github.ai/inference/chat/completions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github+json",
    }

    def extract(obj):
        choices = obj.get("choices") or []
        if not choices:
            return None
        return choices[0].get("delta", {}).get("content")

    body = {"model": model, "messages": messages, "stream": True, "temperature": 0.2}
    yield from _post_stream(url, headers, body, extract)


def _get_json(url, headers=None, timeout=15):
    """GET url and parse the JSON response body. Raises ProviderError with
    a clean, human-readable message on any HTTP/network/timeout/parse
    failure. Used by the list_models_*() live-availability checks below,
    which are inherently best-effort - the caller (backend/app.py's
    /api/models endpoint) catches this and falls back to the static
    known_models list rather than blocking the model picker."""
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error", {}).get("message", detail)
        except (json.JSONDecodeError, AttributeError):
            pass
        raise ProviderError(f"HTTP {e.code}: {detail[:300]}") from e
    except urllib.error.URLError as e:
        raise ProviderError(f"connection error: {e.reason}") from e
    except TimeoutError as e:
        raise ProviderError(f"request timed out: {e}") from e
    except json.JSONDecodeError as e:
        raise ProviderError(f"unexpected (non-JSON) response: {e}") from e


def list_models_openai(api_key, base_url="https://api.openai.com/v1"):
    """Live model list for the OpenAI account behind api_key - GET
    {base_url}/models. Used to grey out known_models entries the
    account doesn't actually have access to."""
    obj = _get_json(f"{base_url.rstrip('/')}/models", {"Authorization": f"Bearer {api_key}"})
    return sorted(m["id"] for m in obj.get("data", []) if m.get("id"))


def list_models_anthropic(api_key):
    """Live model list from Anthropic's Models API (same auth headers as
    the Messages API)."""
    obj = _get_json(
        "https://api.anthropic.com/v1/models",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    return sorted(m["id"] for m in obj.get("data", []) if m.get("id"))


def list_models_ollama(base_url="http://localhost:11434"):
    """Live model list = whatever's actually pulled locally (GET
    {base_url}/api/tags) - the most precise "availability" signal of any
    provider here, since an Ollama model is either present on disk or it
    isn't."""
    obj = _get_json(f"{base_url.rstrip('/')}/api/tags")
    return sorted(m["name"] for m in obj.get("models", []) if m.get("name"))


def list_models_mistral(api_key):
    """Live model list from Mistral AI's OpenAI-compatible Models API."""
    obj = _get_json("https://api.mistral.ai/v1/models", {"Authorization": f"Bearer {api_key}"})
    return sorted(m["id"] for m in obj.get("data", []) if m.get("id"))


def list_models_deepseek(api_key):
    """Live model list from DeepSeek's OpenAI-compatible Models API."""
    obj = _get_json("https://api.deepseek.com/v1/models", {"Authorization": f"Bearer {api_key}"})
    return sorted(m["id"] for m in obj.get("data", []) if m.get("id"))


def list_models_github(token):
    """Live catalog from GitHub Models (GET /catalog/models) - the
    authoritative, always-current list across every publisher (OpenAI,
    Meta, Microsoft, Mistral AI, DeepSeek, ...) behind this one gateway,
    since the static KNOWN_MODELS seed below can't track every catalog
    change/rename. Unlike the other list_models_* functions, the
    response is a bare JSON array, not {"data": [...]}."""
    obj = _get_json("https://models.github.ai/catalog/models", {
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
    })
    return sorted(m["id"] for m in obj if m.get("id"))


def list_models(provider, **kwargs):
    """Best-effort live availability check dispatcher. Raises
    ProviderError on failure (network/auth/timeout/unsupported
    provider) - callers must catch this and fall back to the static
    known_models list rather than blocking the model picker on a
    failed or not-yet-possible check (e.g. credentials not filled in
    yet)."""
    if provider == "openai":
        return list_models_openai(kwargs["api_key"], kwargs.get("base_url") or "https://api.openai.com/v1")
    elif provider == "anthropic":
        return list_models_anthropic(kwargs["api_key"])
    elif provider == "ollama":
        return list_models_ollama(kwargs.get("base_url") or "http://localhost:11434")
    elif provider == "mistral":
        return list_models_mistral(kwargs["api_key"])
    elif provider == "deepseek":
        return list_models_deepseek(kwargs["api_key"])
    elif provider == "github_models":
        return list_models_github(kwargs["api_key"])
    else:
        raise ProviderError(f"live model listing is not supported for provider {provider!r} (Azure OpenAI deployment names are user-defined and can't be enumerated this way)")


# Provider registry - drives the frontend's provider/model picker. Keys
# are stable identifiers used in API requests. Every provider exposes at
# least one entry under "auth_types" (keyed by an auth_type identifier);
# the frontend only shows an authentication-type selector when a
# provider has more than one option (currently just Azure OpenAI).
#
# KNOWN_MODELS is a curated static baseline shown in the frontend's model
# dropdown for providers with a "model" field (Azure OpenAI uses a
# user-defined "deployment" name instead, so it's excluded). The
# "Check available models" button calls list_models() above to fetch
# the live list for the account/instance behind the entered credentials
# and greys out (disables) any known_models entry not actually present -
# a live check failure (or not having entered credentials yet) simply
# leaves every option selectable, since this is meant to help, not
# block, model selection.
KNOWN_MODELS = {
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4-turbo", "gpt-3.5-turbo", "o3", "o3-mini", "o1"],
    "anthropic": [
        "claude-sonnet-4-5-20250929", "claude-opus-4-5", "claude-haiku-4-5",
        "claude-3-7-sonnet-20250219", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
    ],
    "ollama": ["llama3.1", "llama3.2", "qwen2.5", "mistral", "phi3", "gemma2"],
    "mistral": ["mistral-large-latest", "mistral-small-latest", "codestral-latest", "open-mistral-nemo", "ministral-8b-latest"],
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    # {publisher}/{model_name} catalog IDs - GitHub Models' own naming
    # convention (see stream_github_models()). A small, deliberately
    # non-exhaustive seed spanning the vendors this project's users most
    # often ask for (OpenAI, Meta, Microsoft, Mistral AI, DeepSeek) -
    # "Check available models" pulls the full, authoritative, always-
    # current catalog live rather than relying on this list to track
    # every rename/addition.
    "github_models": [
        "openai/gpt-4.1", "openai/gpt-4o-mini",
        "meta/Llama-3.3-70B-Instruct", "microsoft/Phi-4",
        "mistral-ai/Mistral-Large-2411", "deepseek/DeepSeek-R1",
    ],
}

PROVIDERS = {
    "ollama": {
        "label": "Ollama (local, fully offline) — recommended default",
        "auth_types": {
            "none": {"label": "None (local)", "fields": ["model", "base_url"]},
        },
        "default_auth_type": "none",
        "default_model": "llama3.1",
        "model_hint": "any model you've pulled locally, e.g. llama3.1, qwen2.5, mistral",
        "known_models": KNOWN_MODELS["ollama"],
        "default_base_url": "http://localhost:11434",
        "local": True,
    },
    "openai": {
        "label": "OpenAI",
        "auth_types": {
            "api_key": {"label": "API Key", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "gpt-4o",
        "model_hint": "e.g. gpt-4o, gpt-4o-mini, o3",
        "known_models": KNOWN_MODELS["openai"],
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
        "known_models": KNOWN_MODELS["anthropic"],
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
    "mistral": {
        "label": "Mistral AI",
        "auth_types": {
            "api_key": {"label": "API Key", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "mistral-large-latest",
        "model_hint": "e.g. mistral-large-latest, mistral-small-latest, codestral-latest",
        "known_models": KNOWN_MODELS["mistral"],
        "local": False,
    },
    "deepseek": {
        "label": "DeepSeek",
        "auth_types": {
            "api_key": {"label": "API Key", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "deepseek-chat",
        "model_hint": "deepseek-chat (general) or deepseek-reasoner (chain-of-thought)",
        "known_models": KNOWN_MODELS["deepseek"],
        "local": False,
    },
    "github_models": {
        "label": "GitHub Models (OpenAI, Meta, Microsoft, Mistral AI, DeepSeek, and more via one token)",
        "auth_types": {
            "api_key": {"label": "Personal Access Token", "fields": ["api_key", "model"]},
        },
        "default_auth_type": "api_key",
        "default_model": "openai/gpt-4o-mini",
        "model_hint": "{publisher}/{model} catalog ID, e.g. openai/gpt-4.1, meta/Llama-3.3-70B-Instruct - use \"Check available models\" for the live catalog",
        "known_models": KNOWN_MODELS["github_models"],
        "local": False,
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
    elif provider == "mistral":
        # Mistral AI's chat-completions API is OpenAI-SDK-compatible
        # (same request/response shape) - reuses stream_openai() with
        # Mistral's own base URL rather than duplicating the same HTTP
        # logic in a near-identical new function.
        yield from stream_openai(kwargs["api_key"], kwargs["model"], messages, base_url="https://api.mistral.ai/v1")
    elif provider == "deepseek":
        # Same OpenAI-compatibility story as Mistral above - DeepSeek's
        # own docs explicitly recommend pointing an OpenAI client at
        # this base URL.
        yield from stream_openai(kwargs["api_key"], kwargs["model"], messages, base_url="https://api.deepseek.com/v1")
    elif provider == "github_models":
        yield from stream_github_models(kwargs["api_key"], kwargs["model"], messages)
    else:
        raise ProviderError(f"unknown provider: {provider!r}")
