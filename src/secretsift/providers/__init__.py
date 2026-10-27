"""AI provider adapters (mock, OpenAI-compatible, Ollama, llama.cpp, OpenAI, Anthropic, Gemini)."""

from __future__ import annotations

from secretsift.providers.anthropic import AnthropicProvider
from secretsift.providers.base import (
    Message,
    Provider,
    ProviderRequest,
    ProviderResponse,
    ProviderStatus,
)
from secretsift.providers.gemini import GeminiProvider
from secretsift.providers.instrumented import InstrumentedProvider
from secretsift.providers.llama_cpp import LlamaCppProvider
from secretsift.providers.mock import MockProvider
from secretsift.providers.ollama import OllamaProvider
from secretsift.providers.openai import OpenAIProvider
from secretsift.providers.openai_compatible import OpenAICompatibleProvider
from secretsift.providers.registry import (
    available_provider_types,
    create_provider,
    provider_statuses,
)
from secretsift.providers.transport import Transport, UrllibTransport

__all__ = [
    "AnthropicProvider",
    "GeminiProvider",
    "InstrumentedProvider",
    "LlamaCppProvider",
    "Message",
    "MockProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "Provider",
    "ProviderRequest",
    "ProviderResponse",
    "ProviderStatus",
    "Transport",
    "UrllibTransport",
    "available_provider_types",
    "create_provider",
    "provider_statuses",
]
