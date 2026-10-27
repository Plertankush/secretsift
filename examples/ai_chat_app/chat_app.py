"""AI-chat example. Intentionally leaky code: only ever call it with synthetic data.

Every target takes a ``provider``; secretsift injects an instrumented provider (here the offline
mock provider, so no model and no network are involved).
"""

from __future__ import annotations

from typing import Any

from secretsift.providers.base import Message, ProviderRequest


def _ask(provider: Any, text: str) -> str:
    request = ProviderRequest(messages=[Message(role="user", content=text)])
    return str(provider.complete(request).text)


def _stream(provider: Any, text: str) -> str:
    request = ProviderRequest(messages=[Message(role="user", content=text)])
    return "".join(provider.stream(request))


def leaky_prompt(provider: Any, customer_email: str, question: str) -> str:
    """INTENTIONALLY LEAKY: pastes the customer's email into the prompt."""
    return _ask(provider, f"Customer {customer_email} asks: {question}")


def fixed_prompt(provider: Any, customer_email: str, question: str) -> str:
    """Fixed: the model never needs the email to answer, so it is not sent."""
    del customer_email
    return _ask(provider, f"A customer asks: {question}")


def leaky_echo(provider: Any, customer_email: str, question: str) -> str:
    """INTENTIONALLY LEAKY: the prompt carries the email and the (echoing) model repeats it."""
    return _ask(provider, f"{question} (account: {customer_email})")


def fixed_echo(provider: Any, customer_email: str, question: str) -> str:
    """Fixed: no email goes into the prompt, so the model has nothing to repeat."""
    del customer_email
    return _ask(provider, question)


def leaky_error(provider: Any, customer_email: str, question: str) -> str:
    """INTENTIONALLY LEAKY: this provider's error message quotes the prompt, email included."""
    return _ask(provider, f"{question} (account: {customer_email})")


def fixed_error(provider: Any, customer_email: str, question: str) -> str:
    """Fixed: send a pseudonym; a provider error can then only quote the pseudonym."""
    del customer_email
    try:
        return _ask(provider, f"{question} (account: customer-1)")
    except Exception:
        raise RuntimeError("assistant temporarily unavailable") from None


def leaky_stream(provider: Any, customer_email: str, question: str) -> str:
    """INTENTIONALLY LEAKY: the streamed reply echoes the email, split across 5-char chunks."""
    return _stream(provider, f"{question} (account: {customer_email})")


def fixed_stream(provider: Any, customer_email: str, question: str) -> str:
    """Fixed: no email in the prompt, so nothing to stream back."""
    del customer_email
    return _stream(provider, question)
