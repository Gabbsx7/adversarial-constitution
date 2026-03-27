"""
Retry and circuit breaker utilities for resilient LLM and HTTP calls.

Ollama and remote LLMs fail silently under load. This module wraps calls
with exponential backoff, jitter, and a per-model circuit breaker so a
single flaky model doesn't stall the entire audit campaign.

Usage:
    from adversarial.utils.retry import with_retry, CircuitBreaker

    # Decorate any async callable:
    result = await with_retry(my_llm_call, model_name="ollama/llama3")

    # Or use the circuit breaker directly:
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
    result  = await breaker.call(my_llm_call)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import defaultdict
from collections.abc import Callable
from enum import StrEnum
from typing import Any, TypeVar

logger = logging.getLogger("adversarial.retry")

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MAX_ATTEMPTS    = 3
DEFAULT_BASE_DELAY      = 1.0   # seconds
DEFAULT_MAX_DELAY       = 30.0  # seconds
DEFAULT_JITTER_RANGE    = 0.5   # ± seconds added to each delay
DEFAULT_RETRYABLE_CODES = {429, 500, 502, 503, 504}

# Exceptions that should always trigger a retry regardless of error code
RETRYABLE_EXCEPTION_SUBSTRINGS = [
    "connection",
    "timeout",
    "rate limit",
    "overloaded",
    "temporarily unavailable",
    "service unavailable",
    "context length",
    "ollama",
]


# ---------------------------------------------------------------------------
# Core retry helper
# ---------------------------------------------------------------------------

async def with_retry(
    coro_factory: Callable[[], Any],
    *,
    model_name:    str = "unknown",
    max_attempts:  int = DEFAULT_MAX_ATTEMPTS,
    base_delay:    float = DEFAULT_BASE_DELAY,
    max_delay:     float = DEFAULT_MAX_DELAY,
    jitter:        float = DEFAULT_JITTER_RANGE,
    fallback:      str | None = None,
) -> Any:
    """
    Execute an async callable with exponential backoff and jitter.

    Args:
        coro_factory: A zero-argument callable that returns a coroutine.
                      Called fresh on each attempt (NOT the coroutine itself).
        model_name:   Used in log messages only.
        max_attempts: Total attempts before giving up.
        base_delay:   Initial wait between retries (doubles each attempt).
        max_delay:    Cap on wait time.
        jitter:       Random ± added to avoid thundering herd.
        fallback:     Value to return after exhausting retries (None = re-raise).

    Returns:
        The result of the coroutine, or `fallback` if all attempts fail.

    Example:
        result = await with_retry(
            lambda: agent.ainvoke(messages),
            model_name="ollama/llama3",
        )
    """
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            err_str  = str(exc).lower()

            is_retryable = any(s in err_str for s in RETRYABLE_EXCEPTION_SUBSTRINGS)
            if not is_retryable:
                logger.debug(f"[retry] Non-retryable error for {model_name}: {exc}")
                break

            if attempt == max_attempts:
                break

            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            delay += random.uniform(-jitter, jitter)
            delay  = max(0.1, delay)

            logger.warning(
                f"[retry] {model_name} — attempt {attempt}/{max_attempts} failed: "
                f"{type(exc).__name__}. Retrying in {delay:.1f}s..."
            )
            await asyncio.sleep(delay)

    if fallback is not None:
        logger.error(
            f"[retry] {model_name} — all {max_attempts} attempts failed. "
            f"Returning fallback. Last error: {last_exc}"
        )
        return fallback

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitState(StrEnum):
    CLOSED   = "closed"    # Normal operation
    OPEN     = "open"      # Failing — reject calls immediately
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreaker:
    """
    Per-model circuit breaker.

    Opens after `failure_threshold` consecutive failures, preventing
    the attack engine from wasting time on a dead model. Automatically
    transitions to HALF_OPEN after `recovery_timeout` seconds to test
    if the model has recovered.

    Usage:
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        try:
            result = await breaker.call(lambda: my_llm.ainvoke(messages))
        except CircuitOpenError:
            # Model is down — use fallback or skip
    """

    def __init__(
        self,
        failure_threshold:  int   = 3,
        recovery_timeout:   float = 60.0,
        success_threshold:  int   = 1,
    ) -> None:
        self.failure_threshold  = failure_threshold
        self.recovery_timeout   = recovery_timeout
        self.success_threshold  = success_threshold

        self._state:             CircuitState = CircuitState.CLOSED
        self._failure_count:     int   = 0
        self._success_count:     int   = 0
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call(self, coro_factory: Callable[[], Any]) -> Any:
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    logger.info("[circuit] Transitioning to HALF_OPEN — testing recovery")
                else:
                    raise CircuitOpenError(
                        f"Circuit is OPEN. Recovery in "
                        f"{self.recovery_timeout - (time.monotonic() - self._last_failure_time):.0f}s"
                    )

        try:
            result = await coro_factory()
            await self._on_success()
            return result
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state         = CircuitState.CLOSED
                    self._success_count = 0
                    logger.info("[circuit] Recovered — transitioning to CLOSED")

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failure_count    += 1
            self._last_failure_time = time.monotonic()
            self._success_count     = 0
            if self._failure_count >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    logger.error(
                        f"[circuit] Opening circuit after {self._failure_count} failures"
                    )
                self._state = CircuitState.OPEN


class CircuitOpenError(Exception):
    """Raised when a circuit breaker rejects a call."""


# ---------------------------------------------------------------------------
# Global registry — one breaker per model
# ---------------------------------------------------------------------------

_breakers: dict[str, CircuitBreaker] = defaultdict(CircuitBreaker)


def get_breaker(model_name: str) -> CircuitBreaker:
    """Return (or create) the circuit breaker for a given model."""
    return _breakers[model_name]


async def resilient_invoke(
    coro_factory: Callable[[], Any],
    model_name:   str,
    fallback:     str = "[MODEL_UNAVAILABLE]",
) -> Any:
    """
    Convenience wrapper: retry + circuit breaker in one call.

    Intended for use inside attack modules:
        response = await resilient_invoke(
            lambda: (agent | StrOutputParser()).ainvoke(messages),
            model_name="ollama/llama3",
        )
    """
    breaker = get_breaker(model_name)
    try:
        return await breaker.call(
            lambda: with_retry(coro_factory, model_name=model_name, fallback=fallback)
        )
    except CircuitOpenError as exc:
        logger.warning(f"[resilient] Circuit open for {model_name}: {exc}")
        return fallback