from datetime import datetime, timedelta, timezone


_MAX_ATTEMPTS = 5
_WINDOW = timedelta(minutes=30)
_LOCK_DURATION = timedelta(minutes=15)


_attempt_state: dict[str, tuple[int, datetime, datetime | None]] = {}


def _state_key(scope: str, subject: str) -> str:
    return f"{scope}:{subject.strip().lower()}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def is_locked(scope: str, subject: str) -> bool:
    key = _state_key(scope, subject)
    state = _attempt_state.get(key)
    if state is None:
        return False

    failed_count, first_failed_at, locked_until = state
    now = _now()

    if locked_until is not None and now < locked_until:
        return True

    if now - first_failed_at > _WINDOW:
        _attempt_state.pop(key, None)

    return False


def register_failed_attempt(scope: str, subject: str) -> bool:
    key = _state_key(scope, subject)
    now = _now()

    state = _attempt_state.get(key)
    if state is None:
        _attempt_state[key] = (1, now, None)
        return False

    failed_count, first_failed_at, locked_until = state

    if locked_until is not None and now < locked_until:
        return True

    if now - first_failed_at > _WINDOW:
        _attempt_state[key] = (1, now, None)
        return False

    next_count = failed_count + 1
    if next_count >= _MAX_ATTEMPTS:
        _attempt_state[key] = (next_count, first_failed_at, now + _LOCK_DURATION)
        return True

    _attempt_state[key] = (next_count, first_failed_at, None)
    return False


def clear_attempts(scope: str, subject: str) -> None:
    _attempt_state.pop(_state_key(scope, subject), None)
