import asyncio


class HealthGauge:
    """
    This is a makeshift health check system.

    This health gauge is used to track the health of the application and provide a way to return a somewhat meaningful
    value to readiness probes.

    The health gauge is a simple counter that can be incremented and decremented. When an exception occurs that is
    outside of regular application flow-control (an actual error and not a warning), then the counter is
    incremented. As time goes on, the counter decrements. When a burst of exceptions occurs, the is_healthy method will
    return false, triggering a failed readiness check.
    """

    def __init__(self, value: int = 0, health_threshold: int = 100) -> None:
        self._value = value
        self._health_threshold = health_threshold
        self._lock = asyncio.Lock()

    async def womp(self, d=1) -> int:
        async with self._lock:
            self._value += int(d)
            return self._value

    async def tick(self) -> None:
        async with self._lock:
            if self._value > 0:
                self._value -= 1

    async def is_healthy(self) -> bool:
        async with self._lock:
            return self._value <= self._health_threshold
