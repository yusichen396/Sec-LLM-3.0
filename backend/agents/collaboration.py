"""Agent collaboration via shared blackboard for multi-agent orchestration."""
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List


class Blackboard:
    """Thread-safe shared memory for agent collaboration.

    ReconAgent publishes discoveries; ExploitAgent reads and chains them;
    ReportAgent aggregates everything.
    """

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._history: List[Dict[str, Any]] = []
        self._owners: Dict[str, str] = {}
        self._lock = RLock()

    def publish(self, key: str, value: Any, source: str = "") -> None:
        """Publish a discovery to the blackboard."""
        with self._lock:
            if key in self._owners and self._owners[key] != source:
                raise ValueError(f"{key!r} belongs to {self._owners[key]!r}, not {source!r}")
            snapshot = deepcopy(value)
            self._owners[key] = source
            self._data[key] = snapshot
            self._history.append({
                "key": key,
                "value": deepcopy(snapshot),
                "source": source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return deepcopy(self._data.get(key, default))

    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._data)

    def get_by_source(self, source: str) -> Dict[str, Any]:
        with self._lock:
            return deepcopy({k: v for k, v in self._data.items()
                             if self._owners[k] == source})

    def list_keys(self) -> List[str]:
        with self._lock:
            return sorted(self._data.keys())

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return deepcopy(self._history)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._history.clear()
            self._owners.clear()
