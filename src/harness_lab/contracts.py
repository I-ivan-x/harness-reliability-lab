"""Public runtime inputs; no task oracle, environment initializer, or fault plan."""

from dataclasses import asdict, dataclass, field
from math import isfinite
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True)
class TaskInput:
    task_id: str
    instruction: str
    target_ref: str
    as_of: str

    def __post_init__(self) -> None:
        if not all(isinstance(v, str) and v for v in asdict(self).values()):
            raise ValueError("Task fields must be nonempty strings")


@dataclass(frozen=True)
class Budget:
    model_calls: int = 6
    tool_attempts: int = 6
    decision_steps: int = 6
    output_tokens_per_call: int = 800
    input_tokens_per_call: int = 16000
    tool_result_bytes: int = 16000
    total_s: float = 120.0
    cleanup_s: float = 6.0
    tool_timeout_s: float = 0.18
    model_timeout_s: float = 30.0

    def __post_init__(self) -> None:
        if any(
            type(value) not in (int, float) or not isfinite(value) or value <= 0
            for value in asdict(self).values()
        ):
            raise ValueError("Budgets must be positive numbers")
        if any(
            type(getattr(self, name)) is not int
            for name in (
                "model_calls",
                "tool_attempts",
                "decision_steps",
                "output_tokens_per_call",
                "input_tokens_per_call",
                "tool_result_bytes",
            )
        ):
            raise ValueError("Count and size budgets must be integers")
        if self.total_s <= self.cleanup_s or self.cleanup_s < 5:
            raise ValueError("Reserve at least five seconds for SDK process cleanup")


@dataclass(frozen=True)
class RunConfig:
    run_id: str
    principal: str
    artifact_dir: Path
    policy: Literal["P0", "P1", "P2"] = "P1"
    can_read: bool = True
    can_write: bool = True
    budget: Budget = field(default_factory=Budget)
    backoff_s: float = 0.02
    jitter_s: float = 0.01
    seed: int = 0

    def __post_init__(self) -> None:
        if self.policy not in {"P0", "P1", "P2"}:
            raise ValueError("Unknown recovery policy")
        if not self.run_id or not self.principal or self.backoff_s < 0 or self.jitter_s < 0:
            raise ValueError("Invalid run configuration")

    @property
    def operation_id(self) -> str:
        return f"{self.run_id}:write-0"


@dataclass
class Ports:
    controller: Any
    tools: Any
