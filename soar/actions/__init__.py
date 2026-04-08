"""
CyberNest SOAR Action Registry.

Provides the BaseAction abstract class and a decorator-based registry that
automatically discovers and registers all concrete action implementations.

Usage:
    from soar.actions import ACTION_REGISTRY, BaseAction, register_action

    @register_action
    class MyAction(BaseAction):
        name = "my_action"
        description = "Does something useful"

        async def execute(self, params, context):
            return {"success": True, "output": {"result": "done"}, "error": None}
"""

from __future__ import annotations

import abc
from typing import Any, Optional


ACTION_REGISTRY: dict[str, type["BaseAction"]] = {}


class BaseAction(abc.ABC):
    """Abstract base for all SOAR playbook actions.

    Every action must define ``name`` and ``description`` class attributes
    and implement the async ``execute`` method.
    """

    name: str = ""
    description: str = ""

    @abc.abstractmethod
    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the action.

        Args:
            params: Action-specific parameters (already template-rendered).
            context: Execution context containing alert data, config, and
                     outputs from previous playbook steps.

        Returns:
            A dict with keys:
                success (bool): Whether the action completed without error.
                output  (dict): Structured result data for downstream steps.
                error   (str | None): Error message if success is False.
        """
        ...

    @classmethod
    def result(
        cls,
        success: bool,
        output: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> dict[str, Any]:
        """Helper to build a consistently shaped result dict."""
        return {
            "success": success,
            "output": output or {},
            "error": error,
        }


def register_action(cls: type[BaseAction]) -> type[BaseAction]:
    """Class decorator that registers an action in the global registry.

    The action is keyed by its ``name`` class attribute.  If ``name`` is
    empty the class name is lower-cased and used instead.

    Raises:
        ValueError: If an action with the same name is already registered.
    """
    action_name = cls.name or cls.__name__.lower()
    if action_name in ACTION_REGISTRY:
        raise ValueError(
            f"Duplicate action name '{action_name}': "
            f"{ACTION_REGISTRY[action_name].__name__} already registered"
        )
    ACTION_REGISTRY[action_name] = cls
    return cls
