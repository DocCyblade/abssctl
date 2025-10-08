"""Template rendering facilities for abssctl."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined


class TemplateError(RuntimeError):
    """Raised when template rendering fails."""


@dataclass(slots=True)
class TemplateEngine:
    """Renders templates from override and built-in search paths."""

    search_paths: tuple[Path, ...]
    _env: Environment = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialise the backing Jinja environment."""
        self._env = Environment(
            loader=FileSystemLoader([str(path) for path in self.search_paths]),
            autoescape=False,
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            trim_blocks=False,
            lstrip_blocks=False,
        )

    @classmethod
    def from_paths(cls, paths: Iterable[Path]) -> TemplateEngine:
        """Construct an engine from *paths*, normalising them to Path objects."""
        normalised = tuple(Path(path).expanduser() for path in paths)
        return cls(search_paths=normalised)

    @classmethod
    def with_overrides(cls, override: Path | None = None) -> TemplateEngine:
        """Create an engine using the default built-in templates plus *override*."""
        builtin_root = Path(__file__).parent / "builtin"
        paths: list[Path] = []
        if override is not None:
            paths.append(Path(override).expanduser())
        paths.append(builtin_root)
        return cls.from_paths(paths)

    def render_to_string(self, template_name: str, context: Mapping[str, object]) -> str:
        """Render *template_name* using *context* and return the result as a string."""
        try:
            template = self._env.get_template(template_name)
        except Exception as exc:  # pragma: no cover - Jinja provides detail
            raise TemplateError(f"Failed to load template '{template_name}': {exc}") from exc
        try:
            return template.render(**context)
        except Exception as exc:  # pragma: no cover - Jinja provides detail
            raise TemplateError(f"Failed to render template '{template_name}': {exc}") from exc

    def render_to_path(
        self,
        template_name: str,
        destination: Path | str,
        context: Mapping[str, object],
        *,
        mode: int = 0o640,
    ) -> bool:
        """Render *template_name* to *destination* and return True when content changed."""
        rendered = self.render_to_string(template_name, context)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        if destination_path.exists():
            current = destination_path.read_text(encoding="utf-8")
            if current == rendered:
                return False

        destination_path.write_text(rendered, encoding="utf-8")
        os.chmod(destination_path, mode)
        return True


__all__ = ["TemplateEngine", "TemplateError"]
