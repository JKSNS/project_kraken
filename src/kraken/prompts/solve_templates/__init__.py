"""Parameterized solve script templates for KRAKEN."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent


def render_solve_template(template_name: str, **kwargs) -> str:
    """Render a parameterized solve template with given variables."""
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)))
    template = env.get_template(template_name)
    return template.render(**kwargs)


def list_templates() -> list[str]:
    """List available solve templates."""
    return [p.name for p in _TEMPLATES_DIR.glob("*.py.j2")]
