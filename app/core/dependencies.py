"""
Dependencies cho FastAPI - Shared dependencies
"""
from fastapi import Request
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from app.core.config import settings

# Jinja2 environment cho templates
jinja_env = Environment(loader=FileSystemLoader(str(settings.TEMPLATES_DIR)))

def get_template_env() -> Environment:
    """Get Jinja2 template environment"""
    return jinja_env

def render_template(template_name: str, **kwargs) -> str:
    """Render Jinja2 template"""
    # Auto-detect template location
    # If template is in pages/, use it directly
    # Otherwise, try pages/ prefix first, then root
    template_paths = [
        f"pages/{template_name}",  # Try pages/ first
        template_name,  # Then try root
    ]
    
    for path in template_paths:
        try:
            template = jinja_env.get_template(path)
            return template.render(**kwargs)
        except:
            continue
    
    # If all paths fail, try original path (will raise exception)
    template = jinja_env.get_template(template_name)
    return template.render(**kwargs)

def get_yara_rules():
    """Get YARA rules instance"""
    from app.core.config import settings
    return settings.get_yara_rules()

def get_static_analyzer():
    """Get Static Analyzer instance"""
    from app.core.config import settings
    return settings.get_static_analyzer()

