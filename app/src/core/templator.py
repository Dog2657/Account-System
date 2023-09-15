from jinja2 import Template

def render(path: str, **data):
    with open(path) as file:
        template = Template( file.read() )

    return template.render(**data)