from jinja2 import Environment, FileSystemLoader

environment = Environment(loader=FileSystemLoader("templates/"))

def render(path: str, **data):
    template = environment.get_template(path)
    return template.render(**data)