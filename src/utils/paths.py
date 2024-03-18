from pathlib import Path

def get_project_root():
    return Path(__file__).parent.parent.parent

def expand_path(path_str):
    if path_str[0] == ".":
        return get_project_root() / Path(path_str)
    else:
        return Path(path_str)