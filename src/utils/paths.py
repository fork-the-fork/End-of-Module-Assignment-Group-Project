"""
The utils.paths module contains utilities to support file pathing.
"""
from pathlib import Path

def get_project_root() -> Path:
    """
    Get project root returns the root of the project as a pathlib.Path instance.
    It is useful for relative directories such as those specified in default.ini

    Returns:
        Project root as a path.
    """
    return Path(__file__).parent.parent.parent

def expand_path(path_str: str) -> Path:
    """
    Expands relative paths with respect to the project root.
    
    Args: path_str: path_str to be resolved.

    Returns:
        Expand path str.
    """
    if path_str[0] == ".":
        return get_project_root() / Path(path_str)
    else:
        return Path(path_str)