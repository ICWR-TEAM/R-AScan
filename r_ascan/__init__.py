"""R-AScan package."""

__all__ = ["RAScan"]


def __getattr__(name):
    if name == "RAScan":
        from .app import RAScan

        return RAScan
    raise AttributeError(name)
