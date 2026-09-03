"""Assessment package with deliberately explicit, decoupled submodule imports.

Keeping package initialization side-effect free ensures technical evaluation can load even when
external framework metadata is unavailable. Import public contracts from ``models``, ``profiles``,
``controls``, or ``frameworks`` according to the responsibility being used.
"""
