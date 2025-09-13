import inspect
import os
import sys
from pathlib import Path

import polytracker

DOCS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = Path(DOCS_PATH).parents[0]

sys.path = [str(ROOT_PATH)] + sys.path

MODULES = []


def process_module(module):
    shortname = module.__name__.split(".")[-1]
    with open(os.path.join(DOCS_PATH, f"{module.__name__}.rst"), "w") as f:
        f.write(f"{module.__name__}\n")
        f.write(f"{'=' * len(module.__name__)}\n")
        f.write(
            f"""
.. automodule:: {module.__name__}
"""
        )
        classes = []
        for name, c in inspect.getmembers(module, inspect.isclass):
            if (
                hasattr(c, "__module__")
                and c.__module__ == module.__name__
                and not name.startswith("_")
            ):
                classes.append(c)
        if classes:
            f.write(
                f"""
{shortname} classes
{'-' * len(shortname)}--------
"""
            )
            for cls in sorted(classes, key=lambda c: c.__name__):
                f.write(
                    f"""
{cls.__name__}
{'*' * len(cls.__name__)}

.. autoclass:: {cls.__name__}
   :members:
   :undoc-members:
   :inherited-members:
   :show-inheritance:
"""
                )

        functions = []
        for name, func in inspect.getmembers(module, inspect.isfunction):
            if (
                hasattr(func, "__module__")
                and func.__module__ == module.__name__
                and not name.startswith("_")
            ):
                functions.append(func)
        if functions:
            f.write(
                f"""
{shortname} functions
{'-' * len(shortname)}----------
"""
            )
            for func in sorted(functions, key=lambda o: o.__name__):
                f.write(
                    f"""
{func.__name__}
{'*' * len(func.__name__)}

.. autofunction:: {func.__name__}
"""
                )


for name, obj in inspect.getmembers(polytracker, inspect.ismodule):
    if (
        obj.__name__.startswith("polytracker")
        and not obj.__name__ == "polytracker.polytracker"
        and obj not in MODULES
    ):
        MODULES.append(obj)

MODULES = [polytracker] + sorted(MODULES, key=lambda m: m.__name__)

for m in MODULES:
    process_module(m)

with open(os.path.join(DOCS_PATH, "package.rst"), "w") as f:
    f.write(
        """PolyTracker API
---------------

.. toctree::
   :maxdepth: 4

"""
    )
    f.write("\n".join(f"   {m.__name__}" for m in MODULES))
