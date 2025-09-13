# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.

import subprocess

from polytracker import version as version_string


# -- Project information -----------------------------------------------------

project = "PolyTracker"
copyright = "2019–2021, Trail of Bits"
author = "Carson Harmon and Evan Sultanik"

# The full version, including alpha/beta/rc tags
release = version_string()
version = release
github_url = "https://github.com/trailofbits/polytracker"
# Has this version been released yet?
if (
    subprocess.call(
        ["git", "rev-list" f"v{version}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    == 0
):
    # There is a tag associated with this release
    github_url = f"{github_url}releases/tag/v{version}"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.autosectionlabel",
    "sphinx_rtd_theme",
    #'sphinxcontrib.fulltoc'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
# html_theme = 'classic'
html_theme = "sphinx_rtd_theme"

html_theme_options = {
    "canonical_url": "https://trailofbits.github.io/polytracker/latest/",
    "logo_only": False,
    "display_version": False,  # This manually configured in our custom templates
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
    #'vcs_pageview_mode': '',
    #'style_nav_header_background': 'white',
    # Toc options
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
}

html_context = {"github_url": github_url}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# html_js_files = [
#    'localtoc.js',
# ]


def skip(app, what, name, obj, would_skip, options):
    if name == "__init__":
        return False
    return would_skip


def docstring_callback(app, what, name, obj, options, lines: list):
    if what == "class" or what == "function":
        if lines and lines[0].strip():
            lines.insert(1, "")
            lines.insert(2, name)
            lines.insert(3, "*" * len(name))
            if len(lines) == 4:
                lines.append("")


def setup(app):
    app.connect("autodoc-skip-member", skip)
    # app.connect('autodoc-process-docstring', docstring_callback)


add_package_names = False
# prefix each section label with the name of the document it is in, followed by a colon
autosectionlabel_prefix_document = True
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = True
todo_include_todos = True

# autodoc_default_options = {
#    'inherited-members': True
# }
