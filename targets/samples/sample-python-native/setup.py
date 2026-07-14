"""Build the reportnative CPython C extension for the sample-python target.

The reportkit CLI's `native` op imports this module, so the audit harness's
Python bootstrap (`pip install -e .`) builds it in-place next to the sources
where the runner's PYTHONPATH finds it. The AddressSanitizer surface is built
separately from the same C core by .audit/build.sh.
"""
from setuptools import Extension, setup

setup(
    name="reportnative",
    version="0.1.0",
    ext_modules=[
        Extension(
            "reportnative",
            sources=["reportnativemodule.c", "reportnative_core.c"],
        ),
    ],
)
