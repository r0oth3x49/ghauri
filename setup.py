"""Setuptools script."""
import os
import ghauri
from setuptools import setup, find_packages  # , Extension

requirements = [
    "tldextract",
    "colorama",
    "requests",
    "chardet",
]


setup(
    name="ghauri",
    version=ghauri.__version__,
    description="An advanced SQL injection detection & exploitation tool.",
    classifiers=["Programming Language :: Python3"],
    author="Nasir Khan",
    author_email="r0oth3x49@gmail.com",
    packages=find_packages(),
    package_data={"": []},
    include_package_data=True,
    zip_safe=False,
    test_suite="ghauri",
    install_requires=requirements,
    entry_points={"console_scripts": ["ghauri=ghauri.scripts.ghauri:main"]},
    keywords=[
        "mysql",
        "mssql",
        "oracle",
        "postgre",
        "sql",
        "injection",
        "boolean-based",
        "time-based",
        "error-based",
    ],
    python_requires=">=3.7",
)
