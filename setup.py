#!/usr/bin/env python3
import re
from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent
long_description = (ROOT / "README.md").read_text(encoding="utf-8")
version = re.search(
    r'^__version__\s*=\s*"([^"]+)"', (ROOT / "src" / "__init__.py").read_text(), re.M
).group(1)

setup(
    name="BrandSentra",
    version=version,
    author="BrandSentra Team",
    author_email="support@brandsentra.com",
    description="Digital Risk Protection & Brand Intelligence Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BrandSentra/BrandSentra",
    packages=find_packages(exclude=("tests", "tests.*")),
    py_modules=["main"],
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "aiohttp>=3.9.0",
    ],
    extras_require={
        "certstream": ["certstream>=1.0.9"],
        "whois": ["python-whois>=0.9.4"],
        "tls": ["cryptography>=42.0.0"],
        "dev": ["pytest", "pytest-cov", "flake8", "black", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "brandsentra=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
