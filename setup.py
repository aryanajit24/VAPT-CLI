
from pathlib import Path
from setuptools import find_packages, setup

README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
REQUIREMENTS = [
    line.strip()
    for line in (Path(__file__).parent / "requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="vapt-cli",
    version="1.0.0",
    author="aryanajit24",
    author_email="",  
    description="Vulnerability Assessment & Penetration Testing CLI",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/aryanajit24/VAPT-CLI",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "vapt": [
            "reporting/templates/*.html",
            "reporting/templates/*.css",
        ]
    },
    install_requires=REQUIREMENTS,
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "vapt=vapt.main:entry_point",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="vapt security penetration-testing vulnerability-assessment cli",
)
