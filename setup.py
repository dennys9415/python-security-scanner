from setuptools import setup, find_packages

setup(
    name="python-security-scanner",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.0.0",
        "colorama>=0.4.4",
        "Jinja2>=3.0.0",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "security-scanner=security_scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
)