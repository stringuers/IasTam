from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="defensys-scanner",
    version="1.0.0",
    author="DefenSys Team",
    author_email="contact@defensys.ai",
    description="AI-powered cybersecurity vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/defensys/scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.10.0",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
            "pre-commit>=3.5.0",
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "pandas>=2.0.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "defensys=defensys_cli_api:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
