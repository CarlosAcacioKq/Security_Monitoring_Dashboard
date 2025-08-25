#!/usr/bin/env python3
"""
Setup script for Enterprise Security Monitoring Dashboard
Installs dependencies and initializes the system
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="security-monitoring-dashboard",
    version="2.0.0",
    author="Carlos Acacio", 
    author_email="carlos.acacio@example.com",
    description="Enterprise Security Monitoring Dashboard with Multi-Source Threat Intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CarlosAcacioKq/Security_Monitoring_Dashboard",
    project_urls={
        "Bug Tracker": "https://github.com/CarlosAcacioKq/Security_Monitoring_Dashboard/issues",
        "Documentation": "https://github.com/CarlosAcacioKq/Security_Monitoring_Dashboard#readme",
        "Source": "https://github.com/CarlosAcacioKq/Security_Monitoring_Dashboard",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring", 
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "flake8>=6.1.0",
        ],
        "production": [
            "gunicorn>=21.2.0",
            "redis>=5.0.0",
            "psycopg2-binary>=2.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-monitor=main:main",
            "security-dashboard=web_dashboard:main",
            "threat-intel=production_threat_intel:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.sql"],
    },
    keywords=[
        "security", "siem", "threat-intelligence", "cybersecurity", 
        "monitoring", "dashboard", "malware", "incident-response"
    ],
)