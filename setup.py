from setuptools import setup, find_packages
import os

# Function to read requirements from requirements.txt
def parse_requirements(filename="requirements.txt"):
    """Load requirements from a pip requirements file."""
    try:
        with open(os.path.join(os.path.dirname(__file__), filename), 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except IOError:
        # Handle case where requirements.txt might not exist during certain build/sdist phases
        # or if you want to define core requirements directly in setup.py
        # For this tool, it's better if requirements.txt exists.
        print("Warning: requirements.txt not found. Core dependencies might be missing.")
        return []

# Get the long description from the README file
try:
    with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "A cross-platform Python CLI reconnaissance tool for ethical hacking and security research."


setup(
    name="reconpy", # Name for PyPI - should be unique, changed from "recon_tool"
    version="0.1.0", # Should match config.VERSION ideally, or manage version centrally
    author="Ravindhar V", # Replace with your name/handle
    author_email="ravindhar.upm@gmail.com", # Replace with your email
    description="A cross-platform Python CLI reconnaissance tool.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RavindharCYS/recon_tool", # Replace with your project's URL
    
    # find_packages() will discover the 'recon_tool' package directory.
    # If you have other top-level packages, list them or use include/exclude.
    packages=find_packages(where=".", include=['recon_tool', 'recon_tool.*']),
    
    # Include non-code files specified in MANIFEST.in (if you create one)
    # or by using include_package_data=True and adding them to package_data
    include_package_data=True, 
    # Example: if you have data files inside your package
    # package_data={
    #     'recon_tool': ['workflows/*.json', 'data/*.txt'], 
    # },

    # Classifiers help users find your project
    # Full list: https://pypi.org/classifiers/
    classifiers=[
        "Development Status :: 3 - Alpha", # Or Beta, Production/Stable
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License", # Choose your license
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    
    python_requires='>=3.8', # Minimum Python version
    
    install_requires=parse_requirements(), # Load dependencies from requirements.txt
    
    # Define the command-line script
    entry_points={
        'console_scripts': [
            'reconpy=recon_tool.main:main_entry', # <-- Here
        ],
    },
    
    # Optional: links to project homepage, documentation, source code, etc.
    project_urls={
        'Bug Reports': 'https://github.com/RavindharCYS/recon_tool/issues',
        'Source': 'https://github.com/RavindharCYS/recon_tool/',
    },
)