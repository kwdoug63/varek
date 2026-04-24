from setuptools import setup, find_packages

setup(
    name="varek-lang",
    version="0.1.0",
    author="Kenneth Wayne Douglas, MD",
    description="VAREK: AI Pipeline Programming Language",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={"console_scripts": ["syn=syn:main"]},
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Compilers",
    ],
)
