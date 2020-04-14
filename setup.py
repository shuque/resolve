import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="resolve",
    version="0.22",
    author="Shumon Huque",
    author_email="shuque@gmail.com",
    description="Command line iterative DNS resolution program and library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shuque/resolve",
    packages=['reslib'],
    scripts=['resolve.py'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
