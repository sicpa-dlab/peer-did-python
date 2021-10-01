import pathlib

from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="peerdid",
    version="0.2.0",
    description="PeerDID for Python",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/sicpa-dlab/peer-did-python",
    author="SICPA",
    author_email="DLCHOpenSourceContrib@sicpa.com",
    license="Apache-2.0",
    python_requires=">=3.5",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=["base58~=2.1.0", "varint~=1.0.2"],
    extras_require={
        "tests": [
            "pytest==5.4.3",
        ]
    },
)
