from setuptools import setup

# TODO move remaining things
setup(
    install_requires=["base58~=2.1.0", "varint~=1.0.2"],
    extras_require={"tests": ["pytest==6.2.5", "pytest-xdist==2.3.0"]},
)
