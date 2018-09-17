from setuptools import setup, find_packages
try:
    from pip._internal.download import PipSession
except ImportError:
    from pip.download import PipSession
try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

def reqs(path):
    return [str(r.req) for r in parse_requirements(path, session=PipSession())]

INSTALL_REQUIRES = reqs("requirements.txt")

setup(
    name='MobilePASSER',
    version='1.0',
    description='A reimplementation of the MobilePASS client in Python.',
    packages=find_packages(),
    install_requires=INSTALL_REQUIRES,
    entry_points={
        'console_scripts': ['mobilepasser = mobilepasser.mobilepasser:main',]
    },
)
