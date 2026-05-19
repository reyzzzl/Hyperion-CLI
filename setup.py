from setuptools import setup, find_packages

setup(
    name="hyperion-pqc",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        'liboqs-python>=0.8.0',
        'cryptography>=41.0.0',
        'pysocks>=1.7.0',
        'stem>=1.8.0',
        'argon2-cffi>=21.0.0'
    ],
    entry_points={
        'console_scripts': [
            'hyperion=hyperion.cli.commands:main'
        ]
    }
)