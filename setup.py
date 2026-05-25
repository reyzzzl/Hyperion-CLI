from setuptools import setup, find_packages

setup(
    name="hyperion-pqc",
    version="2.0.0",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
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
    },
    author="Hyperion Team",
    author_email="Hyperionteam@proton.me",
    description="Post-Quantum Secure Messenger with Kyber-512, Double Ratchet, and Tor",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/reyzzzl/Hyperion-CLI",
    license="GPL-3.0",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: Chat",
        "Operating System :: OS Independent",
    ],
    keywords="post-quantum cryptography, kyber, dilithium, tor, e2ee, p2p, messenger",
)