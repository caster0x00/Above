from setuptools import setup, find_packages

setup(
    name="above",
    version="2.8",
    url="https://github.com/caster0x00/above",
    author="Mahama Bazarov",
    author_email="mahamabazarov@mailbox.org",
    description="Invisible Network Protocol Sniffer",
    long_description=open('README.md', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['network security', 'network sniffer'],
    packages=find_packages(),
    install_requires=[
        'scapy',
        'colorama',
    ],
    py_modules=['above.above_oui_dict'],
    entry_points={
        "console_scripts": ["above = above.above:main"],
    },
    python_requires='>=3.11',
    include_package_data=True,
)
