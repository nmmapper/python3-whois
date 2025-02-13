import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python3-whois", 
    version="1.9.1",
    author="nmmapper",
    author_email="inquiry@nmmapper.com",
    description="python implementation for the linux whois utility parsing the reults",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nmmapper/python3-nmap",
    project_urls={
        'Documentation': 'https://nmap.readthedocs.io/en/latest/',
        'How it is used': 'https://www.nmmapper.com/sys/networkmapper/nmap/online-port-scanning/',
        'Homepage': 'https://www.nmmapper.com/',
        'Source': 'https://github.com/nmmapper/python3-nmap',
        'Subdomain finder': 'https://www.nmmapper.com/sys/tools/subdomainfinder/',
        'theHarvester online': 'https://www.nmmapper.com/sys/theharvester/email-harvester-tool/online/',
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    setup_requires=['wheel'],
    #install_requires=['simplejson'],
)
