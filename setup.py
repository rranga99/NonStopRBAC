from setuptools import setup, find_packages

setup(
    name="nsrbac",
    version='0.1',
    author="Rajesh Ranganathan",
    author_email="SkandTechFolks@gmail.com",
    description="nsrbac is a tool to mange Role Based Access Control on NonStop",
    license="MIT",
    packages=find_packages(),
    url="https://github.com/rranga99/nsrbac",
    install_requires=[
        'click',
        'filelock'
    ],
    entry_points={"console_scripts": ["rbac=nsrbac.nsrbac:nsrbac"]},
)
