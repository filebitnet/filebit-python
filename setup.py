from setuptools import setup

requirements = """
cryptography
requests
requests-toolbelt
docopt
tqdm
crc32c
"""

setup(
   name='filebit',
   version='1.1',
   description='filebit python library and cli',
   author_email='admin@filebit.net',
   packages=['filebit'],
   install_requires=requirements.strip().splitlines(),
   entry_points={
        "console_scripts": [
            "filebit = filebit.__main__:main",
        ]
    }
)
