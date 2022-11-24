from setuptools import setup

requirements = """
cryptography
requests
requests-toolbelt
docopt
tqdm
"""

setup(
   name='filebit',
   version='1.0',
   description='filebit python library and cli',
   author_email='admin@filebit.net',
   packages=['filebit'],
   install_requires=requirements.strip().splitlines(),
   entry_points = {
        "console_scripts": [
            "filebit = filebit.__main__:main",
        ]
    }
)
