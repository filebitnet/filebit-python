from setuptools import setup
from codecs import open

requirements = """
cryptography
requests
requests-toolbelt
docopt
tqdm
crc32c
"""


with open('readme.md', 'r', encoding='utf-8') as rm_file:
    readme = rm_file.read()

setup(
   name='filebit',
   version='1.2.2',
   description='filebit python library and cli',
   long_description=readme,
   long_description_content_type='text/markdown',
   packages=['filebit'],
   install_requires=requirements.strip().splitlines(),
   url='https://github.com/filebit/filebit-python',
   author='filebit.net',
   author_email='support@filebit.net',
   entry_points={
        "console_scripts": [
            "filebit = filebit.__main__:main",
        ]
    }
)
