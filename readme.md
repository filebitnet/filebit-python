# Work in Progress
the python library and it's documentation are still work in progress

## Installation
```
pip install -U .
```

## Upload
```python
from filebit import upload
u = upload.Upload(path)
u.start()
print(u.get_link())
```

## CLI Usage
```bash
CLI for filebit. Can upload and download files.
Usage:
    filebit upload <FILE> [-p parallel]
    filebit download <url> [-o OUTPUT] [-l licence_key] [-p parallel] [--overwrite]

Options:
    FILE: path to a file
    -o OUTPUT: path or directory to a place where to store the file
    -l licence_key: valid licence key for premium downloads
    --overwrite: overwrite if file exists
    -p parallel: upload or download multiple chunks at the same time
```