# Installation
```
pip install filebit
```

## Check Filebit URL & Get Parts
```python
from filebit import api
filebit_url = "https://filebit.net/f/qknI9LX#Ac1A3HJ13aBRn66XHnkktQNlOK1dxItiRqnkAovV82uU";
is_valid = api.is_valid_url(filebit_url)
print(is_valid) # True
parts = api.get_parts(filebit_url)
print(parts) # ('qknI9LX', 'Ac1A3HJ13aBRn66XHnkktQNlOK1dxItiRqnkAovV82uU')
```

## Get Upload Server
```python
from filebit import api
# get a list of usable servers
servers = api.get_upload_servers()
print(servers)

# pick one randomly
random_server = api.get_upload_server()
print(random_server)
```

## Get File Informations
```python
from filebit import api
info = api.get_file_info("https://filebit.net/f/teBKKQ6#Abts8F6i70LmwgoeUrDe_8RWMmuXBtQj5C_BguRzJL-p")
filename = info['filename']
filesize = info['filesize']
print(f'{filename} Filesize: {filesize}')
#Example.zip Filesize: 104857600
```

## Multi File Information(s)
```python
from filebit import api, crypto
urls = [
    "https://filebit.net/f/tlBKQQ6#Abts8F6i70LmwgoeUrDe_1RWMmuXBtQj5C_BguRzJL",
    "https://filebit.net/f/AfAiPEM#AbotIF8zJdU44b6cF_9f9kXIir_U5AmODfRiWE9xDo2U"
] # replace example links with actual links...

infos = api.get_multi_info(urls);

for url in urls:
    parts = api.get_parts(url)
    id = parts[0]
    key = parts[1]
    info = infos[id]
    filename = "n/A"
    size = 0
    if info["state"] == "ONLINE":
        decryptor = crypto.FilebitCipher(key).decryptor()
        filename = crypto.unpad(decryptor.update(crypto.b64dec(info['name'])) + decryptor.finalize()).decode("utf-8")
        size = info['size']
    state = info['state']
    print(f'[{state}] {filename} Filesize: {size}')
```

## Upload
```python
from filebit import upload
u = upload.Upload(path)
u.max_workers = 4 # parallel upload workers
u.start(retries=10) # returns admin code
print(u.get_link())
```

## Download
```python
import os
from filebit import download
from pathlib import Path
d = download.Download("https://filebit.net/f/tlBKQQ6#Abts8F6i70LmwgoeUrDe_1RWMmuXBtQj5C_BguRzJL")
d.prepare()
path = Path(os.getcwd())
if path.is_dir():
    path = path.joinpath(d.filename)
d.start(path)
success = d.validate()
if success:
    print("File download successful")
    print("Stored at:")
    print(d.path)
else:
    print("Download failed.")
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