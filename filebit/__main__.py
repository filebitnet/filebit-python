import os
import sys
from docopt import docopt
from tqdm import tqdm
from pathlib import Path
from . import upload, download

__doc__ = """
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
"""

o = docopt(__doc__)


def main_upload():
    u = upload.UploadProgressParallel(o["<FILE>"])
    if o['-p']:
        try:
            workers = int(o['-p'])
        except ValueError:
            sys.stderr.write("-p must be number")
            sys.exit(2)
    else:
        workers = 2
    u.max_workers = workers
    u.start(retries=10)  # returns admin code
    link = u.get_link()
    print(link)


def main_download():
    with tqdm(unit_scale=True, unit_divisor=1024, unit="B", colour='red') as bar:
        d = download.Download(o['<url>'], o['-l'], bar)
        d.prepare()
        if not o['-o']:
            path = Path(os.getcwd())
        else:
            path = Path(o['-o'])
        if path.is_dir():
            path = path.joinpath(d.filename)
        if path.is_file() and not o['--overwrite']:
            sys.stderr.write("File exists.")
            sys.exit(2)
        if o['-p']:
            try:
                workers = int(o['-p'])
            except ValueError:
                sys.stderr.write("-p must be number")
                sys.exit(2)
        else:
            workers = 2
            if not o['-l']:
                workers = 1
        d.start(path, o['--overwrite'], workers)
    success = d.validate()
    if success:
        print("File download successful")
        print("Stored at:")
        print(d.path)
    else:
        print("Download failed.")


def main():
    if o['download']:
        main_download()
    elif o['upload']:
        main_upload()
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
