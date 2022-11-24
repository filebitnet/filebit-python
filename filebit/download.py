import time
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from . import crypto, api
from tqdm import trange


class Download:
    def __init__(self, url, license_key=None, progress_bar=None):
        self.url = url
        self.fileid, self.filebit_key = api.get_parts(url)
        self.license_key = license_key
        self.progress_bar = progress_bar
        self.download_queue = None
        self.st = False
        self.chunks = None
        self.path = None
        self.filesize = None
        self.key = None
        self.iv = None
        self.filename = None
        self.slot = None
        self.waiting_time = None
        self.chunks = None
        self.downloading = False

    def validate_slot(self):
        data = api.call('file/slot.json', slot=self.slot['ticket'])
        if 'error' in data:
            raise api.FilebitError(data['error'])
        if not data['success']:
            raise api.FilebitError('slot was not properly confirmed')

    def wait(self, wait=None):
        t = time.time()
        to_wait = wait if wait else self.waiting_time
        if self.progress_bar is not None and to_wait > 0:
            for _ in trange(to_wait, desc="waiting"):
                time.sleep(1)
        else:
            time.sleep(to_wait)
        time.sleep(max(0, time.time() - t - to_wait))

    def acquire_info(self):
        info = api.get_file_info(self.url, st=self.st)
        self.filename = info['filename']
        self.filesize = info['filesize']
        if self.progress_bar is not None:
            self.progress_bar.reset(self.filesize)
            self.progress_bar.set_description(f"Downloading {self.filename}")
        self.slot = info['slot']
        self.waiting_time = self.slot['wait']

    def chunk_info(self):
        data = api.call('storage/bucket/contents.json', id=self.fileid)
        if 'error' in data:
            raise api.FilebitError(data['error'])
        self.chunks = data['chunks']

    def start(self):
        if self.license_key:
            self.st = api.request_speedticket(self.license_key)
        self.downloading = True
        self.acquire_info()
        self.wait()
        self.validate_slot()
        self.chunk_info()

    def start_download(self, path, overwrite=False, workers=2):
        self.path = path
        if os.path.exists(path):
            if overwrite:
                os.remove(path)
            else:
                raise api.FilebitError("file exists")
        if not self.st:
            workers = 1

        self.download_queue = Queue(maxsize=workers * 2)
        with ThreadPoolExecutor(max_workers=workers) as e:
            fs = [e.submit(self.download_chunk, chunk_id, offset0, length, downloadid)
                  for chunk_id, offset0, __, length, crc32, downloadid in self.chunks]
            with open(self.path, "wb") as f:
                try:
                    f.truncate(self.filesize)
                except OSError:
                    raise api.FilebitError("could not allocate file")

                while not all(future.done() for future in fs) or not self.download_queue.empty():
                    offset, data = self.download_queue.get()
                    f.seek(offset)
                    f.write(data)
                    if self.progress_bar is not None:
                        self.progress_bar.update(len(data))

    def download_chunk(self, chunk_id, offset, length, downloadid):
        response = requests.get(f'{api.api_endpoint}download/{downloadid}?slot={self.slot["ticket"]}', stream=True)
        decryptor = crypto.FilebitCipher(self.filebit_key).decryptor()
        for data in response.iter_content(0x100000, False):
            if data == "Forbidden":
                return False
            if data[0] + data[-1] == b"{}":
                j = response.json()
                if "error" in j:
                    pass
                return False
            length -= len(data)
            to_write = decryptor.update(data)
            if length < 0:
                to_write = crypto.unpad(memoryview(to_write))
            self.download_queue.put((offset, memoryview(to_write)))
            offset += len(data)
        dl = decryptor.finalize()
        if dl:
            self.progress_bar.update(len(dl))
            self.download_queue.put((offset, crypto.unpad(dl)))
        return True
