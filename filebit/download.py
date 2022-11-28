import time
import os
import requests
import traceback
import sys
import signal
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from crc32c import crc32c
from tqdm import trange
from . import crypto, api


class Download:
    def __init__(self, url, license_key=None, progress_bar=None):
        self.url = url
        self.fileid, self.filebit_key = api.get_parts(url)
        self.license_key = license_key
        self.progress_bar = progress_bar
        self.download_queue = None
        self.retry_queue = Queue()
        self.st = False
        self.info = None
        self.chunks = None
        self.path = None
        self.filesize = None
        self.key = None
        self.iv = None
        self.filename = None
        self.slot = None
        self.waiting_time = None
        self.chunks = None
        self.success = None
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
            for _ in trange(to_wait, desc=f"{to_wait}s waiting"):
                time.sleep(1)
        else:
            time.sleep(to_wait)
        time.sleep(max(0, time.time() - t - to_wait))

    def acquire_info(self):
        info = api.get_file_info(self.url, st=self.st)
        self.filename = info['filename']
        self.filesize = info['filesize']
        self.info = info
        if self.progress_bar is not None:
            self.progress_bar.reset(self.filesize)
            self.progress_bar.set_description_str(f"(downloading) ({self.filename}) ")
        self.slot = info['slot']
        self.waiting_time = self.slot['wait']

    def chunk_info(self):
        data = api.call('storage/bucket/contents.json', id=self.fileid)
        if 'error' in data:
            raise api.FilebitError(data['error'])
        self.chunks = data['chunks']

    def validate(self, delete_on_failure=True):
        def delete():
            if not delete_on_failure:
                return
            print("deleting corrupted file\n", file=sys.stderr, flush=True)
            os.remove(self.path)

        if self.success is False:
            delete()
            return False
        if self.downloading:
            return
        from .upload import calculate_file_hash, calculate_file_hash_progress
        file_hash = self.info.get('hash', None)
        if not file_hash or not file_hash['isAttached']:
            return True
        if self.progress_bar is not None:
            self.success = calculate_file_hash_progress(self.path, file_hash['type']) == file_hash["value"]
        else:
            self.success = calculate_file_hash(self.path, file_hash['type']) == file_hash["value"]
        if not self.success:
            print("hash check failed\n", file=sys.stderr, flush=True)
            delete()
        return self.success

    def prepare(self):
        if self.license_key:
            self.st = api.request_speedticket(self.license_key)
        self.acquire_info()
        self.wait()
        self.validate_slot()
        self.chunk_info()

    def start(self, path, overwrite=False, workers=2, retries=5):
        self.downloading = True
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
            def sigint(signum, frame):
                self.downloading = False
                e.shutdown(False, cancel_futures=True)
                if self.progress_bar is not None:
                    self.progress_bar.leave = False
                    self.progress_bar.close()
                self.success = False
                self.validate()
                raise KeyboardInterrupt
            signal.signal(signal.SIGINT, sigint)

            fs = [e.submit(self.download_chunk, chunk_id, offset0, length, downloadid, crc32, retries)
                  for chunk_id, offset0, __, length, crc32, downloadid in self.chunks]
            with open(self.path, "wb") as f:
                try:
                    f.truncate(self.filesize)
                except OSError:
                    raise api.FilebitError("could not allocate file")

                while (not all(future.done() for future in fs) or
                       not self.download_queue.empty() or
                       not self.retry_queue.empty()):
                    if not self.retry_queue.empty():
                        t, args = self.retry_queue.get(False)
                        if t > time.time():
                            self.retry_queue.put((t, args))
                        else:
                            if self.progress_bar is not None:
                                self.progress_bar.set_description_str(
                                    f"(downloading) ({self.filename}) (retrying chunk {args[0]}) "
                                )
                            fs.append(e.submit(self.download_chunk, *args))
                    try:
                        offset, data = self.download_queue.get(timeout=0.3)
                    except Empty:
                        continue
                    if not self.downloading:
                        for future in fs:
                            future.cancel()
                        break
                    f.seek(offset)
                    f.write(data)
                    if self.progress_bar is not None:
                        self.progress_bar.update(len(data))
        self.downloading = False

    def download_chunk(self, chunk_id, offset, length, downloadid, chunk_crc32, retries=5):
        start_offset = offset
        start_length = length

        def abort(msg=None):
            if self.progress_bar is not None:
                self.progress_bar.leave = False
                self.progress_bar.close()
                if msg:
                    print("Download failed:", msg, file=sys.stderr, flush=True)
            self.downloading = False
            self.success = False
            return False

        def retry(next_time, msg=None):
            """retry to download chunk after next_time seconds"""
            if self.progress_bar is not None:
                if msg:
                    self.progress_bar.set_description_str(f"(downloading) ({self.filename}) (retry) ({msg})")
                self.progress_bar.update(-(offset - start_offset))
            self.retry_queue.put((time.time() + next_time, (chunk_id,
                                  start_offset, start_length, downloadid,
                                  chunk_crc32, retries - 1)))
            return False

        if retries <= 0:
            return abort("maximum retries reached.")
        try:
            response = requests.get(
                f'{api.api_endpoint}download/{downloadid}?slot={self.slot["ticket"]}',
                stream=True,
                timeout=(10, 20),  # connect timeout, read timeout
            )
        except requests.exceptions.ConnectionError:
            return retry(20, "connection error")
        except requests.exceptions.Timeout:
            return retry(20, "timeout")
        except requests.exceptions.BaseHTTPError:
            return retry(20, "http error")
        except BaseException:
            print("ttt")
            if not self.downloading:
                return
            traceback.print_exc(file=sys.stderr)
            return abort()
        decryptor = crypto.FilebitCipher(self.filebit_key).decryptor()
        crc32 = 0
        try:
            for data in response.iter_content(0x100000, False):
                if not self.downloading:
                    return
                if data == "Forbidden":
                    return retry(20)
                if data[0] + data[-1] == b"{}":
                    j = response.json()
                    if "error" in j:
                        return retry(5)
                    else:
                        return retry(10)
                crc32 = crc32c(data, crc32)
                length -= len(data)
                to_write = decryptor.update(data)
                if length < 0:
                    to_write = crypto.unpad(memoryview(to_write))
                self.download_queue.put((offset, memoryview(to_write)))
                offset += len(data)
        except requests.exceptions.Timeout:
            return retry(5, "read timeout")
        except requests.exceptions.ConnectionError:
            return retry(5, "read timeout")
        except BaseException:
            print("tttt")
            if not self.downloading:
                return
            traceback.print_exc(file=sys.stderr)
            return abort()

        dl = decryptor.finalize()
        if dl:
            self.progress_bar.update(len(dl))
            self.download_queue.put((offset, crypto.unpad(dl)))
        if chunk_crc32 != crc32:
            retry(4, "crc failed")
            return False
        return True
