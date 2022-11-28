import os
import hashlib
import random
import requests
import requests.exceptions
import io
import threading
from crc32c import crc32c
import time
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from pathlib import Path
from functools import partial
from . import api, crypto
from tqdm import tqdm


class Upload:
    def __init__(self, path, name=None, sha256=None):
        self.path = Path(path)
        if not self.path.is_file():
            raise api.FilebitError("path not a valid file")
        self.size = self.path.stat().st_size
        self.key = os.urandom(16)
        self.iv = os.urandom(16)
        self.sha256 = sha256 if sha256 else calculate_file_hash(path)
        name = name if name else self.path.name
        if isinstance(name, str):
            name = name.encode("utf-8")
        self.filename = name
        self.nksh = crypto.name_key_size_hash(self.filename, self.key, self.size)
        self.upload_id = self.generate_upload_id()
        self.chunks = api.get_slice_offset(self.size)
        self.servers = api.get_upload_servers()
        self.fileid = None
        self.admincode = None
        self.upload_completed = False
        self.crc_map = dict()
        self.retry_upload_chunks = Queue()

    def generate_upload_id(self):
        encryptor = crypto.FilebitCipher(key=self.key, iv=self.iv).encryptor()
        encrypted_filename = encryptor.update(crypto.pad(self.filename)) + encryptor.finalize()
        data = api.call('storage/bucket/create.json', {
            'name': crypto.b64enc(encrypted_filename),
            'size': self.size,
            'sha256': self.sha256,
            'nksh': self.nksh
        })
        if not data['id']:
            raise api.FilebitError("could not get an id from upload server")
        return data['id']

    def upload_producer(self, encrypted_file, chunk_id=None):
        return MultipartEncoder(
            fields={
                "file": (self.filename, encrypted_file, 'application/octet-stream')
            }
        )

    def retry_upload_chunk(self, s, msg, retries):
        self.retry_upload_chunks.put((time.time() + 5, s, retries))
        return False

    def upload_chunk(self, s, retries=5):
        if retries <= 0:
            raise api.FilebitError("max retries reached.")
        chunk_id, seek, end = s
        bytes_to_upload = end - seek
        url = f"https://{random.choice(self.servers)}/storage/bucket/{self.upload_id}/add/{chunk_id}/{seek}-{end}"
        enc = crypto.FilebitCipher(key=self.key, iv=self.iv).encryptor()
        encrypted_file = io.BytesIO()
        with open(self.path, 'rb') as f:
            f.seek(seek)
            while bytes_to_upload > 0:
                data = f.read(min(0x10000, bytes_to_upload))
                if len(data) == bytes_to_upload:
                    data = crypto.pad(data)
                bytes_to_upload -= len(data)
                encrypted_file.write(enc.update(data))
            encrypted_file.write(enc.finalize())
        encrypted_file.seek(0)
        crc32 = crc32c(encrypted_file.getbuffer())
        m = self.upload_producer(encrypted_file, chunk_id)
        try:
            response = requests.post(url, data=m, headers={'Content-Type': m.content_type}, timeout=20)
            data = response.json()
        except requests.exceptions.Timeout:
            return self.retry_upload_chunk(s, "timeout", retries-1)
        except requests.exceptions.HTTPError:
            return self.retry_upload_chunk(s, "http error", retries - 1)
        except requests.exceptions.ConnectionError:
            return self.retry_upload_chunk(s, "http connection error", retries - 1)
        except requests.exceptions.JSONDecodeError:
            return self.retry_upload_chunk(s, "json decode error", retries - 1)
        else:
            if response.status_code != 200:
                return self.retry_upload_chunk(s, f"http error: {response.status_code}", retries-1)
            if "error" in data:
                return self.retry_upload_chunk(s, f"error: {data['error']}", retries - 1)
            if data['crc32'] != crc32:
                return self.retry_upload_chunk(s, "crc32 failed", retries-1)

        self.crc_map[chunk_id] = crc32
        return end - seek

    def upload_all(self, retries):
        for s in self.chunks:
            self.upload_chunk(s)
        while not self.retry_upload_chunks.empty():
            t, s, retries = self.retry_upload_chunks.get()
            time.sleep(max(t - time.time(), 0))
            self.upload_chunk(s, retries)

    def finalize_upload(self):
        sha = hashlib.sha256(b",".join(str(v).encode('ascii') for k, v in sorted(self.crc_map.items()))).hexdigest()
        data = api.call('storage/bucket/finalize.json', {
            "uploadid": self.upload_id,
            "server": random.choice(self.servers),
            "sha": sha,
            "chunks": len(self.crc_map)
        })
        if 'error' in data:
            raise api.FilebitError(data['error'])
        self.fileid = data['id']
        self.admincode = data['admincode']
        self.upload_completed = True
        self.close()
        return self.admincode

    def start(self, retries=5):
        self.upload_all(retries)
        return self.finalize_upload()

    def close(self, failed=False):
        pass

    def get_admin_code(self):
        return self.admincode

    def get_link(self):
        if not self.upload_completed:
            raise api.FilebitError("upload not completed")
        return f'{api.api_endpoint}f/{self.fileid}#{crypto.merge_key_iv(self.key, self.iv)}'


def calculate_file_hash(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(partial(f.read, 0x100000), b''):
            h.update(chunk)
    return h.hexdigest()


def calculate_file_hash_progress(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    path = Path(path)
    size = path.stat().st_size
    with tqdm(desc=f"Calculating hash ({algorithm})", total=size, leave=False,
              unit="B", unit_divisor=1024, unit_scale=True) as bar:
        with open(path, "rb") as f:
            for chunk in iter(partial(f.read, 0x100000), b''):
                h.update(chunk)
                bar.update(len(chunk))
    return h.hexdigest()


class UploadProgress(Upload):
    """Upload with CLI output"""
    def __init__(self, path, name=None, sha256=None):
        if not sha256:
            sha256 = calculate_file_hash_progress(path)
        super().__init__(path, name, sha256)
        self.progress_bar = tqdm(desc="(uploading)", total=self.size, colour='green',
                                 unit="B", unit_divisor=1024, unit_scale=True, leave=False)

    def retry_upload_chunk(self, s, msg, retries):
        self.progress_bar.set_description_str(f'(uploading) ({s[0]} {msg}) (retry)')
        try:
            monitor = threading.local().monitor
        except AttributeError:
            pass
        else:
            self.progress_bar.update(-monitor.bytes_read)
        return super().retry_upload_chunk(s, msg, retries)

    def upload_producer(self, encrypted_file, chunk_id=None):
        p = super().upload_producer(encrypted_file)
        self.progress_bar.refresh()

        def m(mo):
            self.progress_bar.update(mo.bytes_read - mo._last_progress)
            mo._last_progress = mo.bytes_read

        monitor = MultipartEncoderMonitor(p, m)
        monitor._last_progress = 0
        threading.local().monitor = monitor
        return monitor

    def get_link(self):
        self.progress_bar.update(self.size - self.progress_bar.n)
        self.progress_bar.close()
        return super().get_link()

    def close(self, failed=False):
        self.progress_bar.close()
        super().close()


class ParallelUpload(Upload):
    max_workers = 6

    def upload_all(self, retries):
        with ThreadPoolExecutor(max_workers=self.max_workers) as e:
            failed = False
            try:
                fs = [e.submit(self.upload_chunk, s, retries) for s in self.chunks]
                while not self.retry_upload_chunks.empty() or not all(f.done() for f in fs):
                    try:
                        t, s, retries = self.retry_upload_chunks.get(timeout=0.3)
                    except Empty:
                        continue
                    if t > time.time():
                        self.retry_upload_chunks.put((t, s, retries))
                        continue
                    fs.append(e.submit(self.upload_chunk, s, retries))
                    failed_futures = [f for f in fs if f.done() and f.exception()]
                    if failed_futures:
                        raise api.FilebitError(f"upload failed: {''.join(str(f) for f in failed_futures)}")
            except BaseException as e:
                failed = True
                raise e
            finally:
                self.close(failed)


class UploadProgressParallel(UploadProgress, ParallelUpload):
    pass
