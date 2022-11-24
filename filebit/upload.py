import os
import hashlib
import random
import requests
import requests.exceptions
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        self.sha256 = sha256 if sha256 else calc_sha256(path)
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

    def upload_chunk(self, s):
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
        m = self.upload_producer(encrypted_file, chunk_id)
        response = requests.post(url, data=m, headers={'Content-Type': m.content_type})
        response.raise_for_status()
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(response.content)
            raise
        if "error" in data:
            raise api.FilebitError(f"upload chunk {chunk_id} failed")
        self.crc_map[chunk_id] = data["crc32"]
        return end - seek

    def upload_all(self):
        for s in self.chunks:
            self.upload_chunk(s)

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
        return self.admincode

    def start(self):
        self.upload_all()
        return self.finalize_upload()

    def get_link(self):
        if not self.upload_completed:
            raise api.FilebitError("upload not completed")
        return f'{api.api_endpoint}f/{self.fileid}#{crypto.merge_key_iv(self.key, self.iv)}'


def calc_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(partial(f.read, 0x100000), b''):
            h.update(chunk)
    return h.hexdigest()


def calc_sha256_progress(path):
    h = hashlib.sha256()
    path = Path(path)
    size = path.stat().st_size
    with tqdm(desc="Calculating hash", total=size,
              unit="B", unit_divisor=1024, unit_scale=True) as bar:
        with open(path, "rb") as f:
            for chunk in iter(partial(f.read, 0x100000), b''):
                h.update(chunk)
                bar.update(len(chunk))
    return h.hexdigest()


class UploadProgress(Upload):
    """Upload with CLI output"""
    def __init__(self, path, name=None, sha256=None):
        sha256 = calc_sha256_progress(path)
        super().__init__(path, name, sha256)
        self.progress_bar = tqdm(desc="Uploading data", total=self.size, colour='green',
                                 unit="B", unit_divisor=1024, unit_scale=True)

    def upload_producer(self, encrypted_file, chunk_id=None):
        p = super().upload_producer(encrypted_file)
        self.progress_bar.refresh()

        def m(mo):
            self.progress_bar.update(mo.bytes_read - mo._last_progress)
            mo._last_progress = mo.bytes_read

        monitor = MultipartEncoderMonitor(p, m)
        monitor._last_progress = 0
        return monitor

    def get_link(self):
        self.progress_bar.update(self.size - self.progress_bar.n)
        self.progress_bar.close()
        return super().get_link()


class ParallelUpload(Upload):
    max_workers = 6

    def upload_all(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as e:
            for _ in as_completed(e.submit(self.upload_chunk, s) for s in self.chunks):
                pass


class UploadProgressParallel(UploadProgress, ParallelUpload):
    pass
