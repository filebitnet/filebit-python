import requests
import random
import re
from . import crypto

api_endpoint = "https://filebit.net/"
url_match = re.compile("https://filebit.net/f/(.*?)#(.*)")


class FilebitError(requests.HTTPError):
    pass


def call(api, data=None, **kwargs):
    """perform a call to the filebit api
    :param api: api endpoint
    :param data: dict with data to post. Will be transformed to json
    :param kwargs: kwargs will be transformed to json"""
    url = api_endpoint + api
    if isinstance(data, dict) and kwargs:
        d = data.copy()
        d.update(kwargs)
    else:
        d = data if data else kwargs
    response = requests.post(url, json=d)
    response.raise_for_status()
    return response.json()


def get_upload_servers():
    """request all upload servers"""
    data = call("storage/server.json")
    if 'checkin' not in data:
        raise FilebitError('unexpected response')
    servers = data['checkin']
    return servers


def get_upload_server():
    """request a random upload server"""
    return random.choice(get_upload_servers())


def is_valid_url(url: str):
    """Check if a url is a valid filebit url"""
    return bool(url_match.match(url))


def get_parts(url: str):
    """Helper function to get fileid and filebit key of a file from a valid filebit url"""
    m = url_match.match(url)
    if not m:
        raise FilebitError("not a valid url")
    return m.group(1), m.group(2)


def get_file_info(url_or_id, filebit_key=None, st=None):
    """Request detailed information on a filebit link or a fileid and its key
    :param url_or_id: filebit url or fileid
    :param filebit_key: filebit key if no full link
    :param st: speed ticket.
    :return:
    """
    if not filebit_key:
        filebit_id, filebit_key = get_parts(url_or_id)
    else:
        filebit_id = url_or_id
    d = dict(file=filebit_id)
    if st:
        d['st'] = st
    data = call('storage/bucket/info.json', d)
    if "error" in data:
        raise FilebitError("could not get info of file")
    filename_encrypted = crypto.b64dec(data['filename'])
    decryptor = crypto.FilebitCipher(filebit_key).decryptor()
    data['filename'] = crypto.unpad(decryptor.update(filename_encrypted) + decryptor.finalize()).decode("utf-8")
    return data


def get_multi_info(urls_or_fileids):
    """request data on multiple urls
    :param urls_or_fileids: a list of filebit urls or iterable of filebit fileids
    """
    if not isinstance(urls_or_fileids, list):
        urls_or_fileids = list(urls_or_fileids)
    if not url_match.match(urls_or_fileids[0]):
        fileids = urls_or_fileids
    else:
        fileids = [get_parts(url)[0] for url in urls_or_fileids]
    data = call('storage/multiinfo.json', files=fileids)
    return data


def get_slice_offset(size: int):
    """helper function to split a file into chunks for uploading
    :param size: size of file to be uploaded
    """
    chunklist = []
    done = 0
    offset_a = 512000
    offset_b = 52428800
    chunk_id = 0
    for i in range(1, 9):
        if done >= size:
            return chunklist
        position = min(i*offset_a, size)
        chunklist.append([chunk_id, done, min(size, done + position)])
        done += position
        chunk_id += 1

    while done < size:
        chunklist.append([chunk_id, done, min(size, done+offset_b)])
        done += offset_b
        chunk_id += 1
    return chunklist


def request_speedticket(licence_key: str):
    """request a speed ticket for downloading
    :param licence_key: a valid filebit licence key"""
    data = call('app/licence/add.json', key=licence_key, skc=1)
    if 'error' in data:
        raise FilebitError("could not validate licence key")
    return data['key']


def activate_debugging():
    """Installs debug handlers for requests and http.client"""
    import logging
    from http.client import HTTPConnection

    log = logging.getLogger('urllib3')
    log.setLevel(logging.DEBUG)
    stream = logging.StreamHandler()
    stream.setLevel(logging.DEBUG)
    log.addHandler(stream)
    HTTPConnection.debuglevel = 1
