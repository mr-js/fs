from dataclasses import dataclass
import uuid
from enum import Enum
import hashlib
import base64
import os, sys
import shutil
import codecs
import pickle
import zlib
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tqdm import tqdm, trange

import logging
msg_format = '%(asctime)s - %(levelname)10s: %(message)s'
date_format ='%d.%m.%Y %H:%M:%S'
log_filename = 'journal.log'
logging.basicConfig(level=logging.DEBUG,
                    format=msg_format,
                    datefmt=date_format,
                    filename=log_filename,
                    filemode='w')
log = logging.getLogger('FS')
if not log.handlers:
    console = logging.StreamHandler()
    log.addHandler(console)


def timer(message = 'Started'):
    if not hasattr(timer, 'started_time') or message == '#reset':
        timer.started_time = time.process_time()
    else:
        log.info(f'{message}: {time.process_time() - timer.started_time} seconds')


@dataclass
class PATHS:
    input: str = 'input'
    output: str = 'output'
    storage: str = 'storage'
    root: str = os.getcwd()


@dataclass
class FSO:
    id: str
    path: str
    name: str
    content: bytes
    crc: str
    def __hash__(self):
        return hash((self.id))


class FSD:
    data: bytes = b''
    memory: set() = set()
    password: str = ''
    key: bytes = b''
    cipher: None
    segment_size: int =1024*1024*1024
    paths: PATHS
    volume_size: int = 1024*1024*1024


    def __init__(self, password='', paths=PATHS('input', 'output', 'storage'), volume=1024*1024*1024):
        self.volume_size = volume
        self.paths = paths
        self.set_password(password)


    def set_password(self, password=''):
        if password != '':
            m = hashlib.sha256()
            m.update(password.encode('utf-8'))
            key = m.digest()
        else:
            key = get_random_bytes(16)
        with codecs.open('fs.key', 'wb') as f:
            f.write(key)
        self.__read_password()


    def __read_password(self):
        with codecs.open('fs.key', 'rb') as f:
            self.key = f.read()


    def __dir_files(self, path, ext=''):
        total_size = 0
        filenames = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if not ext or file.endswith(ext):
                    filenames.append(os.path.join(root, file))
                    total_size += os.path.getsize(os.path.join(root, file))
        # !! BUG filenames = [filename for filename in filenames] => input\in\r.txt = > \output\input\in\r.txt\r.txt (directory duplication)
        return filenames, total_size


    def __dir_clear(self, path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        os.mkdir(path)


    def __error(self, e):
        log.error(f'error: {e}')
        sys.exit(1)


    def __load(self):
        try:
            log.info('loading...')
            self.memory.clear()
            filenames, total_size = self.__dir_files(self.paths.input)
#             if total_size >= 10_000_000_000:
#                 raise ValueError('total input files size is too large')
            for filename in (pbar := tqdm(filenames)):
                pbar.set_description(f'Loading {os.path.basename(filename)}')
                with codecs.open(filename, 'rb') as f:
                    content = f.read()
                fso = FSO(str(uuid.uuid4()), filename, os.path.basename(filename), content, hashlib.md5(content).hexdigest())
                self.memory.add(fso)
        except Exception as e:
            self.__error(e)


    def __pack(self):
        try:
            log.info('dumping...')
            dump = pickle.dumps(self.memory)
            log.info('crypting...')
            self.cipher = AES.new(self.key, AES.MODE_CTR, use_aesni='True')
            self.data = b''
            for offset in (pbar := trange(0, len(dump), self.segment_size)):
                pbar.set_description(f'Crypting {offset}')
                self.data += self.cipher.encrypt(dump[offset:offset+self.segment_size])
                self.nonce = self.cipher.nonce
            log.info('compressing...')
            self.data = zlib.compress(self.data)
        except Exception as e:
            self.__error(e)


    def __upload(self):
        try:
            log.info('uploading...')
            self.__dir_clear(self.paths.storage)
            volume_index = 1
            volume_index_width = len(str(round(len(self.data)/self.volume_size)))+1
            for offset in trange(0, len(self.data), self.volume_size):
                with codecs.open(os.path.join(self.paths.storage, f'store{volume_index:0{volume_index_width}d}.dat'), 'wb') as f:
                    f.write(self.data[offset:offset+self.volume_size])
                volume_index += 1
        except Exception as e:
            self.__error(e)


    def __download(self):
        try:
            log.info('downloading...')
            self.data = b''
            filenames, total_size = self.__dir_files(self.paths.storage, '.dat')
            for filename in (pbar := tqdm(filenames)):
                pbar.set_description(f'Downloading {os.path.basename(filename)}')
                with codecs.open(filename, 'rb') as f:
                    self.data += f.read()
        except Exception as e:
            self.__error(e)


    def __unpack(self):
        try:
            log.info('decompressing...')
            dump = zlib.decompress(self.data)
            log.info('decrypting...')
            data = b''
            self.cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce, use_aesni='True')
            for offset in (pbar := trange(0, len(dump), self.segment_size)):
                pbar.set_description(f'Decrypting {offset}')
                data += self.cipher.decrypt(dump[offset:offset+self.segment_size])
            log.info('pulling...')
            self.memory = pickle.loads(data)
        except Exception as e:
            self.__error(e)


    def __extract(self):
        try:
            log.info('extracting...')
            self.__dir_clear(self.paths.output)
            for file in (pbar := tqdm(self.memory)):
                pbar.set_description(f'Extracting {file.name}')
                filename = os.path.join(self.paths.output, file.path, file.name)
                os.makedirs(os.path.join(self.paths.output, file.path), exist_ok=True)
                with codecs.open(filename, 'wb') as f:
                    if hashlib.md5(file.content).hexdigest() == file.crc:
                        f.write(file.content)
                    else:
                        log.error(f'{file.name} is corrupted')
        except Exception as e:
            self.__error(e)


    def store(self):
        self.__load()
        self.__pack()
        self.__upload()


    def receive(self):
        self.__download()
        self.__unpack()
        self.__extract()


if __name__ == "__main__":
    path = os.getcwd()
    os.chdir(path)
    timer()
    fsd = FSD('', PATHS('input', 'output', 'storage'))
    timer('started')
    fsd.store()
    timer('stored')
    timer('#reset')
    fsd.receive()
    timer('received')
    timer('#reset')
