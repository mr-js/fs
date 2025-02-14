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
import secrets
from aes.aes import encrypt, decrypt
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
    # log.addHandler(console)


def timer(message = 'Started'):
    if not hasattr(timer, 'started_time') or message == '#reset':
        timer.started_time = time.process_time()
    else:
        log.info(f'{message}: {time.process_time() - timer.started_time} seconds')


@dataclass
class PATHS:
    path = os.getcwd()
    os.chdir(path)    
    root: str = os.path.join(os.getcwd(), 'temp')    
    input: str = 'input'
    output: str = 'output'
    storage: str = 'storage'


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
    memory: set = set()
    password: str = ''
    key: bytes = b''
    paths: PATHS
    volume_size: int = 1024*1024*1024
    crypt_part_size: int = 16


    def __init__(self, password='', root='temp', input='input', output='output', storage='storage', volume=1024):
        self.volume_size = volume * 1024 * 1024
        self.paths = PATHS(root, input, output, storage)
        self.set_password(password)


    def set_password(self, password=''):
        if password != '':
            m = hashlib.sha256()
            m.update(password.encode('utf-8'))
            self.key = m.digest()
        else:
            self.key = secrets.token_bytes(16)
        with codecs.open(os.path.join(self.paths.root, 'fs.key'), 'wb') as f:
            f.write(self.key)
        self.__read_password()


    def __read_password(self):
        with codecs.open(os.path.join(self.paths.root, 'fs.key'), 'rb') as f:
            self.key = f.read()
        self.password = base64.b64encode(self.key).decode('utf-8') 


    def __dir_files(self, path, ext=''):
        total_size = 0
        filenames = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if not ext or file.endswith(ext):
                    filenames.append(os.path.join(root, file))
                    total_size += os.path.getsize(os.path.join(root, file))
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
            filenames, total_size = self.__dir_files(os.path.join(self.paths.root, self.paths.input))
            for filename in (pbar := tqdm(filenames)):
                pbar.set_description(f'Loading')
                with codecs.open(filename, 'rb') as f:
                    content = f.read()
                if filename.startswith(os.path.join(self.paths.root, self.paths.input)):
                    path = os.path.dirname(filename[len(os.path.join(self.paths.root, self.paths.input)):].lstrip(os.path.sep))
                file = os.path.basename(filename)
                fso = FSO(str(uuid.uuid4()), path, file, content, hashlib.md5(content).hexdigest())
                self.memory.add(fso)
        except Exception as e:
            self.__error(e)


    def __pack(self):
        try:
            log.info('dumping...')
            dump = pickle.dumps(self.memory)
            log.info('compressing...')
            data = zlib.compress(dump)
            log.info('crypting...')
            self.data = b''
            pbar = tqdm(desc=f'Crypting', total=len(data))
            crypted_data = []
            temp = []
            for byte in data:
                pbar.update(1)
                temp.append(byte)
                if len(temp) == self.crypt_part_size:
                    crypted_part = encrypt(temp, self.password)
                    crypted_data.extend(crypted_part)
                    del temp[:]
            if 0 < len(temp) < self.crypt_part_size:
                empty_spaces = self.crypt_part_size - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                crypted_part = encrypt(temp, self.password)
                crypted_data.extend(crypted_part)
            self.data = bytes(crypted_data)
            pbar.close()
        except Exception as e:
            self.__error(e)


    def __upload(self):
        try:
            log.info('uploading...')
            self.__dir_clear(os.path.join(self.paths.root, self.paths.storage))
            volume_index = 1
            volume_index_width = len(str(round(len(self.data)/self.volume_size)))
            for offset in (pbar := trange(0, len(self.data), self.volume_size)):
                pbar.set_description(f'Uploading')
                file = f'store{volume_index:0{volume_index_width}d}.dat' if volume_index_width > 1 else f'store.dat'
                with codecs.open(os.path.join(self.paths.root, self.paths.storage, file), 'wb') as f:
                    f.write(self.data[offset:offset+self.volume_size])
                volume_index += 1
        except Exception as e:
            self.__error(e)


    def __download(self):
        try:
            log.info('downloading...')
            self.data = b''
            filenames, total_size = self.__dir_files(os.path.join(self.paths.root, self.paths.storage), '.dat')
            for filename in (pbar := tqdm(filenames)):
                pbar.set_description(f'Downloading')
                with codecs.open(filename, 'rb') as f:
                    self.data += f.read()
        except Exception as e:
            self.__error(e)


    def __unpack(self):
        try:
            log.info('decrypting...')      
            dump = b''
            decrypted_data = []
            temp = []
            data = self.data
            pbar = tqdm(desc=f'Decrypting', total=len(self.data))
            for byte in data:
                pbar.update(1)
                temp.append(byte)
                if len(temp) == self.crypt_part_size:
                    decrypted_part = decrypt(temp, self.password)
                    decrypted_data.extend(decrypted_part)
                    del temp[:] 
            if 0 < len(temp) < self.crypt_part_size:
                empty_spaces = self.crypt_part_size - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                decrypted_part = encrypt(temp, self.password)
                decrypted_data.extend(decrypted_part )
            pbar.close()
            log.info('decompressing...')
            dump = zlib.decompress(bytes(decrypted_data))            
            log.info('pulling...')
            self.memory = pickle.loads(dump)
            pass
        except Exception as e:
            self.__error(e)


    def __extract(self):
        try:
            log.info('extracting...')
            self.__dir_clear(os.path.join(self.paths.root, self.paths.output))
            for file in (pbar := tqdm(self.memory)):
                pbar.set_description(f'Extracting')
                filename = os.path.join(self.paths.root, self.paths.output, file.path, file.name)
                os.makedirs(os.path.join(self.paths.root, self.paths.output, file.path), exist_ok=True)
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
        print('STORED OK!')


    def receive(self):
        self.__download()
        self.__unpack()
        self.__extract()
        print('RECEIVED OK!')


if __name__ == "__main__":
    # demo init
    fsd = FSD('password', root='temp', input='input', output='output', storage='storage', volume=1024)
    # file system conversion, packaging and encryption
    fsd.store()
    # decryption, decompression and file system conversion
    fsd.receive()
