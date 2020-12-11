import struct, hashlib, time
import binascii
import contextlib
import mmap, zlib
from string import ascii_lowercase
from random import choice, randint, random
import os, shutil
from Crypto.Cipher import AES
from hashlib import md5

key   = bytes([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01])
iv   = bytes([0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef, 0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x12])
exeNameHeader = b'\xBB\xCD\x63\x09\x07\xA0\xB9\xED\x90'

def readChunk(infile, size):
    chunk = infile.read(size)
    if len(chunk) == 0:
        return 0
    elif len(chunk) % 16 != 0:
        chunk += b' ' * (16 - len(chunk) % 16)

    return chunk

def findKeywordInMemory(m, findValue):
    NOTFOUND = -1

    m.seek(0)
    headerMark = findValue
    loc = m.find(headerMark)
    if loc == NOTFOUND:
        return -1

    return loc

def writeEngineNameInBinary(in_filename, new_name):
    with open(in_filename, 'rb+') as f, contextlib.closing(mmap.mmap(f.fileno(), 0)) as m:
        find = exeNameHeader
        loc = findKeywordInMemory(m, find)
        if loc == -1:
            return False
        tmp = bytearray(str.encode(new_name))
        for i in range(len(tmp)):
            tmp[i] = tmp[i] ^ 6
        m[loc:loc+16] = tmp

def decrypt_file(in_filename, out_filename, chunksize=24 * 1024):
    with open(in_filename, 'rb') as infile:
        magicSize = struct.unpack('<L', infile.read(struct.calcsize('L')))[0]
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0] + magicSize
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

def encrypt_file(in_filename, out_filename=None, chunksize=24 * 1024):
    if not out_filename:
        new_name = ''.join([choice(ascii_lowercase) for _ in range(randint(16, 16))])
        writeEngineNameInBinary("PELoader.exe", new_name)
        out_filename = new_name

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open('./data/' + out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<L', 17490)) # MagicNumber 'RD'
            outfile.write(struct.pack('<Q', filesize))

            while True:
                chunk = readChunk(infile, chunksize)
                if chunk == 0:
                    break
                outfile.write(encryptor.encrypt(chunk))

def init():
    if not os.path.isfile('./data'):
        shutil.rmtree('./data')
    os.mkdir('./data')

if __name__ == '__main__':
    init()
    encrypt_file("calc.exe")
