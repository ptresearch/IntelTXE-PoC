#!/usr/bin/env python
# Decryptor for OpenIPC configuration by Mark Ermolov (@_markel___)
#                                        Maxim Goryachy (@h0t_max)
#
# Details:  https://github.com/ptresearch/IntelME-JTAG
#           https://github.com/ptresearch/IntelTXE-POC
from time import gmtime, strftime
import os
import sys
import struct
import shutil
import zipfile

from argparse import ArgumentParser as argpars
from Crypto.Cipher import AES
from Crypto.Hash import SHA as sha1

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3


def create_backup(paths):
    archiveName = strftime("OpenIPC_backup_%Y%m%d_%H%M%S.zip", gmtime())
    zip = zipfile.ZipFile(archiveName, 'w', zipfile.ZIP_DEFLATED)
    for path in paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                zip.write(os.path.join(root, file))
    zip.close()

def decrypt_path(name):
    decryptName  = ""
    counter = 0
    for c in name:
        if   c == '_':
            decChar = ord('?')
        elif c == '-':
            decChar = ord('>')
        elif c == '\\' or c == '.':
            decryptName += c
            counter = 0
            continue
        elif c <= '9':
            decChar = ord(c) - ord('0')
        elif c <= 'Z':
            decChar = ord(c) - ord('7')
        elif c <= 'z':
            decChar = ord(c) - ord('=')

        counter += 1
        decChar = counter ^ decChar ^ 0xA

        if   decChar == ord('?'):
            decChar = ord('_')
        elif decChar == ord('>'):
            decChar = ord('-')
        elif decChar >= ord('$') and decChar <= ord('='):
            decChar = decChar + ord('=')
        elif decChar >= ord('\n') and decChar <= ord('#'):
            decChar = decChar + ord('7')
        elif decChar <= ord('\t'):
            decChar = decChar + ord('0')
        else:
            decChar = ord(c)
            counter = 0
        decryptName += chr(decChar)
    return decryptName

def copy_dir(srcPath, dstPath):
    for item in os.listdir(srcPath):
        src = os.path.join(srcPath, item)
        dst = os.path.join(dstPath, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, False, None)
        else:
            shutil.copy2(src, dst)
 
class Decryptor:
    IVLEN = 16
    KEYLEN = 32
    COUNT = 5
    def __init__(self, key):
        self.iv, self.key = self.__bytes_to_key(key)

    def __bytes_to_key(self, key):
        d = ""
        hashStr = ""
        while len(hashStr) <= self.IVLEN + self.KEYLEN:
            sha = sha1.new()
            sha.update(d+key)
            d = sha.digest()
            for i in xrange(self.COUNT-1):
                sha = sha1.new()
                sha.update(d)
                d = sha.digest()
            hashStr += d
        key = hashStr[0:self.KEYLEN]
        iv = hashStr[self.KEYLEN:self.KEYLEN+self.IVLEN]
        return iv, key

    def __decrypt(self, cipherText):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.decrypt(cipherText)

    def __remove_padding(self, plainText):
        plainSize = len(plainText)
        paddingSize = ord(plainText[-1])
        return plainText[:plainSize-paddingSize]

    def decrypt_data(self, cipherText):
        plainText = self.__decrypt(cipherText)
        return self.__remove_padding(plainText)


class BinXMLParser:    
    def __init__(self, decrypt):
        self.decrypt = decrypt

    def __offsetDetect(self):
        signature = self.data[0:8][::-1]
        self.offset = 0
        if signature == "Not DAL!":
            self.offset = 8

    def __read_bytes(self, size):
        result = self.data[self.offset:self.offset+size]
        self.offset += size
        return result

    def __read_int(self):
        val, = struct.unpack_from('<L', self.__read_bytes(4))
        return val

    def __read_byte(self):
        val, = struct.unpack_from('<B', self.__read_bytes(1))
        return val

    def __read_strings(self):
        self.__offsetDetect()
        stringsCount = self.__read_int()
        assert len(self.data) > stringsCount
        self.strings  = []
        for i in xrange(stringsCount):
            strlen = self.__read_int()
            str = self.__read_bytes(strlen)
            self.strings.append(str)

    def __get_item(self, level=0):
        tagName = self.strings[self.__read_int()]
        attr = self.__read_byte()
        self.xml += "  "*level
        self.xml += "<" + tagName
        val = ""
        if attr & 1:
                self.__read_int()
        if attr & 2:
                val = self.strings[self.__read_int()]
                val = val.lstrip().rstrip()
        if attr & 4:
                attrs_count = self.__read_int()
                attrs_dict = {}
                for i in xrange(attrs_count):
                    attrName = self.strings[self.__read_int()]
                    attrVal = self.strings[self.__read_int()]
                    if self.decrypt and attrName == "Path":
                        attrVal= decrypt_path(attrVal)
                    self.xml += " " + attrName + '="' + attrVal + '"'
        if attr & 8:
                self.xml += ">\n";
                childCount = self.__read_int()
                for i in xrange(childCount):
                    self.__get_item(level+1)

        if val != "":
            self.xml += ">\n" + "  "*(level+1) + val +"\n"
            self.xml += "  "*level + "</" + tagName + ">\n"
        else:
            if attr & 8:
                self.xml += "  "*level + "</" + tagName + ">\n"
            else:
                self.xml += "/>\n"

    def __xmlBuild(self):
        self.xml = ""
        self.__get_item()
        return  self.xml

    def parse(self, binData):
        self.offset = 0
        self.data = binData
        self.__read_strings()
        return self.__xmlBuild()


class IPCDecryptor:
    FORBIDIRNAME = ["Python", "enhancements", "__pycache__"]
    def __init__(self, path, key):
        self.path = path
        if (not os.path.exists(os.path.join(path, "Data", "Index.bin")) or
                not os.path.exists(os.path.join(path, "Config", "Index.bin"))):
            print ("Error: {} isn't OpenIPC root directory\n".format(path))
            exit(-1)
        self.dec = Decryptor(key.decode("hex"))
    
    def __decrypt_file(self, fileName):
        f = open(fileName, "rb")
        cipherText = f.read()
        f.close()
        assert len(cipherText) != 0
        plainText = self.dec.decrypt_data(cipherText)
        os.remove(fileName)
        return plainText
    
    def __decrypt_xml(self, fileName,  newFileName, decryptPath):
        plainText = self.__decrypt_file(fileName)
        binXML = BinXMLParser(decryptPath)
        xml = binXML.parse(plainText)
        f = open(newFileName, "wb")
        f.write(xml)
        f.close
        
    def __decrypt_py(self, fileName,  newFileName):
        plainText = self.__decrypt_file(fileName)
        f = open(newFileName, "wb")
        f.write(plainText)
        f.close
        
    def __decrypt_directory(self, path, name):
        fullPath = os.path.join(path,name)
        for item in os.listdir(fullPath):
            if os.path.isdir(os.path.join(fullPath, item)):
                if not (item in self.FORBIDIRNAME):
                    decryptName = decrypt_path(item)
                    if decryptName=="Python":
                        if not self.skipPython:
                            copy_dir(os.path.join(fullPath, item),
                                     os.path.join(fullPath, decryptName))
                            shutil.rmtree(os.path.join(fullPath, item))
                            self.__decrypt_directory(fullPath, decryptName)
                    else:
                        os.rename(os.path.join(fullPath, item),
                                  os.path.join(fullPath, decryptName))
                        self.__decrypt_directory(fullPath, decryptName)

            else:
                decryptName = decrypt_path(item)
                extension = os.path.splitext(decryptName)[1]
                if extension == ".xml" or extension == ".xsd":
                    self.__decrypt_xml(os.path.join(fullPath, item),
                                       os.path.join(fullPath, decryptName),
                                       False)
                elif not self.skipPython  and extension == ".py":
                    self.__decrypt_py(os.path.join(fullPath, item),
                                      os.path.join(fullPath, decryptName))

    def decrypt_files(self, noBackup, python):
        self.skipPython = python==False
        if not noBackup:
            create_backup([os.path.join(self.path, "Config"),
                           os.path.join(self.path, "Data")])
        self.__decrypt_xml(os.path.join(self.path, "Config", "Index.bin"),
                           os.path.join(self.path, "Config", "Index.xml"),
                           False)
        self.__decrypt_xml(os.path.join(self.path, "Data", "Index.bin"),
                           os.path.join(self.path, "Data", "Index.xml"),
                           True)
        self.__decrypt_directory(self.path, "Data")


def parse_arguments():
    pars = argpars(description='Decryptor for OpenIPC configuration')
    pars.add_argument('-p', help='path', type=str, default="OpenIPC")
    pars.add_argument('-nb', help="don't create backup", action="store_true")
    pars.add_argument('-k', help='AES key', type=str, required=True)
    pars.add_argument('-python', help='Decrypt Python files', action="store_true")
    return ( pars.parse_args().p,
             pars.parse_args().k,
             pars.parse_args().nb,
             pars.parse_args().python )
    
def main():
    path, key, noBackup, python = parse_arguments()
    decryptor = IPCDecryptor(path, key)
    decryptor.decrypt_files(noBackup, python)

if __name__ == "__main__":
    main()
