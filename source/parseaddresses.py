#!/usr/bin/python3

from pwn import flat
from argsprint import CLIG, CBRO, CRED, CVER, CJAU, CBLE, CPUR, CCYA, CEND


def codePrint(i, ADR):
    print(CBLE + "[{0}] Code address :   0x0{1}".format(i, ADR) + CEND)
def heapPrint(i, ADR):
    print(CBRO + "[{0}] Heap address :   0x{1}".format(i, ADR) + CEND)
def inputPrint(i, ADR):
    print(CVER + "[{0}] User input :     0x{1}".format(i, ADR) + CEND)
def libcPrint(i, ADR):
    print("[{0}] Libc address :   0x{1}".format(i, ADR))
def stackPrint(i, ADR):
    print(CCYA + "[{0}] Stack address :  0x{1}".format(i, ADR) + CEND)


def parseAdresse32(architecture, pie, i, ADR):

    if architecture == 1:

        if len(ADR) == 8 and ADR[0] == 'b' and ADR[1] == 'f':
            stackPrint(i, ADR)
            return
        elif len(ADR) == 8 and ADR[0] == 'b' and ADR[1] == '7':
            libcPrint(i, ADR)
            return

    elif architecture == 2:
    
        if len(ADR) == 8 and ADR[0] == 'f' and ADR[1] == 'f':
            stackPrint(i, ADR)
            return
        elif len(ADR) == 8 and ADR[0] == 'f' and ADR[1] == '7':
            libcPrint(i, ADR)
            return

    if not pie:
        if len(ADR) >= 6 and ADR[0] == '8' and ADR[2] == '4':
            codePrint(i, ADR)
            return
    else:
        if len(ADR) >= 6 and ADR[0] == '5' and (ADR[1] == '5' or ARD[1] == '6'):
            codePrint(i, ADR)
            return

    if len(ADR) >= 4 and "4141" in ADR:
        inputPrint(i, ADR)
        return


def parseAdresse64(es, i, ADR):
    # todo
    exit("TODO")
