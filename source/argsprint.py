#!/usr/bin/python3

import argparse
from pwn import *
from sys import exit

CLIG = '\x1b[1;29;1m'   # Blanc éclatant
CBRO = '\x1b[1;30;1m'   # Gris foncé / Brun
CRED = '\x1b[1;31;1m'   # Rouge
CVER = '\x1b[1;32;1m'   # Vert
CJAU = '\x1b[1;33;1m'   # Jaune
CBLE = '\x1b[1;34;1m'   # Bleu
CPUR = '\x1b[1;35;1m'   # Violet
CCYA = '\x1b[1;36;1m'   # Cyan
CEND = '\x1b[0m'

def printDone(STR):
    print(CVER + "[+] " + STR + CEND)
    exit(0)
def printError(STR):
    print(CRED + "[X] " + STR + CEND)
    exit(1)
def printInfo(STR):
    print(CPUR + "[I] " + STR + CEND)
def printLight(STR):
    print(CCYA + "[-] " + STR + CEND)
def printWarning(STR):
    print(CJAU + "[!] " + STR + CEND)

def persoInfoArch():
    CTHIN = '\x1b[1;32;0m'
    print(CVER + "\nInformations about --architecture option :" + CEND)
    print(CVER + "\t0 :" + CTHIN + " print this help and exit." + CEND)
    print(CVER + "\t1 :" + CTHIN + " the binary is a x86 binary launched in a 32 bits environment." + CEND)
    print(CVER + "\t2 :" + CTHIN + " the binary is a x86 binary launched in a 64 bits environment." + CEND)
    print(CVER + "\t3 :" + CTHIN + " the binary is a x86_64 binary launched in a 64 bits environment." + CEND)
    print(CVER + "\t4 :" + CTHIN + " the binary is an ARM binary launched in a 32 bits environment." + CEND)
    print(CVER + "\t9 :" + CTHIN + " the binary is a x64 binary launched in a 32 bits environment.\n" + CEND)
    exit(0)

def persoInfoDisplay():
    CTHIN = '\x1b[1;32;0m'
    print(CVER + "\nInformations about --architecture option :" + CEND)
    print(CVER + "\t0 :" + CTHIN + " print this help and exit." + CEND)
    print(CVER + "\t1 :" + CTHIN + " display all addresses or values." + CEND)
    print(CVER + "\t2 :" + CTHIN + " display Stack addresses." + CEND)
    print(CVER + "\t3 :" + CTHIN + " display Libc addresses." + CEND)
    print(CVER + "\t4 :" + CTHIN + " display Heap addresses." + CEND)
    print(CVER + "\t5 :" + CTHIN + " display Code addresses." + CEND)
    print(CVER + "\t6 :" + CTHIN + " display only user input.\n" + CEND)
    exit(0)


def checkParameters(es):

    parser      = argparse.ArgumentParser()
    talk        = parser.add_mutually_exclusive_group()
    target      = parser.add_mutually_exclusive_group() # J'ai retiré required=True, ce qui me permet de renvoyer un message d'erreur personnalisé.

    parser.add_argument("-a",   "--architecture",       help="indicate architecture and env ; use 0 to get more information", choices = [0, 1, 2, 3, 4, 9], default = 1, type=int)
    parser.add_argument("-nj",  "--no-junk",            help="do not use getJunk() function", action="store_true")
    #parser.add_argument("-o",  "--offset",             help="offset used for the format string payload", default = 1, type=int)
    parser.add_argument("-p",   "--pointed",            help="read pointed values (usei of %%s instead of %%x formater)", action="store_true")
    parser.add_argument("-rs",  "--reverse-syntax",     help="use reverse Format String syntax (Ex: %%5$x-AAAA instead of AAAA-%%5$x) ; recommended with --pointed (-p) option", action="store_true")
    #parser.add_argument("-t",  "--heap",               help="looking for heap addresses", action="store_true")
    parser.add_argument("-dt",  "--fine-display-tuning", help="only display specific addresses type", choices = [0, 1, 2, 3, 4, 5, 6], default = 1, type=int)
    parser.add_argument("-sp",  "--show-payload",       help="show payload before sending", action="store_true")
    parser.add_argument("-z",   "--pie",                help="use PIE adresses set", action="store_true")

    target.add_argument("-l", "--local",                help="start exploitation on a local binary, example: -l ~/BINARY", type=str)
    target.add_argument("-r", "--remote",               help="start exploitation on a remote service, example: -r HOST:PORT", type=str)

    parser.add_argument("-c",   "--close",              help="close the process and open a new one before sending a new payload", action="store_true")

    talk.add_argument("-d",     "--debug",              help="show debugging informations during execution", action="store_true")
    talk.add_argument("-s",     "--silent",             help="make pwntools silent", action="store_true")

    args = parser.parse_args()

    es.NOJUNK   = args.no_junk
    es.SP       = args.show_payload
    es.CLOSE    = args.close
    if es.CLOSE:
        es.OPENAGAIN = True

    if args.architecture == 0:          # Emplacement du bloc important sinon je me choppe l'erreur de -l / -r.
        persoInfoArch()
    else:
        es.ARCH = args.architecture
        if es.ARCH == 4:
            printInfo("ARM architecture option is not implemented yet")
            exit(2)

    if args.fine_display_tuning == 0:   # Emplacement du bloc important sinon je me choppe l'erreur de -l / -r.
        persoInfoDisplay()
    else:
        DFT = [2, 3, 4, 5, 6]
        if args.fine_display_tuning in DFT:
        #es.DT = args.fine_display_tuning
        #if es.ARCH == 4:
            printInfo("This option is not implemented yet")
            exit(2)

    if args.remote:
        es.REMOTE   = True
        IDs         = args.remote
        try:
            es.HOST = IDs.split(':')[0]
            es.PORT = int(IDs.split(':')[1], 10)
        except (IndexError, ValueError):
            printError("Wrong host/port")
    elif args.local:
        es.LOCAL    = True
        es.BIN      = args.local
    """else:
        printInfo("Use default configuration ; this can be configured in the script")
        es.LOCAL    = False
        es.BIN      = None
        es.REMOTE   = True
        es.HOST     = "challenge02.root-me.org"
        es.PORT     = 56003"""
    if not es.LOCAL and not es.REMOTE:      # Remplace le required=True
        printError("Error : -l (--local) or -r (--remote) parameter is required.")
        exit(2)

    if args.pointed:
        es.FMTCHAR = b"s"

    if args.silent:
        context.log_level='error'
    if args.debug:
        context.log_level='debug'


    #if args.offset:
    #    es.FSBOFF = args.offset








