#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
from textwrap import wrap
import zlib

def get_icv(msg):
    icv = zlib.crc32(msg)
    return (icv.to_bytes(4, byteorder='little'), icv)


#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
message= b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
ICV = b'\xcc\x88\xcb\xb2'
IV = b'\x00\x00\x00'

# rc4 seed est composé de IV+clé
seed = IV+key
cipher = RC4(seed, streaming=False)

ciphertext = cipher.crypt(message + ICV)

print('Ciphertext: ' + ciphertext.hex())
# 8a04d7b44c14b88e294f62f2ac2f290b637a4d8e68575c05c46da60cdca7ebc23e2abf6cecb3fa23
#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]
arp.show()
# Message 1
msg = message[:len(message) // 3]
#msg = b"\xAA" * 16
icv, icv_int = get_icv(msg)
ciphertext = cipher.crypt(msg + icv)
#ciphertext = msg + b"\xBB" * 4
print("Message 1: %s" % msg)
print("Message 1: %s" % ciphertext)
print("Message 1: %s" % ciphertext.hex())
arp.iv = IV
arp.wepdata = ciphertext[:-4]
arp.icv = int.from_bytes(ciphertext[-4:], "little")
arp.FCfield = int.from_bytes(b'\x45', "big")
arp.SC = 0
arp.show()

wrpcap('arp3.cap', arp, append=False)  #

# Message 2
msg = message[len(message) // 3:len(message) // 3 * 2]
icv, icv_int = get_icv(msg)
print("Message 2: %s" % msg)
arp.wepdata = cipher.crypt(msg + icv)
arp.iv = IV
arp.icv = icv_int
arp.FCfield = int.from_bytes(b'\x45', "big")
arp.SC += 1

wrpcap('arp3.cap', arp, append=True)  #

# Message 3
msg = message[len(message) // 3 * 2:]
icv, icv_int = get_icv(msg)
print("Message 3: %s" % msg)
arp.wepdata = cipher.crypt(msg + icv)
arp.iv = IV
arp.icv = icv_int
arp.FCfield = int.from_bytes(b'\x41', "big")
arp.SC += 1
wrpcap('arp3.cap', arp, append=True)  #
