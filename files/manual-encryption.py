#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Robin Müller and Stéphane Teixeira Carvalho"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib


def get_icv(msg):
    """
      Calculate the ICV of a given message
    """
    icv = zlib.crc32(msg)
    return icv.to_bytes(4, byteorder='little')


# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
# Message that will be sent (ARP Who has 192.168.1.200? Tell 192.168.1.100)
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
# IV that we set at 0 in our case
IV = b'\x00\x00\x00'

# rc4 seed that is composed of the IV and the key
seed = IV+key
# Initialize the RC4 cipher with the seed
cipher = RC4(seed, streaming=False)
# Encrypt the message and the icv using the encrypt method of RC4
ciphertext = cipher.crypt(message + get_icv(message))

# Read the current packet in the wireshark capture to get a template structure
arp = rdpcap('arp.cap')[0]
# Add the ciphertext to the wepdata part of the packet we remove the four last bytes because it is the cipher icv
arp.wepdata = ciphertext[:-4]
# Add the iv used in the packet
arp.iv = IV
# Add the ICV to our packet as said before we send the cipher ICV so the four last bytes of our cypher text
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

# Write the arp packet encrypted in the wireshark file
wrpcap('arp2.cap', arp, append=False)
