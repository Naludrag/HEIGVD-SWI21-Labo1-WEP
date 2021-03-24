#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually fragment a wep message and encrypt it with a given WEP key"""

__author__ = "Robin Müller and Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2021, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib
from scapy.layers.dot11 import RadioTap


def get_icv(msg):
    """
      Calculate the ICV of a given message
    """
    icv = zlib.crc32(msg)
    return icv.to_bytes(4, byteorder='little')


def fragment(msg, n):
    """
      Yield n fragments from message.
    """
    chunkLen = len(msg) // n
    for i in range(0, len(msg), chunkLen):
        yield msg[i:i + chunkLen]


# The number of fragments (w/ the current message, possible values are 1, 2, 3, 4)
NB_FRAGMENTS = 3

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
# Message that will be fragmentated. We chose to use the ARP packet from the example
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
# Chosen IV for RC4 in our case the IV 0
IV = b'\x00\x00\x00'

# Initialize RC4 with the seed that is composed of the IV and the key
seed = IV + key
cipher = RC4(seed, streaming=False)

# Read the packet from the template file to have a template structure for the message
arp = rdpcap('arp.cap')[0]

""" Send the fragments """
fragments = list(fragment(message, NB_FRAGMENTS))
for i in range(0, NB_FRAGMENTS):  # Fragment the message
    msg = fragments[i]
    # Calculate the icv with CRC
    icv = get_icv(msg)
    # Encrypt the message and the ICV
    ciphertext = cipher.crypt(msg + icv)
    # Put the encrypted data in the wepdata of the packet. Remove the last 4 bytes because it is the encrypt ICV
    arp.wepdata = ciphertext[:-4]
    # Set the IV used
    arp.iv = IV
    # Put the ICV in the packet. The ICV is in the last four bytes of the encrypted message.
    # The value is also put in a little endian way to be readable
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
    # Remove the RadioTap value of the length of the packet to recalculate it. If not use the packet will keep
    # the value len of the template and wireshark will not succeed to read the fragment
    arp[RadioTap].len = None
    # If this is the last part ot the message in our case the third round we disable the More Fragment flag otherwise
    # we enable the bit
    arp.FCfield.MF = i < (NB_FRAGMENTS - 1)
    # As i will start at 0 it will follow the value of the SC (counter of fragments)
    arp.SC = i
    # To delete the content of arp-manual-fragmentation.cap if the file exists
    if i == 0:
        wrpcap('arp-manual-fragmentation.cap', arp, append=False)
    else:
        wrpcap('arp-manual-fragmentation.cap', arp, append=True)
    print("--Fragment " + str(i + 1) + "--")
    print('Text: ' + fragments[i].hex())
    print('Ciphertext: ' + ciphertext[:-4].hex())
