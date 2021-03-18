#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Robin Müller and Stéphane Teixeira Carvalho"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib
from scapy.layers.dot11 import RadioTap


def get_icv(message):
    """
      Get the ICV of a given message
    """
    icv = zlib.crc32(message)
    return icv.to_bytes(4, byteorder='little')


# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
# Message that will be fragmentated. We choose to use the ARP packet from the example
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
# Choosen IV for RC4 in our case the IV 0
IV = b'\x00\x00\x00'

# Send the rc4 seed composed by the IV and the key
seed = IV + key
cipher = RC4(seed, streaming=False)

# Read the packet from the template file to have a template structure for the message
arp = rdpcap('arp.cap')[0]

""" Send the fragments """
for i in range(0, 3):
    # Slice the message in 3 parts here we will take the first part of it
    msg = message[:len(message) // 3]
    # In the second round take the second part of the message
    if i == 1:
        msg = message[len(message) // 3:len(message) // 3 * 2]
    # In the third round take the third part of the message
    elif i == 2:
        msg = message[len(message) // 3 * 2:]
    # Calculate the icv with CRC
    icv = get_icv(msg)
    # Encrypt the message and the ICV
    mes = cipher.crypt(msg + icv)
    # Put the encrypted data in the wepdata of the packet. Remove the last 4 bytes because it is the encrypt ICV
    arp.wepdata = mes[:-4]
    # Set the IV used
    arp.iv = IV
    # Put the ICV in the packet. The ICV is in the last four bytes of the encrypted message.
    # The value is also put in a little endian way to be readable
    arp.icv = struct.unpack('!L', mes[-4:])[0]
    # Remove the RadioTap value of the length of the packet to recalculate it
    arp[RadioTap].len = None
    # If this is the last part ot the message in our case the third round we disable the More Fragment flag otherwise
    # we enable the bit
    arp.FCfield.MF = i < 2
    # As i will start at 0 it will follow the value of the SC (counter of fragments
    arp.SC = i
    # To delete the content of arp3.cap if the file exists
    if i == 0:
        wrpcap('arp3.cap', arp, append=False)
    else:
        wrpcap('arp3.cap', arp, append=True)
