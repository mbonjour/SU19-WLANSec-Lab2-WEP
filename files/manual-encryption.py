#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]

# The rc4 seed is composed by the IV+key
seed = arp.iv+key 

# We ask the user to enter some data to encrypt into the wepdata of the arp packet
data = raw_input("What is the data you want to send ? max. 36b\n")


#We need 36bytes of data for Wireshark to print it correctly
data = data[:36].ljust(36)

# We get the ICV from the CRC32 of the data that the user entered. And apply some conversion for Wireshark to understand it.
# We convert it to little endian using struct.pack so we can encrypt it correctly
# This conversion is requiered by the rc4 implementation we are using.

icv = crc32(data)
icv = icv & 0xffffffff

icv_encoded=struct.pack('<L', icv)

# CLear text including the icv. That's the manner to encrypt the ICV and data from the same keystream.
message = data + icv_encoded

# Encryption using rc4
cipher = rc4.rc4crypt(message,seed)  
print("Encrypted data (cleartext + ICV)" + cipher.encode("hex"))

# The ICV the last 4 bytes - I convert it to Long big endian using unpack
icv_encrypted=cipher[-4:]
(icv_numerique,)=struct.unpack('!L', icv_encrypted)

# The payload is the messge minus the 4 last bytes
text_encrypted=cipher[:-4] 

# We put the data on the packet and the ICV too

arp.wepdata = text_encrypted
arp.icv = icv_numerique
# We finally construct our forged packet
wrpcap('arp2.cap', arp)

print 'Encrypted Message: ' + text_encrypted.encode("hex")
print 'Encrypted icv (hex):  ' + icv_encrypted.encode("hex")
print 'Numerical value of icv (encrypted): ' + str(icv_numerique)
