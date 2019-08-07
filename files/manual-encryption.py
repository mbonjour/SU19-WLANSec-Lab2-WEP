#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = ""
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]
# The rc4 seed is composed by the IV+key
seed = arp.iv+key 

data = raw_input("What is the data you want to send ? max. 36b\n")
#arp.wepdata = data
data = data.ljust(36)
#  arp.dst
# = raw_input("Destination address Currently : " + arp.dst)
#arp.dst = 

# I recover the ICV from the message (arp.icv). This is a long integer
# Wireshark likes to show this number in hex. And even if Wireshark knows the correct key and
# can decrypt the ICV, it will show the encrypted version only.

# I convert the icv to hex using '{:x}.format and then to it's ascii representation using decode("hex")
# This conversion is requiered by the rc4 implementation we are using.

icv = crc32(data)
icv = icv & 0xffffffff

icv_encoded=struct.pack('<L', icv)

print(icv)
print(icv_encoded.encode("hex"))

#print 'icv as shown by Wireshark (encrypted): '+'{:x}'.format(arp.icv)

# Encrypted text including the icv. You need to produce this if you want to decrypt the ICV

message = data + icv_encoded
print(message)

# Decryption using rc4
cipher = rc4.rc4crypt(message,seed)  
print(cipher.encode("hex"))

# The ICV the last 4 bytes - I convert it to Long big endian using unpack
icv_encrypted=cipher[-4:]
(icv_numerique,)=struct.unpack('!L', icv_encrypted)

# The payload is the messge minus the 4 last bytes
text_encrypted=cipher[:-4] 

arp.wepdata = text_encrypted
arp.icv = icv_numerique
wrpcap('arp2.cap', arp)

print 'Encrypted Message: ' + text_encrypted.encode("hex")
print 'Encrypte icv (hex):  ' + icv_encrypted.encode("hex")
print 'Numerical value of icv: ' + str(icv_numerique)
