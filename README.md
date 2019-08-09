# Wireless Networks and Security

## WEP Security

__Please work in teams of 3 students__

__Korean/Swiss hybrid teams are highly encouraged__

## Authors : Aygerim Bilyalova, Mickael Bonjour, Rachel Gan

### For this first part, you will need to:

* Understand how to __manually__ decrypt WEP frames using Python and Scapy 
* __Manually__ encrypt WEP frames using Python and Scapy, based on a decryption script
* Are you fast enough? Forge WEP protected fragments in order to obtain a keystream larger than 8 bytes


You will need Scapy but __not__ the Alfa interfaces this time. Please refer to the [MAC Security Lab](https://github.com/arubinst/SU19-WLANSec-Lab1-MAC) for important information about Monitor Mode, Python, Scapy, WiFi interfaces, etc.


## Your Work

### 1. Manually Decrypt WEP

In this part, you will recover the Python script [`manual-decryption.py`](./files/manual-decryption.py) (sorry... Python 2.7 only... the code hasn't been updated to Python 3). You will also need the capture file [`arp.cap`](./files/arp.cap) containing a WEP encrypted ARP message and the library [`rc4.py`](./files/rc4.py) to generate the keystreams needed in order to encrypt/decrypt WEP. All the files need to be copied to the same local folder on your machine.

- Open the capture file [`arp.cap`](./files/arp.cap) with Wireshark
   
- Use Wireshark to decrypt the file. For this, you will need to configure in Wireshak the WEP key. (In Wireshark : Preferences&rarr;Protocols&rarr;IEEE 802.11&rarr;Decryption Keys). You will also need to activate decryption in the IEEE 802.11 window (« Enable decryption »). You will find the WEP key in the Python Script [`manual-decryption.py`](./files/manual-decryption.py).
   
- Execute the script with `python manual-decryption.py`
   
- Compare the output of the script with the capture text decrypted by Wireshark
   
- Analyse the code of the script



### 2. Manual Encryption of WEP

Using the script [`manual-decryption.py`](./files/manual-decryption.py) as a guide, create a new script `manual-encryption.py` capable of encrypting a message and saving it to a pcap file so that it could be sent to an AP our a receiving STA.

So, basically, you will need to:

1. Create your message
2. Calculate the Integrity Control (ICV)
3. Encrypt the message (see the [`manual-decryption.py`](./files/manual-decryption.py) script and the theory slides for details)
4. Save the message to a pcap


### Some Details to Make your Life Easier:

- __THIS IS STRONGLY RECOMMENDED__: You may use the same original arp frame as "template" for your forged frame. Consider it an "empty" shell that you can fill up with your own data. The advantage is that this "shell" already has many parameters configured that would otherwise be hard to configure manually. You will need (at least) to update the data field (`wepdata`) and the integrity control field (`icv`). Optionally, you coud change the MAC adresses and other fields, but it is not required for this exercise. 
- The field `wepdata` accepts data in __text__ format.
- The field `icv` is a long int.
- Use the original script as a guide for the different format conversions that might be necessary. Take into account that you may have to do some of them in reverse.
- Export your new frame in pcap format using Scapy and then, read it in Wireshark. If Wireshark is capable of decrypting your forged frame, then you did a good job!
- Format conversion will be your __nightmare__. If your script doesn't work (Wireshark does not decrypt your frame), it will most probably be because of the way you calculated or you encoded the ICV. Typical problems are the __endianness__ and the __format__. Try to understand what the original script does. 


### 3. Fragmentation (Bonus assignment)

In this part, you will enhance your script in order to encrypt 3 fragments.

Using your `manual-encryption.py` script, you will write a new one `encrypt-fragments.py` capable of encrypting a long message by fragmenting the payload and encrypting at least 3 fragments. You could actually write a "general" tool that generates as many fragments as requested in the command line.

### Some Details to Make your Life Easier:

- Every fragment is numbered. The first frame of a sequence of fragments is always fragment number 0. A whole frame (without fragmentation) also carries the fragment number 0.
- To increase the fragment counter, you can use the frame field "SC". For exemple : `frame.SC += 1`
- All fragments except the last one carry the bit `more fragments` with a value of 1, to indicate that a new fragment will be received.
- The field containing the "more fragments" bits is available in Scapy within the `FCfield` field. You will need to manipulate this field for your fragments. This same field is visible in Wireshark in IEEE 802.11 Data &rarr; Frame Control Field &rarr; Flags
- To verify that this part works, you may import your fragments in Wireshark. It must be able to recompose the original frame, if you did a good job.
- Try a long message. Short messages tend to fail. You can actually encrypt the same message in each fragment (so that Wireshark should show the message 3 times in a row).


## Deliverablesi

### Screen of decrypted data
![Wireshark decrypting our packet](./files/wireshark-decrypted.png)

Fork of the original repo. Then, a Pull Request containing : :

- The names of the students. You can add this to the ```README.md```
- WEP encryption script __extensively commented/documented__
  - pcap file generated by your script containing the encrypted frame
  - Screen grab of your frame imported and decrypted by Wireshark
-	Bonus: Fragmentation script __extensively commented/documented__
  - pcap file generated by your script containing the encrypted fragments
  - Screen grab of your frames imported and decrypted by Wireshark 
