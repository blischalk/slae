#!/usr/bin/python
'''
Author: Brett Lischalk
Title: Cycling Encoder
Description:
Cycles through a dword using the
lowest significant byte as the value to xor
a byte of shellcode with.
'''

# Set the dword you want to be your
# value to cycle through in encoder
encoder=0xdeadbeef
encoder_dirty=encoder
shellcode="\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

encoded=bytearray()
shellcode_bytes=bytearray(shellcode)

while len(shellcode_bytes) != 0:
  # when we have shifted our decoder to zero
  # we want to reset it to begin the cycle again
  if encoder_dirty == 0x00000000:
    encoder_dirty = encoder

  # get the first and rest of our shellcode
  f, r            = shellcode_bytes[0], shellcode_bytes[1:]
  #print "encoding: %x" % f
  b               = encoder_dirty & 0xff
  #print "b is: %x" % b
  result          = f ^ b
  #print "result: %x" % result
  # get the lowest significant byte of our decoder
  # xor the current shellcode byte
  # append it to our encoded shellcode
  encoded.append(result)

  # update our shellcode to be the shellcode
  # minus the first byte
  shellcode_bytes = r

  # shift off the lowest significant byte
  encoder_dirty   = encoder_dirty >> 8

# Format our bytes as hex for output
formatted = [hex(b) for b in encoded]

print "Shellcode Length: %s" % len(formatted)
print(",".join(formatted))
