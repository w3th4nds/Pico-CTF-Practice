#!/usr/bin/python3.8
from pwn import *
import os
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'critical'

# Open the file
f = open('pass.txt', 'r')
pw = f.read().split('==')
f.close()

for i in pw:
  print(i)

