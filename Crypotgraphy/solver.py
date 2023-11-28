#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
from Crypto.Util.number import inverse

r = remote('jupiter.challenges.picoctf.org', 1981)

def get_flag():
  pause(1)
  r.sendline('cat flag*')
  success(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')

# Round 1
r.recvuntil('q : ')
p = int(r.recvline().strip())
r.recvuntil('p : ')
q = int(r.recvline().strip())

r.sendlineafter(':', 'y')
r.sendline(f'{p*q}') # 4636878989

# Round 2
r.recvuntil('p : ')
q = int(r.recvline().strip())

r.recvuntil('n : ')
n = int(r.recvline().strip())

r.sendlineafter(':', 'y')
r.sendline(f'{int(n/q)}') # 93089

# Round 3
r.sendlineafter('(Y/N):', 'n')

# Round 4
r.recvuntil('q : ')
p = int(r.recvline().strip())
r.recvuntil('p : ')
q = int(r.recvline().strip())
r.sendlineafter(':', 'y')
r.sendline(f'{(p-1)*(q-1)}')

# Round 5
r.recvuntil('plaintext : ')
pt = int(r.recvline().strip())
r.recvuntil('e : ')
e  = int(r.recvline().strip())
r.recvuntil('n : ')
n = int(r.recvline().strip())
r.sendlineafter(':', 'y')
r.sendline(f'{pow(pt, e, n)}')

# Round 6
r.sendlineafter('(Y/N):', 'n')

# Round 7
r.recvuntil('q : ')
q = int(r.recvline().strip())
r.recvuntil('p : ')
p = int(r.recvline().strip())
r.recvuntil('e : ')
e  = int(r.recvline().strip())
r.sendlineafter(':', 'y')
phi_n = (p - 1) * (q - 1)
r.sendline(f'{pow(e, -1, phi_n)}')
context.log_level = 'debug'

# Round 8
r.recvuntil('p : ')
p = int(r.recvline().strip())
p = 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
r.recvuntil('ciphertext : ')
ct = int(r.recvline().strip())
ct = 18031488536864379496089550017272599246134435121343229164236671388038630752847645738968455413067773166115234039247540029174331743781203512108626594601293283737392240326020888417252388602914051828980913478927759934805755030493894728974208520271926698905550119698686762813722190657005740866343113838228101687566611695952746931293926696289378849403873881699852860519784750763227733530168282209363348322874740823803639617797763626570478847423136936562441423318948695084910283653593619962163665200322516949205854709192890808315604698217238383629613355109164122397545332736734824591444665706810731112586202816816647839648399
r.recvuntil('e : ')
e  = int(r.recvline().strip())
e = 65537
r.recvuntil('n : ')
n = int(r.recvline().strip())
n = 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289
q = int(n/p)


r.sendlineafter(':', 'y')
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
r.sendline(f'{pow(ct, d, n)}')
# print(f'p: {p}\ne: {e}\nn: {n}\nct: {ct}')
# print(f'LEL: {pow(ct, d, n)}')

# picoCTF{FREQUENCY_IS_C_OVER_LAMBDA_AGFLCGTYUE}


r.interactive()