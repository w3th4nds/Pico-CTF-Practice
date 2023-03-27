### Mod 26

The challenge provides this encoded string:

`cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_nSkgmDJE}`. 

It's `ROT13` encoded so we can decode it this way.

```python
#!/usr/bin/python3.8
import codecs

print(codecs.encode("cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_nSkgmDJE}", 'rot_13'))
```

```bash
➜  Crypotgraphy git:(main) ✗ python solver.py
picoCTF{XXX}
```

### 13

This is the exact same challenge that's why I added them together.

```python
#!/usr/bin/python3.8
import codecs

print(codecs.encode("cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}", 'rot_13'))
```

```bash
➜  Crypotgraphy git:(main) ✗ python solver.py
picoCTF{XXX}
```

### caesar

Download the file and get this ciphertext:

`picoCTF{gvswwmrkxlivyfmgsrhnrisegl}`.

The challenge already says it is `caesars cipher` so we will brute force it because we don't know the shift. 

```python
#!/usr/bin/python3.8

ciphertext = 'gvswwmrkxlivyfmgsrhnrisegl'

def decode(ciphertext, shift):
    plaintext = 'picoCTF{'
    for char in ciphertext:
        if char.isalpha():
            # shift the character back by the given shift
            plaintext += chr((ord(char) - shift - 65) % 26 + 65).lower()
        else:
            plaintext += char.lower()
    plaintext += '}'
    return plaintext

for i in range(26):
  print(decode(ciphertext, i))
```

From the output, only one line is readable.

```bash
picoCTF{mbyccsxqdrobelsmyxntxoykmr}
picoCTF{laxbbrwpcqnadkrlxwmswnxjlq}
picoCTF{kzwaaqvobpmzcjqkwvlrvmwikp}
picoCTF{jyvzzpunaolybipjvukqulvhjo}
picoCTF{ixuyyotmznkxahoiutjptkugin}
picoCTF{hwtxxnslymjwzgnhtsiosjtfhm}
picoCTF{gvswwmrkxlivyfmgsrhnrisegl}
picoCTF{furvvlqjwkhuxelfrqgmqhrdfk}
picoCTF{etquukpivjgtwdkeqpflpgqcej}
picoCTF{dspttjohuifsvcjdpoekofpbdi}
picoCTF{crossingtherubicondjneoach} <--- here
picoCTF{bqnrrhmfsgdqtahbnmcimdnzbg}
picoCTF{apmqqglerfcpszgamlbhlcmyaf}
picoCTF{zolppfkdqeboryfzlkagkblxze}
picoCTF{ynkooejcpdanqxeykjzfjakwyd}
picoCTF{xmjnndiboczmpwdxjiyeizjvxc}
picoCTF{wlimmchanbylovcwihxdhyiuwb}
picoCTF{vkhllbgzmaxknubvhgwcgxhtva}
picoCTF{ujgkkafylzwjmtaugfvbfwgsuz}
picoCTF{tifjjzexkyvilsztfeuaevfrty}
picoCTF{sheiiydwjxuhkrysedtzdueqsx}
picoCTF{rgdhhxcviwtgjqxrdcsyctdprw}
picoCTF{qfcggwbuhvsfipwqcbrxbscoqv}
picoCTF{pebffvatgurehovpbaqwarbnpu}
picoCTF{odaeeuzsftqdgnuoazpvzqamot}
picoCTF{nczddtyrespcfmtnzyouypzlns}
```
