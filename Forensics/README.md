### information

Download the file and check its info with `exiftool`.

```console
exiftool cat.jpg                                                                                       ✭
ExifTool Version Number         : 12.40
File Name                       : cat.jpg
Directory                       : .
File Size                       : 858 KiB
File Modification Date/Time     : 2023:10:18 01:48:48+03:00
File Access Date/Time           : 2023:10:18 01:49:21+03:00
File Inode Change Date/Time     : 2023:10:18 01:49:09+03:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Current IPTC Digest             : 7a78f3d9cfb1ce42ab5a3aa30573d617
Copyright Notice                : PicoCTF
Application Record Version      : 4
XMP Toolkit                     : Image::ExifTool 10.80
License                         : cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9
Rights                          : PicoCTF
Image Width                     : 2560
Image Height                    : 1598
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2560x1598
Megapixels                      : 4.1
```

We see a strange string at `License`. Try to `base64` decode it and get the flag.

```bash
exiftool cat.jpg | grep License | awk '{print $3}' | base64 -d
```

### tunn3l v1s10n

Download the file and run `xxd` on it.

```bash
xxd tunnel | head -n 20                                                                          ✹ ✭
00000000: 424d 8e26 2c00 0000 0000 bad0 0000 bad0  BM.&,...........
00000010: 0000 6e04 0000 3201 0000 0100 1800 0000  ..n...2.........
00000020: 0000 5826 2c00 2516 0000 2516 0000 0000  ..X&,.%...%.....
00000030: 0000 0000 0000 231a 1727 1e1b 2920 1d2a  ......#..'..) .*
00000040: 211e 261d 1a31 2825 352c 2933 2a27 382f  !.&..1(%5,)3*'8/
00000050: 2c2f 2623 332a 262d 2420 3b32 2e32 2925  ,/&#3*&-$ ;2.2)%
00000060: 3027 2333 2a26 382c 2836 2b27 392d 2b2f  0'#3*&8,(6+'9-+/
00000070: 2623 1d12 0e23 1711 2916 0e55 3d31 9776  &#...#..)..U=1.v
00000080: 668b 6652 996d 569e 7058 9e6f 549c 6f54  f.fR.mV.pX.oT.oT
00000090: ab7e 63ba 8c6d bd8a 69c8 9771 c193 71c1  .~c..m..i..q..q.
000000a0: 9774 c194 73c0 9372 c08f 6fbd 8e6e ba8d  .t..s..r..o..n..
000000b0: 6bb7 8d6a b085 64a0 7455 a377 5a98 6f56  k..j..d.tU.wZ.oV
000000c0: 7652 3a71 523d 6c4f 406d 5244 6e53 4977  vR:qR=lO@mRDnSIw
000000d0: 5e54 5339 3370 5852 7661 5973 5f54 7e6b  ^TS93pXRvaYs_T~k
000000e0: 5e86 7463 7e6a 5976 6250 765e 4c7a 6250  ^.tc~jYvbPv^LzbP
000000f0: 876d 5d83 6959 8d73 639b 8171 9e84 7498  .m].iY.sc..q..t.
00000100: 7e6e 9b81 718d 7363 735a 4a70 5747 5a41  ~n..q.scsZJpWGZA
00000110: 314f 3626 4e37 274f 3828 4f38 2851 3a2a  1O6&N7'O8(O8(Q:*
00000120: 5039 294f 3829 4b35 2950 3a2f 4b35 2a3f  P9)O8)K5)P:/K5*?
00000130: 291e 422e 234b 372c 4531 263f 2b20 432f  ).B.#K7,E1&?+ C/
```

As we can see from the [Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) of the file, it was supposed to be a `.bmp` file. 

When we `display` the file, we see this:

![](../assets/tunnel.png)

Now, to fix the whole image, we need to change its extension but also change some things on the header.

![](../assets/bitmap.png)

As we can see, at offset `0x16`, we have the `height` of the `.bmp`. 

With `hexedit`, we tamper with the `height` of the image. Trying to change it from `0x1` to `0x3` worked perfectly.

Before:

```console
xxd tunnel.bmp | head -n 20                                                                          ✹ ✭
00000000: 424d 8e26 2c00 0000 0000 bad0 0000 bad0  BM.&,...........
00000010: 0000 6e04 0000 3201 0000 0100 1800 0000  ..n...2.........
```

After:

```
xxd tunnel.bmp | head -n 20                                                                          ✹ ✭
00000000: 424d 8e26 2c00 0000 0000 bad0 0000 bad0  BM.&,...........
00000010: 0000 6e04 0000 3203 0000 0100 1800 0000  ..n...2.........
```

![](../assets/final_tunnel.png)

### Matryoshka doll

We download the file and see that it's an image.

```bash
file dolls.jpg                                                                              
dolls.jpg: PNG image data, 594 x 1104, 8-bit/color RGBA, non-interlaced
```

As the challenge name suggests, we will extract any given files with `binwalk` using the `-M` option. From the `help` page of `binwalk`:

> Binwalk v2.3.3
> Craig Heffner, ReFirmLabs
> https://github.com/ReFirmLabs/binwalk
>
> Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
>
> Disassembly Scan Options:
>     -Y, --disasm                 Identify the CPU architecture of a file using the capstone disassembler
>     -T, --minsn=<int>            Minimum number of consecutive instructions to be considered valid (default: 500)
>     -k, --continue               Don't stop at the first match
>
> Signature Scan Options:
>     -B, --signature              Scan target file(s) for common file signatures
>     -R, --raw=<str>              Scan target file(s) for the specified sequence of bytes
>     -A, --opcodes                Scan target file(s) for common executable opcode signatures
>     -m, --magic=<file>           Specify a custom magic file to use
>     -b, --dumb                   Disable smart signature keywords
>     -I, --invalid                Show results marked as invalid
>     -x, --exclude=<str>          Exclude results that match <str>
>     -y, --include=<str>          Only show results that match <str>
>
> Extraction Options:
>     -e, --extract                Automatically extract known file types
>     -D, --dd=<type[:ext[:cmd]]>  Extract <type> signatures (regular expression), give the files an extension of <ext>, and execute <cmd>
>     -M, --matryoshka             Recursively scan extracted files

We run this command and successfully read `flag.txt` and remove all the unnecessary directories.

```bash
binwalk -e -M dolls.jpg && clear; find ./ -type f -name "flag.txt" -exec cat {} \; && rm -rf _dolls*
```

### Glory of the Garden

Download the file and run `strings` to get the flag.

```bash
strings garden.jpg | grep pico                                                                       ✹ ✭
Here is a flag "picoCTF{XXX}"
```