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