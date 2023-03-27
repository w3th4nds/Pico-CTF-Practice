#!/bin/bash

flag1="picoCTF{"
flag2=$(sed -n "s/.*'\(.\)'.*/\1/gp" "pass.txt")
flag3="}"

echo "Flag --> $flag1$flag2$flag3" | tr -d "\n"