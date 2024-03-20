#!/bin/sh
if [ -z "$1" ] ; then
    echo "usage: $0 image-file"
    exit -1
fi
mmls -a "$1" |egrep '^[0-9]+:' | while read line
do
    slot=$(echo $line|awk '{print $2}')
    start=$(echo $line|awk '{print $3}'|sed -e 's/^0*//')
    length=$(echo $line|awk '{print $5}'|sed -e 's/^0*//')
    echo "Decrypting $slot"
    dd if="$1" bs=512 skip=${start} count=${length} | ./dsdecrypt - slot_${slot}.img
done
