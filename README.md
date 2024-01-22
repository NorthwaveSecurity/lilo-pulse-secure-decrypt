# About

This tool decrypts encrypted partitions as used by the LILO based Pulse Secure appliances. These are the olders models, recent ones boot using GRUB and make use of LUKS for disk encryption.

# Building

Have OpenSSL installed with development headers.

```
$ make
```

The tool uses deprecated OpenSSL functions causing some warnings to show up. These can be ignored.

# Usage

The `dsdecrypt` tool acts on the single partitions. It detects the correct key by decrypting the first sector and checking if it contains all zeroes.
If no valid key is found, no decryption takes place.
You can force decryption by manually specifying a key using `-k`.

A script called `dump_all.sh` is provided which uses `mmls` (part of sleuthkit) and `dd` to pipe all partitions on an image file through the decrypter.

## Dump entire image

```
$ ./dump_all.sh /path/to/pulse-secure.img
```

## Decrypt single partition

```
$ ./dsdecrypt /path/to/partition.img decrypted_partition.img
```

# Key extraction

Keys were most easily extracted by using a decompiler tool and checking into the `loop_setup_root` function.
An easy way to locate this function is to allow the kernel to panic on a missing root disk. It will show the `RIP`/`EIP` value in the stacktrace.
Alternativately you can also check out /proc/kallsyms on a running system to get the address for `loop_setup_root` and `DS_KERNEL_AESKEY`. The latter holds the xor-obfuscated key.

In order to get the decompressed ELF image from the kernel files you can use the `extract-linux` script from the kernel source.
Checking out the `loop_setup_root` function in Ghidra or Binary Ninja will show you the deobfuscated key, they both their constant folding magic.

## Factory reset kernel

For the factory reset image the `extract-linux` script did not work. Whatever is decompressed is not a valid ELF file.
Also this kernel is a 32-bit build, where the others were x64-64.

From the x86-64 kernels we know that the key is set in the `loop_setup_root` root function.
So in order to find it we boot the image in QEMU using a drive type not supported by the configuration.
This will cause the kernel to panic inside the loop_setup_root, yielding the instruction pointer at time of crash.
By also enabling the gdb port in QEMU we can attach gdb and use it to inspect the code and memory contents.

By browing through the code looking for four consecutive xor operations we quickly find the code below:

```
   0xc0236890:	mov    $0xc049dbac,%esi
   0xc0236895:	lea    -0x1c(%rbp),%eax
   0xc0236898:	mov    %eax,%edi
   0xc023689a:	movsl  %ds:(%rsi),%es:(%rdi)
   0xc023689b:	movsl  %ds:(%rsi),%es:(%rdi)
   0xc023689c:	movsl  %ds:(%rsi),%es:(%rdi)
   0xc023689d:	movsl  %ds:(%rsi),%es:(%rdi)
   0xc023689e:	xorl   $0x99ed2bf2,-0x1c(%rbp)
   0xc02368a5:	xorl   $0xaeef41fe,-0x18(%rbp)
   0xc02368ac:	xorl   $0x141058c7,-0x14(%rbp)
   0xc02368b3:	xorl   $0xd2ed180e,-0x10(%rbp)
```

This code loads 16 bytes from 0xc049dbac onto the stack and xors them with 4 immediate values.

Inspecting the 16 bytes loaded onto the stack:

```
(gdb) x/16b 0xc049dbac
0xc049dbac:	0xd7	0xee	0xf6	0x44	0x61	0xe5	0xfb	0xdd
0xc049dbb4:	0x84	0x80	0xa7	0x79	0xcd	0x8d	0x93	0x68
```

Manually performing the xor operations we get a key which does indeed decrypt the factory-reset partition, unlocking all its mysteries.
