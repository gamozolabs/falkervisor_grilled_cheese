# Falkervisor (grilled_cheese)

## History

This is the latest C version of my hypervisor and probably some of the best C code I've ever written (I've since switched to Rust, you should too). This was used roughly between 2015-2016, and replaced with a Rust version in late 2016.

## Building

Make sure you have `python`, `nasm`, `clang`, and `ld.lld` in your path. Then just type `python build.py`. Use `python build.py clean` to clean.

It builds on Windows easily with the following (however there are no hard reqs on versions):

```
C:\dev\grilled_cheese>clang --version
clang version 7.0.0 (trunk)
Target: x86_64-pc-windows-msvc
Thread model: posix
InstalledDir: C:\Program Files\LLVM\bin

C:\dev\grilled_cheese>python --version
Python 3.6.5

C:\dev\grilled_cheese>nasm --version
NASM version 2.13.03 compiled on Feb  7 2018

C:\dev\grilled_cheese>ld.lld --version
LLD 7.0.0 (compatible with GNU linkers)
```

You might see some files with `*.dc` extensions. This because the build system builds any `*.c` file in the tree, thus to disable things I wasn't using I just threw a `d` in the extension.

## Feature differences from brownie

See brownie here: https://github.com/gamozolabs/falkervisor_beta/

### Improvements over brownie

- It was written in C
- Networking code was greatly improved
- Kernel was portable to Intel (hypervisor not though)
- DHCPv4 is used for getting an IP, no more hardcoded packets
- Remote mapping of files
- Generic VM support, designed to in theory support AMD, Intel, etc from one API
- Many design features were made to reduce the chances of heisenbugs. Full page heap, full ASLR, strict mapping requirements really helped here
- RSTATE error model allowed for human readable call stacks on errors without worrying about unwind info, symbols, or inlining.

### Similarities to brownie

- Performance is about the same, there isn't room for growth in either tools
- Only supports x540 as a network device
- UDP only for networking
- Custom server for communicating over UDP

## Cool features

### Clang support

Early versions of my kernel used MSVC instead. Clang offers much better portability. By using `clang` and `ld.lld` this kernel is easily built on any system without special toolchain requirements. Further clang allows for inline assembly which is nice for kernel development, even though I keep usage to an absolute minimum.

### Remote mapping

The remote mapping `net_map_remote()` allows for files to be mapped over the network and faulted in only when they are used. For VMs this is used to map the entire ~4 GiB snapshot. Combined with CoW, this meant that only pages that were ever touched during a fuzz case were present in memory, and only one copy. If memory was ever written during a fuzz case then this memory might be duplicated to each core.

Typically for a medium size target (1-2 second fuzz case maximum), this meant usually no more than 2-4 MiB was used per VM. Leading to running 64 4GiB VMs with using only a few hundred MiB of RAM!

### Full ASLR

Every bit of every allocation is fully ASLRed. The kernel base and stacks are also fully ASLRed. This ASLR is 36-bits (meaning every bit that isn't a page offset is random). This means you'll get allocations in the `0xffff...` range and the `0x0000...` range.

### Page heap

All allocations are page heaped, their addresses are fully deleted from page tables on free and overflows and underflows can only corrupt data inside the structure itself.

### No identity/linear physical memory map

The machine I developed this for had 512 GiB of RAM. Most kernels have a linear mapping of ALL of physical memory somewhere in the kernel. When dealing with large amounts of memory this uses a huge amount of the virtual address space. This is not really a huge issue, however it makes it so there's a "decent chance" a random address might actually hit valid memory. This makes it possible for heisenbugs for things that "sometimes work".

Instead I use a design where the bootloader provides a 512-entry dynamic mapping mechanism. This consists of single page directory which is mapped at a random address. This means that using 4 KiB (PD) + 2 MiB of reserved page we are able to have a fast mechanism of accessing all physical memory. This greatly reduces the size of active addresses in the virtual address space, leaving more room for randomness and less chance of a random address hitting valid memory.

Performance is about 20% slower with this model over a linear mapping, which is really not that bad.

### Generic VM model

The VM model was starting to be designed to be more generic. This was going to allow for an Intel hypervisor being added while still using the same API for managing both. In this version there are actually 2 VM models, one for AMD's SVM, and another using user-VM. User VM was a made up VM model that makes a semi-isolated guest by using ring3 rather than a whole VM itself. This was great for things like JITs which needed a unique address space but I wanted to support on Intel.

### Rstate

You'll see that all error handling is done through `RSTATES`. This model allows for all errors to chain together the origin of the error all the way up to the top which paniced or handled it. This does not rely on symbols or unwind unwalking so it's much more simple. Further it works correctly regardless of optimization levels or inlining as the stack is managed in the C code itself. Getting clean errors out of this really helped keep code quality up and bug fix times to a minimum.

### Probably some other cool stuff I forgot about
