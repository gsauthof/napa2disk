This README documents some implementation details and design
decisions of the napa2disk project.


## RAII and Wrappers

Napa2disk is written in C++ and heavily makes use of [RAII][raii]
(Resource Acquisition Is Initialization) to avoid resource leaks
and simplify setup, tear-down and error handling.

Thus, the Napatech C-only API is thinly wrapped in C++ classes,
where appropriate. See for example the `nt::Rx_Stream` class
defined in `napa2disk.cc` that thinly wraps `NtNetStreamRx_t`.

When such wrappers are only used in one translation unit, they
are only defined locally, otherwise, when shared, they are
defined in `napatech.cc` (declared in `napatech.hh`) and
`linux.hh`.


## Error Handling

Errors are handled via exceptions to make the code more robust
(i.e. less tedious and error-prone, it's harder to ignore errors
that way) and less convoluted by boilerplate return code checks.

Thus, used C-only API functions (Napatech SDK, Linux and POSIX
APIs) are thinly wrapped in error checking and exception throwing
stub functions. SEe for example `linux::sd_notify()` defined in
`linux.hh`.

Again, when such wrappers are only used in one translation unit,
they are defined there locally, otherwise in the `napatech.hh`
and `linux.hh` headers.


## Napatech Documentation

The Napatech documentation is quite extensive and well-written.
And the best thing is that it's freely available on the Internet.

Other vendors who hide their mediocre documentation behind
annoying account-walls or paywalls could learn from that.

The starting point is:

https://docs.napatech.com/r/Reference-Documentation

Good starting point is then the Streams Section.


## Segments

To make packet capturing efficient, napa2disk uses the segment
interface of the RX network stream API. That means the NIC
FPGA processes incoming frames into segments of a few hundred
kilobytes which are transferred into host memory.
Each segment is basically a vector of PCAP records, i.e. the FPGA
also inserts a proper PCAP record header before each frame.

In contrast, normal NICs transfer frame by frame. Some other NICs
also support bulk transport, but can't add PCAP record headers.
Also, normal NICs usually don't guarantee any particular ordering
in the received frames.

Thus, most of the time napa2disk just needs to write a complete
segment, as-is to disk, which of course is very efficient.

It gets a little bit more involved at the start of a minute
where PCAP files have to be rotated (the old one has to be
truncated, renamed, a new one has to be opened, a PCAP file
header has to be written, etc.).

Also, at the start of a minute a segment has to be scanned to
partition it into the parts that goe into the previous and next
minute PCAP file. IOW, the first frame of the next minute has to
be located.


## Buffering

Since napa2disk uses Linux Async Direct IO, it has to write
properly aligned and full blocks. Thus, it can't directly write
segments.

Instead it copies segments into a ring buffer (cf. `Aio_File`) from
which properly sized blocks are written.

That ring buffer uses a 1 GiB HugePage to save some TLB entries
and thus minimizing the number of TLB misses.

NB: even current CPUs don't have many TLB slots for 1 GiB pages
per core, but we just need one per core for this.


## Async IO

Napa2disk uses Async IO for performance reasons such that modern
NVMe SSD devices are properly utilized.

As a consequence, multiple IO operations can be in-flight and the
process isn't blocked by each IO operation but is able to
concurrently proceed with its operation.

Unfortunately, the Linux Async IO is much underdocumented.

Recent Linux have the very nice `io_uring` async IO API.
However, Redhat only added it to RHEL 9.3 while we were
targeting first RHEL 7.9 and then 8.7.
Thus, your napa2disk author used what was available: Linux Async
API.

NB: The Linux Async API has many limitations. Most notably it
only really is async when using it for Direct IO!

For readers wondering why not simply write into memory-mapped
PCAP files the napa2disk author has a paper recommendation:

https://db.cs.cmu.edu/mmap-cidr2022/

```
@inproceedings{crotty22-mmap,
  author = {Crotty, Andrew and Leis, Viktor and Pavlo, Andrew},
  title = {Are You Sure You Want to Use MMAP in Your Database Management System?},
  booktitle = {{CIDR} 2022, Conference on Innovative Data Systems Research},
  year = {2022},
}
```

## Tracing

For profiling and inspection, napa2disk defines several userspace
probes. Search for the `DTRACE_PROBE*` macros.

At runtime, when not activated, their overhead is effectively nil
since they are basically NOP instructions which only get patched
when the probed is actually traced.

Although the macro names remind of `dtrace` they can be used with
modern Linux tools such as `perf`.


## Testing

For testing purposes, the napa2disk process can be put to sleep
for one second by sending it a `SIGUSR1` signal.

Even when capturing at line-rate, the on-card and host-buffers
are dimensioned large enough that no frames are lost that way.

Since the NVMe SSDs are very fast and even part of a RAID-0,
the buffers are quickly drained when resuming after that second.


## Capture Buffers

The Napatech NT100A01 SmartNIC has 8 GiB on-card RAM which
can be evenly divided between the 4 capture ports. It's used for
buffering incoming packets and outgoing segments.

From there the NIC bulk-transfers segments into host buffers.
Again, each capture port has its own host buffer.
The size is freely configurable and currently it's set to 512 MiB
each.

Finally, napa2disk itself buffers incoming segments into its 1
GiB sized ring buffer (cf. Section Buffering), while they
submitted and not yet completed in the IO device queues.

In each buffering stage, the segments or blocks are released as
soon they reach the next stage.

Because of this buffering architecture the capture process is
robust against short interruptions.


## BUGS

- napa2disk isn't [2038][2038] safe due to the fact that the
  standard PCAP format only uses 4 bytes for the epoche seconds
  field. Thus, before 2038, we have to switch to a different
  capture file format/PCAP variant (that is also supported by the
  capture NIC FPGA image).


## Build Instructions


Dependencies:

- GCC g++ >= 11
- systemd-devel
- systemtap-sdt-devel or `gcc-toolset-${GCC_REL}-systemtap-sdt-devel` when using a toolset
- [nt-driver-3gd-devel and nt-driver-3gd](https://supportportal.napatech.com/index.php?/selfhelp/categories/link-capture-software-linux/139)


Build everything in tree:

    make


[2038]: https://en.wikipedia.org/wiki/Year_2038_problem
[raii]: https://en.cppreference.com/w/cpp/language/raii
