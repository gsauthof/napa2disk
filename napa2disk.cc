// SPDX-License-Identifier: BSL-1.0
//
// 2021, Georg Sauthoff

#include "napatech.hh"
#include "linux.hh"

#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <stdio.h>

#include <unistd.h>
#include <time.h>          // clock_gettime()
#include <string.h>        // strerror()
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>
#include <linux/mman.h>    // MAP_HUGE_1GB
#include <sys/mman.h>
#include <fcntl.h>         // fallocate()
#include <sched.h>
#include <sys/un.h>

// for user space probes (USDT) which can be traced via
// bpf or other means
// NB: when nothing attaches to a probe than its overhead is
// literally executing a NOP instruction
#include <sys/sdt.h>       // DTRACE_PROBE1(), etc.


#include <nt.h>


#include "napa2disk.hh"



static sig_atomic_t globally_interrupted = 0;

static void int_handler(int)
{
    globally_interrupted = 1;
}

#if !NAPA2DISK_NDEBUG
static sig_atomic_t globally_wait = 0;

static void wait_handler(int)
{
    globally_wait = 1;
}
#endif

namespace nt {



    static void ntpl(NtConfigStream_t cfg, NtNtplInfo_t &h, const char *stmt)
    {
        int status = NT_NTPL(cfg, stmt, &h, NT_NTPL_PARSER_VALIDATE_NORMAL);
        if (status != NT_SUCCESS) {
            std::ostringstream o;
            o << status_to_str(status) << ": "
                << h.u.errorData.errBuffer[0] << ", "
                << h.u.errorData.errBuffer[1] << ", "
                << h.u.errorData.errBuffer[2];
            throw Error(o.str());
        }
    }

    class NTPL {
        public:
            NTPL(const char *stmt)
            {
                Config_Stream cfg("napa2disk_cfg");
                ntpl(cfg, h, stmt);
            }
            void close()
            {
                Config_Stream cfg("napa2disk_cfg");
                std::ostringstream o;
                o << "delete=" << h.ntplId;
                NtNtplInfo_t t;
                ntpl(cfg, t, o.str().c_str());
                done = true;
            }
            ~NTPL()
            {
                try {
                    if (!done)
                        close();
                } catch (const Error &e) {
                    // ignore
                }
            }
            NTPL(const NTPL &) =delete;
            NTPL &operator=(const NTPL &) =delete;
        private:
            NtNtplInfo_t h;
            bool done {false};
    };


    class Rx_Stream {
        public:
            Rx_Stream(const char *name,  NtNetInterface_e iface_type, uint32_t stream_id,
                    int host_buf_allowance)
            {
                int status = NT_NetRxOpen(&stream, name, iface_type, stream_id,
                        host_buf_allowance);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            ~Rx_Stream()
            {
                if (stream)
                    NT_NetRxClose(stream);
            }
            Rx_Stream(const Rx_Stream &) =delete;
            Rx_Stream &operator=(const Rx_Stream &) =delete;

            void close()
            {
                int status = NT_NetRxClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            void read(NtNetRx_t &cmd)
            {
                int status = NT_NetRxRead(stream, &cmd);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            // NB:
            // > In segment mode the waiting is always capped to the next
            // > HostBufferPollInterval (ntservice.ini), which is 100 usecs by
            // > default, at which point an empty segment is returned, if no data
            // > arrived. So in segment mode, any timeout larger than
            // > HostBufferPollInterval (including -1) has no effect.
            [[nodiscard]] int get(NtNetBuf_t &buf, int timeout_ms)
            {
                int status = NT_NetRxGet(stream, &buf, timeout_ms);
                if (status != NT_SUCCESS && status != NT_STATUS_TIMEOUT
                        && status != NT_STATUS_TRYAGAIN)
                    throw Error(status_to_str(status));
                return status;
            }
            void get_forever(NtNetBuf_t &buf, int timeout_ms)
            {
                int status = 0;
                for (;;) {
                    status = get(buf, timeout_ms);
                    if (status == NT_SUCCESS)
                        return;
                    if (status != NT_STATUS_TIMEOUT && status != NT_STATUS_TRYAGAIN)
                        throw Error("unknown status in netrxget ...");

                };
            }
            void release(NtNetBuf_t buf)
            {
                int status = NT_NetRxRelease(stream, buf);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
        private:
            NtNetStreamRx_t stream {0};
    };


}

// GCC defines it in some -std= settings
#ifdef linux
    #undef linux
#endif
namespace linux {

    static void clock_gettime(clockid_t clk_id, timespec &tp)
    {
        int r = ::clock_gettime(clk_id, &tp);
        if (r == -1)
            throw Error(errno_to_str("clock_gettime", errno));
    }

    static size_t strftime(char *s, size_t max, const char *format, const struct tm *tm)
    {
        size_t r = ::strftime(s, max, format, tm);
        if (!r)
            throw Error(errno_to_str("strftime", errno));
        return r;
    }
    inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
    {
        struct tm *r = ::gmtime_r(timep, result);
        if (!r)
            throw Error(errno_to_str("gmtime_r", errno));
        return r;
    }
    static struct tm *localtime_r(const time_t *timep, struct tm *result)
    {
        struct tm *r = ::localtime_r(timep, result);
        if (!r)
            throw Error(errno_to_str("localtime_r", errno));
        return r;
    }


    static int open(const char *pathname, int flags, mode_t mode)
    {
        int r = ::open(pathname, flags , mode);
        if (r == -1)
            throw Error(errno_to_str("open", errno));
        return r;
    }
    static void close(int fd)
    {
        int r = ::close(fd);
        if (r == -1)
            throw Error(errno_to_str("close", errno));
    }
    static void fallocate(int fd, int mode, off_t offset, off_t len)
    {
        int r = ::fallocate(fd, mode, offset, len);
        if (r == -1)
            throw Error(errno_to_str("fallocate", errno));
    }
    static void ftruncate(int fd, off_t length)
    {
        int r = ::ftruncate(fd, length);
        if (r == -1)
            throw Error(errno_to_str("ftruncate", errno));
    }


    static void io_setup(unsigned nr_events, aio_context_t *ctx)
    {
        int r = ::syscall(SYS_io_setup, nr_events, ctx);
        if (r == -1)
            throw Error(errno_to_str("io_setup", errno));
    }
    static void io_destroy(aio_context_t ctx)
    {
        int r = ::syscall(SYS_io_destroy, ctx);
        if (r == -1)
            throw Error(errno_to_str("io_destroy", errno));
    }
    static int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp)
    {
        int r = ::syscall(SYS_io_submit, ctx, nr, iocbpp);
        if (r == -1)
            throw Error(errno_to_str("io_submit", errno));
        return r;
    }
    static int io_getevents(aio_context_t ctx, long min_nr, long nr,
            struct io_event *events, struct timespec *timeout)
    {
        int r = ::syscall(SYS_io_getevents, ctx, min_nr, nr, events, timeout);
        if (r == -1)
            throw Error(errno_to_str("io_getevents", errno));
        return r;
    }

    static void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    {
      void *r = ::mmap(addr, length, prot, flags, fd, offset);
      if (r == MAP_FAILED)
          throw Error(errno_to_str("mmap", errno));
      return r;
    }

    static void sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
    {
        int r = ::sched_setaffinity(pid, cpusetsize, mask);
        if (r == -1)
            throw Error(errno_to_str("sched_setaffinity", errno));
    }

    static void nanosleep(const struct timespec *req, struct timespec *rem)
    {
        int r = ::nanosleep(req, rem);
        if (r == -1)
            throw Error(errno_to_str("nanosleep", errno));
    }

    static void setenv(const char *name, const char *value, int overwrite)
    {
        int r = ::setenv(name, value, overwrite);
        if (r == -1)
            throw Error(errno_to_str("setenv", errno));
    }

    static void rename(const char *oldpath, const char *newpath)
    {
        int r = ::rename(oldpath, newpath);
        if (r == -1)
            throw Error(errno_to_str("rename", errno));
    }

}




static uint32_t segment_ts_sec(NtNetBuf_t net_buf)
{
    uint32_t pcap_sec;
    // i.e. struct NtNetBufHdr_s*  == NtNetBufHdr_t;
    NtNetBufHdr_t p = NT_NET_GET_SEGMENT_PTR(net_buf);
    memcpy(&pcap_sec, p, sizeof pcap_sec);
    return pcap_sec;
}

static uint32_t pcap_caplen(const unsigned char *p)
{
    uint32_t x;
    // don't panic, the memcpy() gets optimized away
    memcpy(&x, p + 8, sizeof x);
    return x;
}
static uint32_t pcap_sec(const unsigned char *p)
{
    uint32_t x;
    memcpy(&x, p, sizeof x);
    return x;
}

static void forward_until(nt::Rx_Stream &rx, NtNetBuf_t &net_buf, timespec &now)
{
    for (;;) {
        rx.get_forever(net_buf, 1000);
        assert(NT_NET_GET_SEGMENT_TIMESTAMP_TYPE(net_buf) == NT_TIMESTAMP_TYPE_PCAP_NANOTIME);

        // TODO research wether accessing the first 8 PCAP-pkt-header timestamp bytes
        // through NT_NET_GET_SEGMENT_PTR() is ok, since the NT_NET_GET_SEGMENT_TIMESTAMP
        // macro is fair game even in empty segments
        //
        // However, we need to have this function forward to a non-empty segment,
        // anyways.
        size_t n = NT_NET_GET_SEGMENT_LENGTH(net_buf);
        if (!n) {
            rx.release(net_buf);
            continue;
        }

        if (segment_ts_sec(net_buf) > now.tv_sec)
            return;

        rx.release(net_buf);
    }
}


class Simple_File {
    public:
        Simple_File()
        {
        }
        ~Simple_File()
        {
            if (f)
                fclose(f);
        }
        Simple_File(const Simple_File &) =delete;
        Simple_File &operator=(const Simple_File &) = delete;

        void close()
        {
            if (f) {
                int r = fclose(f);
                if (r == -1)
                    throw linux::Error(linux::errno_to_str("fclose", errno));
                f = 0;
            }
        }
        void rotate(const char *filename)
        {
            if (f)
                close();
            f = fopen(filename, "wb");
            if (!f)
                throw linux::Error(linux::errno_to_str("fopen", errno));
        }
        void write(const void *buf, size_t n)
        {
            ssize_t l = fwrite(buf, 1, n, f);
            if (l < ssize_t(n))
                throw linux::Error(linux::errno_to_str("fwrite", errno));
        }
    private:
        FILE *f {0};
};

class Aio_File {
    public:
        Aio_File(unsigned io_depth = 4, unsigned block_shift_count = 18, unsigned sub_block_shift_count = 18, bool high_prio = false)
            :
                io_depth   (io_depth),
                block_size (1ul << block_shift_count),
                sub_block_size (1ul << sub_block_shift_count),
                shift_count(block_shift_count),
                sub_blocks(block_shift_count > sub_block_shift_count ? (1ul << (block_shift_count - sub_block_shift_count)) : 0),
                rw_flags(high_prio ? RWF_HIPRI : 0)
        {
            ring = static_cast<unsigned char*>(linux::mmap(0, ring_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_1GB,
                        -1, 0));
            p = ring;
            q = ring;

            in_flight.resize(ring_size >> shift_count);

            try {
                linux::io_setup(io_depth, &ctx);
            } catch (const linux::Error &e) {
                munmap(ring, ring_size);
                throw;
            }
        }
        ~Aio_File()
        {
            try {
                close();
                linux::io_destroy(ctx);
            } catch (const std::exception &e) {
                // ignore in destructor
            }
            munmap(ring, ring_size);
        }
        Aio_File(const Aio_File &) =delete;
        Aio_File &operator=(const Aio_File &) = delete;

        void close()
        {
            if (fd == -1)
                return;

            if (dirty)
                submit(p);
            if (submitted)
                reap_completions(submitted);

            linux::ftruncate(fd, off + dirty);
            dirty = 0;

            linux::close(fd);
            fd       = -1;
            p        = ring;
            q        = ring;
            ring_pos = 0;
            off      = 0;
        }
        void rotate(const char *filename)
        {
            close();
            fd = linux::open(filename, O_WRONLY | O_DIRECT | O_CREAT | O_TRUNC, 0644);

            size_t n = 10'000'000'000ul / ((60+20)*8) * (16 + 60) + 24;
            n += block_size - 1;
            n >>= shift_count;
            n <<= shift_count;

            // we use falloacte() instead of posix_fallocate() as the former
            // never tries to emulate it
            linux::fallocate(fd, 0, 0, n);
            // without fallocate(), io_submit() calls fall back to
            // synchronous operation
        }
        void write(const void *buf, size_t n)
        {
            if (ring_pos + n > ring_size) {
                size_t k      = ring_size - ring_pos;
                const unsigned char *b = static_cast<const unsigned char*>(buf);
                write(b    , k);
                write(b + k, n - k);
            } else {
                dirty    += n;
                ring_pos += n;
                unsigned blocks = dirty >> shift_count;
                preflight_check(dirty);
                q = static_cast<unsigned char*>(mempcpy(q, buf, n));
                for (unsigned i = 0; i < blocks; ++i) {
                    submit(p);
                    p     += block_size;
                    off   += block_size;
                    dirty -= block_size;
                }
                if (ring_pos == ring_size) {
                    assert(!dirty);
                    p        = ring;
                    q        = ring;
                    ring_pos = 0;
                }
            }
        }

        unsigned     full_reap_cnt {0};

    private:
        int    fd  {-1};
        size_t off {0};
        aio_context_t ctx           {0};
        struct iocb  io_request     {0};
        struct iocb *io_requests[1] { &io_request };
        // we don't use std::vector<bool> to avoid bit-mask operations
        std::vector<unsigned char> in_flight;
        unsigned char *ring        {0};
        unsigned       ring_size   {1024ul * 1024 * 1024};
        unsigned       ring_pos    {0};
        unsigned       io_depth    {4};
        unsigned       submitted   {0};
        unsigned       block_size  {256ul*1024};
        unsigned       sub_block_size  {256ul*1024};
        unsigned       shift_count {18};
        unsigned       sub_blocks  {0};
        int            rw_flags    {0};
        unsigned char *p           {0};
        unsigned char *q           {0};
        unsigned       dirty       {0};


        void reap_completions(unsigned min_no)
        {
            struct io_event evs[io_depth];
            int r = linux::io_getevents(ctx, min_no, io_depth, evs, 0);
            DTRACE_PROBE1(napa2disk, io-completed, r);
            if (!r)
                throw linux::Error("io_getevents didn't return any completion ...");

            // subtract before the loop in case we throw later have to close()
            // during destruction ...
            submitted -= r;
            for (int i = 0; i < r; ++i) {
                assert(evs[i].data < in_flight.size());
                in_flight[evs[i].data] = 0;

                if (evs[i].res < 0) {
                    std::stringstream o;
                    o << "Async write error: " << evs[i].res;
                    throw linux::Error(o.str());
                }
                if (size_t(evs[i].res) != block_size) {
                    std::stringstream o;
                    o << "partial async write: " << evs[i].res << " < " << block_size;
                    throw linux::Error(o.str());
                }
            }
        }

        // preflight_check() has to be called before submit()ing a sequence
        // of adjacent blocks
        void preflight_check(unsigned dirty)
        {
            unsigned k =            unsigned(p - ring) >> shift_count ;
            unsigned e = k + ((dirty + block_size - 1) >> shift_count);

            for (; k < e; ++k) {
                assert(k < in_flight.size());
                if (in_flight[k]) {
                    // NB: this is highly unlikely to happen even on the most loaded system
                    // if it happens something is seriously wrong
                    ++full_reap_cnt;
                    reap_completions(submitted);
                    return;
                }
            }
        }

        void submit(const void *x)
        {
            if (submitted >= io_depth)
                reap_completions(1);

            unsigned k = unsigned(static_cast<const unsigned char*>(x) - ring) >> shift_count;
            assert(k < in_flight.size());

            if (in_flight[k]) {
                // cf. preflight_check()
                throw linux::Error("block in use after check");
            } else {
                in_flight[k] = 1;
            }

            if (block_size > sub_block_size) {
                struct iovec ivs[sub_blocks];
                const char *p = static_cast<const char*>(x);
                for (size_t i = 0; i < sub_blocks; ++i) {
                    ivs[i].iov_base = const_cast<void*>(static_cast<const void*>(p));
                    ivs[i].iov_len = sub_block_size;
                    p             += sub_block_size;
                }
                io_request.aio_rw_flags   = rw_flags;
                io_request.aio_data       = k;
                io_request.aio_lio_opcode = IOCB_CMD_PWRITEV;
                io_request.aio_fildes     = fd;
                io_request.aio_buf        = reinterpret_cast<uintptr_t>(static_cast<void*>(ivs));
                io_request.aio_nbytes     = sub_blocks;
                io_request.aio_offset     = off;

                linux::io_submit(ctx, 1, io_requests);
            } else {
                io_request.aio_rw_flags   = rw_flags;
                io_request.aio_data       = k;
                io_request.aio_lio_opcode = IOCB_CMD_PWRITE;
                io_request.aio_fildes     = fd;
                io_request.aio_buf        = reinterpret_cast<uintptr_t>(x);
                io_request.aio_nbytes     = block_size;
                io_request.aio_offset     = off;

                linux::io_submit(ctx, 1, io_requests);
            }

            ++submitted;
        }
};


static uint32_t trunc_to_min(uint32_t s)
{
    return s / 60 * 60;
}

static void update_filename(char *filename, size_t n, const char *fmt, time_t epoche)
{
    time_t t = epoche;
    struct tm g;
    linux::localtime_r(&t, &g);
    linux::strftime(filename, n, fmt, &g);
}



struct PCAP_Header {
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    int32_t timezone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

static const char default_output_fmt[] = "%FT%TZ.pcap";

struct Args {
    int         stream_id         {-1};
    std::string output_fmt        {default_output_fmt};
    std::string partial_suffix    {".partial"};
    unsigned    sub_block_shift_count {17};
    unsigned    block_shift_count {20};
    bool        high_prio         {true};
    unsigned    io_depth          {16} ;
    int         core              {-1};
    int         core_off          {-1};
    bool        systemd           {false};
    bool        utc               {true};
    std::string uds_path;
    unsigned    snaplen           {10000};

    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " -s STREAM_ID -c CORE -f OUTPUT_FMT [OPT..]\n"
            "\n"
            "Options:\n"
            "  -C CORE_OFFSET          set affinity to CORE_OFFSET + STREAM_ID\n"
            "  -D                      integrate with systemd (i.e. notify etc.)\n"
            "  -H                      disable RWF_HIPRI write-flag (default: RWF_HIPRI is set)\n"
            "  -a SUB_SHIFT_COUNT      subblock size as shift-count\n"
            "                          (default: 17, i.e. 1<<17 == 128 KiB)\n"
            "  -b BLOCK_SHIFT_COUNT    write block size as shift-count\n"
            "                          (default: 20, i.e. 1<<20 == 1 MiB)\n"
            "  -c CORE                 CPU core number\n"
            "  -d IO_DEPTH             max #writes to issue concurrently (default: " << io_depth << ")\n"
            "  -f OUTPUT_FMT           output filename format string, cf. strftime(3) for\n"
            "                          a list of conversion specifiers\n"
            "                          (default: " << default_output_fmt << ")\n"
            "  -h                      this help text\n"
            "  -l                      use local time instead of UTC\n"
            "  -n SNAPLEN              PCAP file header snaplen (default: " << snaplen << ")\n"
            "  -s STREAM_ID            Napatech stream ID, usually port x -> stream x\n"
            "  -u UDS                  write filename of each rotated PCAP to unix domain socket (default: none)\n"
            "\n"
            "Notes:\n"
            "\n"
            "- this program rotates the capture files, the cleanup of old files is the job\n"
            "  of an external program such as `tmpwatch`\n"
            "- this program requires proper configuration of the Napatech adapter\n"
            "  and streamns, such as configuration of PCAP format, timestamps and buffers\n"
            "  cf. our napatech github repository\n"
            "\n"
            "2021-06-16, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '-' prefix: no reordering of arguments, non-option arguments are
        // returned as argument to the 1 option
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "-C:DHa:b:c:d:f:hln:s:u:")) != -1) {
            switch (c) {
                case '?':
                    {
                        std::ostringstream o;
                        o << "unexpected option : -" << char(optopt) << '\n';
                        throw std::runtime_error(o.str());
                    }
                    break;
                case 1:
                    {
                        std::ostringstream o;
                        o << "unexpected positional argument: " << optarg << '\n';
                        throw std::runtime_error(o.str());
                    }
                    break;
                case 'C':
                    core_off = atoi(optarg);
                    break;
                case 'D':
                    systemd = true;
                    break;
                case 'H':
                    high_prio = false;
                    break;
                case 'a':
                    sub_block_shift_count = atoi(optarg);
                    break;
                case 'b':
                    block_shift_count = atoi(optarg);
                    break;
                case 'c':
                    core = atoi(optarg);
                    break;
                case 'd':
                    io_depth = atoi(optarg);
                    break;
                case 'h':
                    help(std::cout, argv[0]);
                    exit(0);
                    break;
                case 'f':
                    output_fmt = optarg;
                    break;
                case 'l':
                    utc = false;
                    break;
                case 'n':
                    snaplen = atoi(optarg);
                    break;
                case 's':
                    stream_id = atoi(optarg);
                    break;
                case 'u':
                    uds_path = optarg;
                    if (uds_path.size() > 107)
                        throw std::runtime_error("UDS path too long");
                    break;
                default:
                    {
                        std::ostringstream o;
                        o << "sorry, unimplemented option: -" << char(optopt) << '\n';
                        throw std::runtime_error(o.str());
                    }
            }
        }
        output_fmt += partial_suffix;
        if (stream_id == -1)
            throw std::runtime_error("no stream_id specificed (cf. -s)");
        if (core_off != -1)
            core = core_off + stream_id;
        if (core == -1)
            throw std::runtime_error("no CPU core affinity specified (cf. -c)");
    }

};

template <typename File>
inline void rotate(char *filename, char *fin_filename, size_t n,
        const Args &args, const PCAP_Header &pcap_header, uint32_t sec,
        struct sockaddr_un *uds_addr, int uds_fd,
        File &f)
{
    char *t = stpcpy(fin_filename, filename);
    size_t m = t - fin_filename;
    size_t k = args.partial_suffix.size();
    if (m > k) {
        fin_filename[m - k] = 0;
        f.close();
        linux::rename(filename, fin_filename);
    }

    if (uds_fd != -1) {
        // deliberately ignoring errors
        sendto(uds_fd, fin_filename, m + 1, MSG_DONTWAIT,
                (struct sockaddr*) uds_addr, sizeof *uds_addr);
    }

    update_filename(filename, n, args.output_fmt.c_str(), sec);
    f.rotate(filename);
    f.write(&pcap_header, sizeof pcap_header);
}

static void move_to_core(unsigned core)
{
    cpu_set_t cores;
    CPU_ZERO(&cores);
    CPU_SET(core, &cores);
    linux::sched_setaffinity(0, sizeof cores, &cores);
}

static void setup_signal_handlers()
{
    struct sigaction sa = { 0 };
    sa.sa_handler = int_handler;
    for (auto i : { SIGINT, SIGTERM })
        linux::sigaction(i, &sa, 0);

#if !NAPA2DISK_NDEBUG
    {
        struct sigaction sa = { 0 };
        sa.sa_handler = wait_handler;
        linux::sigaction(SIGUSR1, &sa, 0);
    }
#endif
}

static void print_stats(FILE *f, const NtStatistics_t &stat_cmd, int stream_id, unsigned full_reap_cnt)
{
    const auto &d = stat_cmd.u.query_v3.data;

    fprintf(f, "%.2f MiB/s, %.2f mpkt/s",
            float(d.stream.streamid[stream_id].forward.octets)/1024.0/1024.0/60.0,
            float(d.stream.streamid[stream_id].forward.pkts)/1'000'000.0/60.0
           );

    if (d.stream.streamid[stream_id].drop.pkts)
        fprintf(f, "  dropped: %zu pkt, %zu bytes",
                d.stream.streamid[stream_id].drop.pkts,
                d.stream.streamid[stream_id].drop.octets
               );

    if (stream_id < d.port.numPorts) {
        const NtStatGroupport_v2_s &p = d.port.aPorts[stream_id];
        const auto &rx = p.rx;

        if (p.linkDownCounter)
            fprintf(f, "  link_down: %zu", p.linkDownCounter);

        // with the NT100A01 all the rmon1/extRMON/chksum/decode and extDrop are valid
        //
        if (rx.RMON1.dropEvents)
            fprintf(f, "  MAC_drop: %zu", rx.RMON1.dropEvents);
        if (rx.RMON1.crcAlignErrors)
            fprintf(f, "  crc_align_err: %zu pkt", rx.RMON1.crcAlignErrors);
        if (rx.RMON1.fragments)
            fprintf(f, "  fragments: %zu pkt", rx.RMON1.fragments);
        if (rx.RMON1.jabbers)
            fprintf(f, "  jabbers: %zu pkt", rx.RMON1.jabbers);
        if (rx.RMON1.collisions)
            fprintf(f, "  collisions: %zu", rx.RMON1.collisions);

        if (rx.extRMON.pktsHardSliceJabber)
            fprintf(f, "  hard_slice_jabber: %zu pkt", rx.extRMON.pktsHardSliceJabber);
        if (rx.extRMON.pktsCrc)
            fprintf(f, "  crc_err: %zu pkt", rx.extRMON.pktsCrc);
        if (rx.extRMON.pktsAlignment)
            fprintf(f, "  align_err: %zu pkt", rx.extRMON.pktsAlignment);
        if (rx.extRMON.pktsCodeViolation)
            fprintf(f, "  code_violation: %zu pkt", rx.extRMON.pktsCodeViolation);

        if (rx.chksum.pktsIpChkSumError)
            fprintf(f, "  ip_chksum_err: %zu pkt", rx.chksum.pktsIpChkSumError);
        if (rx.chksum.pktsUdpChkSumError)
            fprintf(f, "  udp_chksum_err: %zu pkt", rx.chksum.pktsUdpChkSumError);
        if (rx.chksum.pktsTcpChkSumError)
            fprintf(f, "  tcp_chksum_err: %zu pkt", rx.chksum.pktsTcpChkSumError);

        if (rx.extDrop.pktsMacBandwidth)
            fprintf(f, "  mac_bw_drop: %zu pkt", rx.extDrop.pktsMacBandwidth);
        if (rx.extDrop.pktsOverflow)
            fprintf(f, "  port_buf_ovf_drop: %zu pkt", rx.extDrop.pktsOverflow);
        if (rx.extDrop.pktsDedup)
            fprintf(f, "  dedup_drop: %zu pkt", rx.extDrop.pktsDedup);
        if (rx.extDrop.pktsNoFilter)
            fprintf(f, "  no_filter_drop: %zu pkt", rx.extDrop.pktsNoFilter);
        if (rx.extDrop.pktsFilterDrop)
            fprintf(f, "  filter_drop: %zu pkt", rx.extDrop.pktsFilterDrop);

    }

    if (full_reap_cnt)
        fprintf(f, " full_reaps: %u", full_reap_cnt);

    fprintf(f, "\n");
}


static void verify_adapter(unsigned port)
{
    nt::Info_Stream info("napa2disk_info");
    NtInfo_t req {
        .cmd  = NT_INFO_CMD_READ_PORT_V9,
        .u = { .port_v9 = { .portNo = uint8_t(port) } }
    };
    info.read(req);
    int a = req.u.port_v9.data.adapterNo;
    req = (NtInfo_t){
        .cmd = NT_INFO_CMD_READ_PROPERTY
    };
    snprintf(req.u.property.path, sizeof req.u.property.path,
            "Adapter%d.Filter.FlowMatch", a);
    info.read(req);
    if (req.u.property.data.u.i == 1) {
        fprintf(stderr, "WARNING: suboptimal FPGA image detected, load and activate the vanilla capture image, instead!\n");
        // i.e. such that most of the adapter's SDRAM can be used
        // for buffering incoming packets
    }
}

static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    move_to_core(args.core);
    setup_signal_handlers();
    if (args.utc)
        linux::setenv("TZ", "", 1);
    tzset();

    //Simple_File f;
    Aio_File f(args.io_depth, args.block_shift_count, args.sub_block_shift_count, args.high_prio);
    char filename[N2D_FILENAME_MAX] = {0};
    char fin_filename[N2D_FILENAME_MAX] = {0};
    PCAP_Header pcap_header = {
        .magic   = 0xa1b23c4d   , // pcap ns
        .major   = 2            ,
        .minor   = 4            ,
        .snaplen = args.snaplen , // maximum captured packet size
        .network = 1              // ethernet
    };

    nt::Library lib;

    verify_adapter(args.stream_id);

    // it's more robust to have the streams assigned outside
    // of this program, permanently.
    // That means the assignments are then always in a well-defined state,
    // even in case the capture program terminates abnormally.
    // nt::NTPL assign("Assign[streamid=1]=port==1");

    nt::Stat_Stream stats("napa2disk_stats");
    stats.reset();
    NtStatistics_t stat_cmd = {
        .cmd = NT_STATISTICS_READ_CMD_QUERY_V3,
        .u = {
            .query_v3 = {
                .poll  = 1,
                .clear = 1
            }
        }
    };
    size_t dropped_pkts  = 0;
    size_t dropped_bytes = 0;

    int stream_id = args.stream_id;
    nt::Rx_Stream rx("napa2disk", NT_NET_INTERFACE_SEGMENT, stream_id, -1);

    int uds_fd = -1;
    struct sockaddr_un uds_addr = {
        .sun_family = AF_LOCAL,
    };
    if (!args.uds_path.empty()) {
        uds_fd = linux::socket(AF_LOCAL, SOCK_DGRAM, 0);
        strcpy(uds_addr.sun_path, args.uds_path.c_str());
    }

    if (args.systemd) {
        linux::sd_notify(0, "READY=1");
        linux::sd_notify(0, "STATUS=forwarding stream");
    }

    NtNetBuf_t prev_net_buf = 0;

    timespec now;
    linux::clock_gettime(CLOCK_REALTIME, now);

    forward_until(rx, prev_net_buf, now);
    size_t n = NT_NET_GET_SEGMENT_LENGTH(prev_net_buf);
    // pre-condition for the next loop
    assert(n);
    DTRACE_PROBE1(napa2disk, segment-length, n);
    NtNetBufHdr_t seg_prev = NT_NET_GET_SEGMENT_PTR(prev_net_buf);
    unsigned char *p = reinterpret_cast<unsigned char*>(seg_prev);

    if (args.systemd)
        linux::sd_notify(0, "STATUS=capturing");

    uint32_t next_sec = 0;
    {
        uint32_t sec = trunc_to_min(pcap_sec(p));
        next_sec = sec + 60;
        update_filename(filename, sizeof filename, args.output_fmt.c_str(), sec);
        f.rotate(filename);
        std::cerr << "first rotate to: " << filename << '\n';
        f.write(&pcap_header, sizeof pcap_header);
    }
    NtNetBuf_t net_buf = 0;
    while (!globally_interrupted) {
#if !NAPA2DISK_NDEBUG
        if (globally_wait) {
            fprintf(stderr, "received SIGUSR1 - sleeping for 1 s ...\n");
            struct timespec ts = { .tv_sec = 1 };
            linux::nanosleep(&ts, 0);
            globally_wait = 0;
            fprintf(stderr, "received SIGUSR1 - sleeping for 1 s ... done\n");
        }
#endif
        rx.get_forever(net_buf, 1000 /* ms */);
        size_t m = NT_NET_GET_SEGMENT_LENGTH(net_buf);
        DTRACE_PROBE1(napa2disk, segment-length, m);
        if (m) {
            bool rotated = false;
            NtNetBufHdr_t seg = NT_NET_GET_SEGMENT_PTR(net_buf);
            unsigned char *q = reinterpret_cast<unsigned char*>(seg);

            uint32_t sec = pcap_sec(q);
            if (sec < next_sec) {
                f.write(p, n);
            } else {
                const unsigned char *begin = p;
                const unsigned char *end = begin + n;
                uint32_t k = 0;

                while (p < end) {
                    uint32_t l   = pcap_caplen(p);
                    uint32_t sec = pcap_sec(p);
                    if (sec >= next_sec) {
                        sec = trunc_to_min(sec);
                        if (k) {
                            f.write(begin, k);
                            k = 0;
                            begin = p;
                        }
                        rotate(filename, fin_filename, sizeof filename,
                                args, pcap_header, sec, &uds_addr, uds_fd, f);
                        std::cerr << "Rotate to: " << filename << '\n';
                        next_sec = sec + 60;
                        rotated = true;
                    }
                    k += 16 + l;
                    p += 16 + l;
                }
                if (k)
                    f.write(begin, k);

                uint32_t sec = pcap_sec(q);
                if (sec >= next_sec) {
                    sec = trunc_to_min(sec);
                    rotate(filename, fin_filename, sizeof filename,
                            args, pcap_header, sec, &uds_addr, uds_fd, f);
                    std::cerr << "Borderline rotate to: " << filename << '\n';
                    next_sec = sec + 60;
                    rotated = true;
                }

            }
            rx.release(prev_net_buf);
            prev_net_buf = net_buf;
            n = m;
            p = q;

            if (rotated) {
                stats.read(stat_cmd);
                print_stats(stderr, stat_cmd, stream_id, f.full_reap_cnt);
                if (f.full_reap_cnt)
                    f.full_reap_cnt = 0;
                dropped_pkts  += stat_cmd.u.query_v3.data.stream.streamid[stream_id].drop.pkts;
                dropped_bytes += stat_cmd.u.query_v3.data.stream.streamid[stream_id].drop.octets;
            }
        } else {
            rx.release(net_buf);
            net_buf = 0;
        }
    }

    if (args.systemd) {
        linux::sd_notify(0, "STATUS=done");
        linux::sd_notify(0, "STOPPING=1");
    }

    rx.release(prev_net_buf);
    f.close();

    fprintf(stderr, "TOTAL dropped: %zu pkts, %zu bytes\n", dropped_pkts, dropped_bytes);

    stats.close();
    return 0;
}

#if 0
// when just considering the first packet in a segment, the code is much simpler ...
//
            uint32_t sec = segment_ts_sec(net_buf);
            if (sec >= next_sec) {
                sec = trunc_to_min(sec);
                update_filename(filename, sizeof filename, "%FT%TZ.pcap", sec);
                f.rotate(filename);
                f.write(&pcap_header, sizeof pcap_header);
                last_sec = sec;
            }
            f.write(p, n);
#endif

int main(int argc, char **argv)
{
    try {
        return mainP(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
