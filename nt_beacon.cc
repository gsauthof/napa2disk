// SPDX-License-Identifier: BSL-1.0
//
// 2022, Georg Sauthoff


#include "napatech.hh"
#include "linux.hh"

#include <array>
#include <deque>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h> // inet_pton()
#include <assert.h>
#include <signal.h>    // sigaction(), ...
#include <stdlib.h>    // atoi(), exit(), ...
#include <sys/epoll.h> // epoll_create1(), ...
#include <sys/utsname.h> // uname()
#include <unistd.h>    // getopt(), ...



struct Args {
    uint32_t    port_mask         {0xf};
    bool        systemd           {false};
    std::string mcast_cfg_filename;
    unsigned    join_window_s     {10};


    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " [OPT..]\n"
            "\n"
            "Options:\n"
            "  -D                      integrate with systemd (i.e. notify etc.)\n"
            "  -p PORT_MASK            enable LLDP on all ports that match this bitmask\n"
            "                          (default: " << port_mask << ")\n"
            "  -i IGMP_CONFIG          IGMP join configuration file (default: none)\n"
            "  -w SECONDS              IGMP response window to distribute joins over (default: " << join_window_s << ")\n"
            "\n"
            "2022-06-22, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '-' prefix: no reordering of arguments, non-option arguments are
        // returned as argument to the 1 option
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "-Dhi:t:w:")) != -1) {
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
                case 'D':
                    systemd = true;
                    break;
                case 'h':
                    help(std::cout, argv[0]);
                    exit(0);
                    break;
                case 'i':
                    mcast_cfg_filename = optarg;
                    break;
                case 'p':
                    port_mask = atoi(optarg);
                    break;
                case 'w':
                    join_window_s = atoi(optarg);
                    break;
                default:
                    {
                        std::ostringstream o;
                        o << "sorry, unimplemented option: -" << char(optopt) << '\n';
                        throw std::runtime_error(o.str());
                    }
            }
        }
    }
};


#ifdef linux
    #undef linux
#endif
namespace linux {

    inline void inet_pton(int af, const char *src, void *dst)
    {
        int r = ::inet_pton(af, src, dst);
        if (!r)
            throw Error("inet_pton: invalid IP address -> " + std::string(src));
        if (r == -1)
            throw Error(errno_to_str("inet_pton", errno));
    }

    inline int epoll_create1(int flags)
    {
        int r = ::epoll_create1(flags);
        if (r == -1)
            throw Error(errno_to_str("epoll_create1", errno));
        return r;
    }
    inline void epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
    {
        int r = ::epoll_ctl(epfd, op, fd, event);
        if (r == -1)
            throw Error(errno_to_str("epoll_ctl", errno));
    }

    inline int epoll_wait(int epfd, struct epoll_event *events,
            int maxevents, int timeout)
    {
        int r = ::epoll_wait(epfd, events, maxevents, timeout);
        if (r == -1 && errno != EINTR)
            throw Error(errno_to_str("epoll_wait", errno));
        return r;
    }

    inline void uname(struct utsname *buf)
    {
        int r = ::uname(buf);
        if (r == -1)
            throw Error(errno_to_str("uname", errno));
    }

}


namespace nt {

    class Tx_Stream {
        public:
            Tx_Stream(const char *name, uint64_t portMask, uint32_t NUMA,
                    uint32_t minHostBufferSize)
            {
                int status = NT_NetTxOpen(&stream, name, portMask, NUMA,
                        minHostBufferSize);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            ~Tx_Stream()
            {
                if (stream)
                    NT_NetTxClose(stream);
            }
            Tx_Stream(const Tx_Stream &) =delete;
            Tx_Stream &operator=(const Tx_Stream &) =delete;

            void close()
            {
                int status = NT_NetTxClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            void read(NtNetTx_t &cmd)
            {
                int status = NT_NetTxRead(stream, &cmd);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }

            [[nodiscard]] int get(NtNetBuf_t &buf, uint32_t port, size_t packetSize,
                    enum NtNetTxPacketOption_e packetOption, int timeout_ms)
            {
                int status = NT_NetTxGet(stream, &buf, port, packetSize,
                        packetOption, timeout_ms);
                if (status != NT_SUCCESS && status != NT_STATUS_TIMEOUT
                        && status != NT_STATUS_TRYAGAIN)
                    throw Error(status_to_str(status));
                return status;
            }
            void get_forever(NtNetBuf_t &buf, uint32_t port, size_t packetSize,
                    enum NtNetTxPacketOption_e packetOption,int timeout_ms)
            {
                int status = 0;
                for (;;) {
                    status = get(buf, port, packetSize,
                            packetOption, timeout_ms);
                    if (status == NT_SUCCESS)
                        return;
                    if (status != NT_STATUS_TIMEOUT && status != NT_STATUS_TRYAGAIN)
                        throw Error("unknown status in netrxget ...");

                };
            }
            void release(NtNetBuf_t buf)
            {
                int status = NT_NetTxRelease(stream, buf);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
        private:
            NtNetStreamTx_t stream {0};
    };
}



enum class LLDP {
    CHASSIS   = 1,
    PORT      = 2,
    TTL       = 3,
    PORT_DESC = 4,
    SYS_NAME  = 5,
    SYS_DESC  = 6
};

static unsigned char lldp_type(LLDP t)
{
    unsigned char x = static_cast<unsigned char>(t);
    x <<= 1;
    return x;
}

static size_t mk_lldp(unsigned char *b, unsigned char *end,
        const unsigned char *mac_addr, unsigned char adapter, unsigned char port,
        const char *sys_name, const char *sys_desc)
{
    auto begin = b;
    if (b + 14 > end)
        throw std::runtime_error("buffer overflow - eth header");
    const unsigned char dest_addr[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
    b = static_cast<unsigned char*>(mempcpy(b, dest_addr, sizeof dest_addr));
    b = static_cast<unsigned char*>(mempcpy(b, mac_addr, 6));
    const unsigned char proto[] = { 0x88, 0xcc };
    b = static_cast<unsigned char*>(mempcpy(b, proto, sizeof proto));

    if (b + 9 > end)
        throw std::runtime_error("buffer overflow - chassis");
    *b++ = lldp_type(LLDP::CHASSIS);
    *b++ = 7;
    *b++ = 4; // MAC address
    b = static_cast<unsigned char*>(mempcpy(b, mac_addr, 6));

    if (b + 4 > end)
        throw std::runtime_error("buffer overflow - port");
    *b++ = lldp_type(LLDP::PORT);
    *b++ = 2;
    *b++ = 7; // Locally assigned
    *b++ = '0' + port;

    if (b + 4 > end)
        throw std::runtime_error("buffer overflow - ttl");
    *b++ = lldp_type(LLDP::TTL);
    *b++ = 2;
    *b++ = 0;   // apparently, big-endian short
    *b++ = 120; // seconds

    if (b + 5 > end)
        throw std::runtime_error("buffer overflow - port desc");
    *b++ = lldp_type(LLDP::PORT_DESC);
    *b++ = 3;
    *b++ = '0' + adapter;
    *b++ = '/';
    *b++ = '0' + port;

    size_t l = strlen(sys_name);
    if (b + l + 2 > end)
        throw std::runtime_error("buffer overflow - sys name");
    *b++ = lldp_type(LLDP::SYS_NAME);
    *b++ = l;
    b = static_cast<unsigned char*>(mempcpy(b, sys_name, l));

    l = strlen(sys_desc);
    if (b + l + 2 > end)
        throw std::runtime_error("buffer overflow - sys descr");
    *b++ = lldp_type(LLDP::SYS_DESC);
    *b++ = l;
    b = static_cast<unsigned char*>(mempcpy(b, sys_desc, l));

    if (b + 2 > end)
        throw std::runtime_error("buffer overflow - EOC");
    *b++ = 0;
    *b++ = 0; // 2 byte zero == end of content / end of PDU

    if (b + 4 > end)
        throw std::runtime_error("buffer overflow - FCS");
    b += 4;

    size_t n = b - begin;

    if (n < 64)
        throw std::runtime_error("LLDP frame is too short - check  sys name/desc");
    if (n > 1500)
        throw std::runtime_error("LLDP frame is too long - check  sys name/desc");

    return n;
}


// XXX share with collect_nt_sensors
static unsigned count_adapters(nt::Info_Stream &info)
{
    NtInfo_t req {
        .cmd  = NT_INFO_CMD_READ_SYSTEM
    };
    info.read(req);
    return req.u.system.data.numAdapters;
}


static std::vector<std::vector<unsigned char> > prepare_lldp_frames()
{
    std::vector<std::vector<unsigned char> > frames;
    frames.reserve(8);

    struct utsname u;
    linux::uname(&u);
    char sys_desc[512];
    snprintf(sys_desc, sizeof sys_desc, "%s %s %s %s",
            u.sysname, u.release, u.version, u.machine);

    nt::Info_Stream info("nt_beacon_info");

    unsigned n = count_adapters(info);

    for (uint8_t i = 0; i < n; ++i) {
        NtInfo_t areq {
            .cmd  = NT_INFO_CMD_READ_ADAPTER_V6,
            .u    = { .adapter_v6 = { .adapterNo = i } }
        };
        info.read(areq);

        for (uint8_t j = 0; j < areq.u.adapter_v6.data.numPorts; ++j) {
            uint8_t port_off = areq.u.adapter_v6.data.portOffset;
            NtInfo_t preq {
                .cmd = NT_INFO_CMD_READ_PORT_V9,
                .u   = { .port_v9 = { .portNo = uint8_t(port_off + j) } }
            };
            info.read(preq);

            const unsigned char *mac_addr = preq.u.port_v9.data.macAddress;

            frames.emplace_back(512);
            std::vector<unsigned char> &frame = frames.back();
            size_t n = mk_lldp(frame.data(), frame.data() + frame.size(),
                mac_addr, i, j, u.nodename, sys_desc);
            frame.resize(n);
        }
    }
    return frames;
}


static std::array<unsigned char, 4> parse_ip_address(const std::string &s)
{
    struct in_addr dst;
    linux::inet_pton(AF_INET, s.c_str(), &dst);
    uint32_t a = ntohl(dst.s_addr);
    return std::array<unsigned char, 4> {
        static_cast<unsigned char>( a >> 24        ),
        static_cast<unsigned char>((a >> 16) & 0xff),
        static_cast<unsigned char>((a >>  8) & 0xff),
        static_cast<unsigned char>( a        & 0xff)
    };
}



using Mcast_Cfg = std::vector<std::deque<std::array<unsigned char, 4>>>;


// returns vector of IP-address deques
// first IP address of each deque is the port's source IP address
static Mcast_Cfg read_mcast_cfg(const std::string &filename)
{
    Mcast_Cfg r;
    if (filename.empty())
        return r;
    std::ifstream f(filename);

    unsigned state = 0;
    unsigned port = 23;
    std::string a, b;
    for (std::string line; std::getline(f, line); ) {

        size_t i = line.find('#');
        if (i != std::string::npos)
            line.resize(i);


        if (!line.find("[port")) {
            line.erase(0, 5);
            size_t i = line.find(']');
            if (i == std::string::npos)
                throw std::runtime_error("[port misses ]");
            line.resize(i);
            port = std::stoul(line);
            state = 1;
            if (port + 1> r.size())
                r.resize(port + 1);
            else {
                if (!r[port].empty())
                    throw std::runtime_error("duplicated port section");
            }
            continue;
        }

        std::istringstream g(line);
        a.clear();
        b.clear();
        g >> a >> b;

        if (a == "source") {
            if (state != 1)
                throw std::runtime_error("source directive must follow [portX]");
            r[port].emplace_back(parse_ip_address(b));
            state = 2;
        }
        if (a == "join") {
            if (state != 2)
                throw std::runtime_error("join directive used before defining a source");
            r[port].emplace_back(parse_ip_address(b));
        }
    }
    return r;
}


static void verify_mcast_cfg(const Mcast_Cfg &mcast_cfg, unsigned join_window_s)
{
    for (auto &cfg : mcast_cfg) {
        if (cfg.size() < 2)
            continue;
        if ((cfg.size() - 1) * (60.0 / join_window_s) > 1500.4)
            throw std::runtime_error("multicast join config violates 1500/minute IGMP packet limit - increase window (cf. -w) or reduce the number of groups per port");
    }
}

static std::vector<std::deque<std::array<unsigned char, 4>>::const_iterator>
    mk_join_itrs(const Mcast_Cfg &mcast_cfg, uint32_t port_mask)
{
    std::vector<std::deque<std::array<unsigned char, 4>>::const_iterator> join_itrs(mcast_cfg.size());
    for (size_t port = 0; port < mcast_cfg.size(); ++port) {
        if (((1 << port) & port_mask) == 0 || mcast_cfg[port].size() < 2)
            continue;
        join_itrs[port] = ++mcast_cfg[port].cbegin();
    }
    return join_itrs;
}

static void mcast_l2addr(const unsigned char *addr, unsigned char *maddr)
{
    maddr[0] = 0x01;
    maddr[1] = 0x00;
    maddr[2] = 0x5e;
    maddr[3] = addr[1] & 0x7f;
    maddr[4] = addr[2];
    maddr[5] = addr[3];
}

static uint16_t checksum(const unsigned char *b, const unsigned char *e)
{
    uint32_t x = 0;

    const unsigned char *p = b;
    for (; p < e; p += 2) {
        uint16_t a;
        memcpy(&a, p, sizeof a);
        x += a;
    }

    if (p != e) {
        uint16_t a;
        memcpy(&a, e - 1, 1);
        x += a;
    }

    x = (x >> 16) + (x & 0xffff);
    x = (x >> 16) + (x & 0xffff);

    x = ~ x;

    return x;
}

static size_t mk_igmp_report(unsigned char *b, unsigned char *end,
        const unsigned char *src_maddr, const unsigned char *src_addr,
        const unsigned char *dst_addr)
{
    auto begin = b;
    if (b + 64 > end)
        throw std::runtime_error("buffer overflow - igmp frame");
    unsigned char dst_maddr[6];
    mcast_l2addr(dst_addr, dst_maddr);
    memcpy(b, &dst_maddr, sizeof dst_maddr);
    memcpy(b + 6, src_maddr, 6);
    b[12] = 0x08;
    b[13] = 0x00; // Type: IPv4
    b += 14;


    b[0] = (1 << 6) | 6; // Version and IHL, 6 * 4 == 24
    b[1] = 0; // TOS/DSCP
    b[2] = 0;
    b[3] = 32; // total length
    // cf. https://github.com/gsauthof/dpdk-examples/blob/35228763c05f9b0db510e45a7429be3bbf0faede/mcast_send.c#L331-L332
    b[4] = 0;
    b[5] = 0; // Identification

    // NB: we don't need the DF bit since TTL is 1, anyways ...
    //b[6] = 1 << 6; // Flags -> don't fragment (DF)
    b[6] = 0;     // Flags

    b[7] = 0;     // Fragment offset
    b[8] = 1;     // TTL
    b[9] = 0x02;  // Protocol: IGMP
    b[10] = 0;
    b[11] = 0;    // Header checksum
    memcpy(b + 12, src_addr, 4);
    memcpy(b + 16, dst_addr, 4);

    b[20] = 0x94; // Router Alert - RTRALT
    b[21] = 4;    // option length
    b[22] = 0;
    b[23] = 0;    // padding

    uint16_t ip_csum = checksum(b, b + 24);
    memcpy(b + 10, &ip_csum, sizeof ip_csum);
    b += 24;


    b[0] = 0x16; // IGMPv2 Membership Report
    b[1] = 0;    // max response time
    b[2] = 0;
    b[3] = 0;    // checksum
    memcpy(b + 4, dst_addr, 4);

    uint16_t igmp_csum = checksum(b, b + 8);
    memcpy(b + 2, &igmp_csum, sizeof igmp_csum);
    b += 8;

    // padding
    b += 14;
    // FCS
    b += 4;

    assert(b - begin == 64);

    return b - begin;
}

static void update_igmp_report(unsigned char *b, unsigned char *end,
        const unsigned char *dst_addr)
{
    if (b + 64 != end)
        throw std::runtime_error("igmp frame must be 64 byte long");

    unsigned char dst_maddr[6];
    mcast_l2addr(dst_addr, dst_maddr);
    memcpy(b, &dst_maddr, sizeof dst_maddr);
    b += 14;


    b[10] = 0;
    b[11] = 0; // Header checksum
    memcpy(b + 16, dst_addr, 4);

    uint16_t ip_csum = checksum(b, b + 24);
    // NB: little endian since we computed it like that
    b[10] = ip_csum;
    b[11] = ip_csum >> 8;
    b += 24;


    b[2] = 0;
    b[3] = 0;    // checksum
    memcpy(b + 4, dst_addr, 4);

    uint16_t igmp_csum = checksum(b, b + 8);
    b[2] = igmp_csum;
    b[3] = igmp_csum >> 8;
    b += 8;

}



static std::vector<std::vector<unsigned char>> prepare_igmp_frames(
        const std::vector<std::vector<unsigned char>> &lldp_frames,
        const Mcast_Cfg &mcast_cfg)
{
    std::vector<std::vector<unsigned char>> r;
    auto i = lldp_frames.begin();
    auto j = mcast_cfg.begin();
    const unsigned char dummy_ip_addr[4] = { 0 };
    for (; i != lldp_frames.end() && j != mcast_cfg.end(); ++i, ++j) {
        assert((*i).size() > 12);
        const unsigned char *src_mac_addr = (*i).data() + 6;

        if ((*j).size() < 2)
            continue;

        const unsigned char *src_ip_addr = (*j).front().data();

        auto &frame = r.emplace_back(512);
        size_t n = mk_igmp_report(frame.data(), frame.data() + frame.size(),
            src_mac_addr, src_ip_addr, dummy_ip_addr);
        frame.resize(n);
    }
    return r;
}


static uint64_t read_timer(int tfd)
{
    uint64_t expirations = 0;
    ssize_t l = read(tfd, &expirations, sizeof expirations);
    if (l == -1) {
        if (errno != EINTR)
            throw linux::Error(linux::errno_to_str("read timerfd", errno));
    }
    if (l != sizeof expirations)
        throw linux::Error("short timerfd read");
    return expirations;
}

static std::vector<int> add_igmp_timers(int efd, const Mcast_Cfg &mcast_cfg,
        uint32_t port_mask, unsigned join_window_s)
{
    std::vector<int> r(mcast_cfg.size());
    uint32_t i = 0;
    for (auto &cfg : mcast_cfg) {
        uint32_t port = i++;
        if (((1 << port) & port_mask) == 0 || cfg.size() < 2)
            continue;

        uint64_t x = 1000000000lu;
        x *= join_window_s;
        x /= cfg.size() - 1;

        int timer = linux::timerfd_create(CLOCK_MONOTONIC, 0);
        struct itimerspec timer_spec  = {
            .it_interval = { .tv_sec  = time_t(x / 1000000000lu),
                             .tv_nsec = long  (x % 1000000000lu) },
            .it_value    = { .tv_sec  = 1 }
        };
        linux::timerfd_settime(timer, 0, &timer_spec, 0);

        struct epoll_event ev = { .events = EPOLLIN,
            .data = { .u32 = port + 1 } };
        linux::epoll_ctl(efd, EPOLL_CTL_ADD, timer, &ev);

        r.at(port) = timer;
    }
    return r;
}

static int add_lldp_timer(int efd)
{
    int lldp_timer = linux::timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec lldp_timer_spec = {
        .it_interval = { .tv_sec = 30 },
        .it_value    = { .tv_sec =  1 }
    };
    linux::timerfd_settime(lldp_timer, 0, &lldp_timer_spec, 0);

    {
        struct epoll_event ev = { .events = EPOLLIN,
            .data = { .u32 = 0 } };
        linux::epoll_ctl(efd, EPOLL_CTL_ADD, lldp_timer, &ev);
    }
    return lldp_timer;
}


static sig_atomic_t globally_interrupted = 0;

static void int_handler(int)
{
    globally_interrupted = 1;
}

static void setup_signal_handlers()
{
    struct sigaction sa = { 0 };
    sa.sa_handler = int_handler;
    for (auto i : { SIGINT, SIGTERM })
        linux::sigaction(i, &sa, 0);
}


// NB: a transmit doesn't fail when its port is down,
//     IOW, there is no need to restart this service after port state changes,
//     after reconnecting/re-enabling the port following transmitted frames reach the wire
static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    setup_signal_handlers();


    if (args.systemd)
        linux::sd_notify(0, "STATUS=opening TX stream");

    nt::Library lib;

    nt::Tx_Stream tx("nt_beacon", args.port_mask, NT_NETTX_NUMA_ADAPTER_HB, 4 /* MiB */);

    std::vector<std::vector<unsigned char>> lldp_frames = prepare_lldp_frames();


    if (args.systemd)
        linux::sd_notify(0, "STATUS=reading IGMP config");

    auto mcast_cfg   = read_mcast_cfg(args.mcast_cfg_filename);
    verify_mcast_cfg(mcast_cfg, args.join_window_s);
    mcast_cfg.resize(lldp_frames.size());
    auto igmp_frames = prepare_igmp_frames(lldp_frames, mcast_cfg);


    if (args.systemd)
        linux::sd_notify(0, "STATUS=creating timers");

    int efd = linux::epoll_create1(0);

    int lldp_timer = add_lldp_timer(efd);
    auto igmp_timers = add_igmp_timers(efd, mcast_cfg, args.port_mask, args.join_window_s);


    if (args.systemd) {
        linux::sd_notify(0, "READY=1");
        linux::sd_notify(0, "STATUS=transmitting");
    }

    NtNetBuf_t net_buf = 0;
    struct epoll_event evs[16];
    auto join_itrs = mk_join_itrs(mcast_cfg, args.port_mask);

    while (!globally_interrupted) {

        int n = linux::epoll_wait(efd, evs, sizeof evs / sizeof evs[0], -1);

        for (int i = 0; i < n; ++i) {
            if (!evs[i].data.u32) {
                uint64_t expirations = read_timer(lldp_timer);
                if (!expirations)
                    continue;
                for (size_t port = 0; port < lldp_frames.size(); ++port) {
                    if (((1 << port) & args.port_mask) == 0)
                        continue;
                    const std::vector<unsigned char> &frame = lldp_frames.at(port);

                    // NB: there is also NT_NETTX_PACKET_OPTION_RAW,
                    //     but L2 (i.e. ethernet frames) is raw enough for us
                    // NB: NT_NETTX_PACKET_OPTION_L2 == NT_NETTX_PACKET_OPTION_DEFAULT
                    tx.get_forever(net_buf, port, frame.size(),
                            NT_NETTX_PACKET_OPTION_L2, 1000 /* ms */);

                    unsigned char *p = static_cast<unsigned char*>(NT_NET_GET_PKT_L2_PTR(net_buf));
                    memcpy(p, frame.data(), frame.size());

                    tx.release(net_buf);
                }
            } else {
                uint32_t port = evs[i].data.u32 - 1;
                assert(((1 << port) & args.port_mask) != 0);
                assert(mcast_cfg.at(port).size() >= 2);

                uint64_t expirations = read_timer(igmp_timers.at(port));
                if (!expirations)
                    continue;

                auto &frame = igmp_frames.at(port);
                update_igmp_report(frame.data(), frame.data() + frame.size(),
                        (*join_itrs.at(port)).data());

                tx.get_forever(net_buf, port, frame.size(),
                        NT_NETTX_PACKET_OPTION_L2, 1000 /* ms */);
                unsigned char *p = static_cast<unsigned char*>(NT_NET_GET_PKT_L2_PTR(net_buf));
                memcpy(p, frame.data(), frame.size());
                tx.release(net_buf);

                ++join_itrs[port];
                if (join_itrs[port] == mcast_cfg.at(port).cend())
                    join_itrs[port] = ++mcast_cfg[port].cbegin();
            }
        }

    }

    if (args.systemd) {
        linux::sd_notify(0, "STATUS=done");
        linux::sd_notify(0, "STOPPING=1");
    }

    tx.close();


    return 0;
}


int main(int argc, char **argv)
{
    try {
        return mainP(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
