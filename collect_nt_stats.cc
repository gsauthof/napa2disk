// SPDX-License-Identifier: BSL-1.0
//
// 2022, Georg Sauthoff

#include "napatech.hh"
#include "linux.hh"

#include <stdexcept>
#include <string>
#include <iostream>
#include <sstream>

#include <signal.h> // sigaction(), ...
#include <stdlib.h> // atoi(), exit(), ...
#include <unistd.h> // getopt(), ...


struct Args {
    unsigned interval_s {1};
    unsigned mult {60};

    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " [OPT..]\n"
            "\n"
            "Options:\n"
            "  -i INTERVAL_SECS        buffer query interval (default: 1 s)\n"
            "  -m FACTOR               stats query interval (default: 60)\n"
            "                          i.e. FACTOR * INTERVAL_SECS\n"
            "\n"
            "2022-01-11, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '-' prefix: no reordering of arguments, non-option arguments are
        // returned as argument to the 1 option
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "-hi:m:")) != -1) {
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
                case 'h':
                    help(std::cout, argv[0]);
                    exit(0);
                    break;
                case 'i':
                    interval_s = atoi(optarg);
                    if (!interval_s)
                        throw std::runtime_error("interval must be > 0");
                    break;
                case 'm':
                    mult = atoi(optarg);
                    if (!mult)
                        throw std::runtime_error("factor must be > 0");
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


static void print_port_stats(const NtPortStatistics_v2_s &s, const char *prefix)
{
    if (s.valid.RMON1) {
        std::cout
            << ',' << prefix << "_dropEvents="           << s.RMON1.dropEvents
            << ',' << prefix << "_octets="               << s.RMON1.octets
            << ',' << prefix << "_pkts="                 << s.RMON1.pkts
            << ',' << prefix << "_broadcastPkts="        << s.RMON1.broadcastPkts
            << ',' << prefix << "_multicastPkts="        << s.RMON1.multicastPkts
            << ',' << prefix << "_crcAlignErrors="       << s.RMON1.crcAlignErrors
            << ',' << prefix << "_undersizePkts="        << s.RMON1.undersizePkts
            << ',' << prefix << "_oversizePkts="         << s.RMON1.oversizePkts
            << ',' << prefix << "_fragments="            << s.RMON1.fragments
            << ',' << prefix << "_jabbers="              << s.RMON1.jabbers
            << ',' << prefix << "_collisions="           << s.RMON1.collisions
            << ',' << prefix << "_pkts64Octets="         << s.RMON1.pkts64Octets
            << ',' << prefix << "_pkts65to127Octets="    << s.RMON1.pkts65to127Octets
            << ',' << prefix << "_pkts128to255Octets="   << s.RMON1.pkts128to255Octets
            << ',' << prefix << "_pkts256to511Octets="   << s.RMON1.pkts256to511Octets
            << ',' << prefix << "_pkts512to1023Octets="  << s.RMON1.pkts512to1023Octets
            << ',' << prefix << "_pkts1024to1518Octets=" << s.RMON1.pkts1024to1518Octets
            ;
    }
    if (s.valid.extRMON) {
        std::cout
            << ',' << prefix << "_pkts1519to2047Octets=" << s.extRMON.pkts1519to2047Octets
            << ',' << prefix << "_pkts2048to4095Octets=" << s.extRMON.pkts2048to4095Octets
            << ',' << prefix << "_pkts4096to8191Octets=" << s.extRMON.pkts4096to8191Octets
            << ',' << prefix << "_pkts8192toMaxOctets="  << s.extRMON.pkts8192toMaxOctets
            << ',' << prefix << "_pktsHardSlice="        << s.extRMON.pktsHardSlice
            << ',' << prefix << "_pktsHardSliceJabber="  << s.extRMON.pktsHardSliceJabber
            << ',' << prefix << "_unicastPkts="          << s.extRMON.unicastPkts
            << ',' << prefix << "_pktsCrc="              << s.extRMON.pktsCrc
            << ',' << prefix << "_pktsAlignment="        << s.extRMON.pktsAlignment
            << ',' << prefix << "_pktsCodeViolation="    << s.extRMON.pktsCodeViolation
            << ',' << prefix << "_pktsRetransmit="       << s.extRMON.pktsRetransmit
            ;
    }
    if (s.valid.chksum) {
        std::cout
            << ',' << prefix << "_pktsIpChkSumError="  << s.chksum.pktsIpChkSumError
            << ',' << prefix << "_pktsUdpChkSumError=" << s.chksum.pktsUdpChkSumError
            << ',' << prefix << "_pktsTcpChkSumError=" << s.chksum.pktsTcpChkSumError
            ;
    }
    if (s.valid.decode) {
        std::cout
            << ',' << prefix << "_pktsGiantUndersize=" << s.decode.pktsGiantUndersize
            << ',' << prefix << "_pktsBabyGiant="      << s.decode.pktsBabyGiant
            << ',' << prefix << "_pktsVlan="           << s.decode.pktsVlan
            << ',' << prefix << "_pktsDuplicate="      << s.decode.pktsDuplicate
        // NB: fields with Isl/Mpls left out for now
            ;
    }
    if (s.valid.extDrop) {
        std::cout
            << ',' << prefix << "_pktsMacBandwidth=" << s.extDrop.pktsMacBandwidth

            << ',' << prefix << "_pktsOverflow="     << s.extDrop.pktsOverflow
            << ',' << prefix << "_octetsOverflow="   << s.extDrop.octetsOverflow

            << ',' << prefix << "_pktsDedup="        << s.extDrop.pktsDedup
            << ',' << prefix << "_octetsDedup="      << s.extDrop.octetsDedup

            << ',' << prefix << "_pktsNoFilter="     << s.extDrop.pktsNoFilter
            << ',' << prefix << "_octetsNoFilter="   << s.extDrop.octetsNoFilter

            << ',' << prefix << "_pktsFilterDrop="   << s.extDrop.pktsFilterDrop
            << ',' << prefix << "_octetsFilterDrop=" << s.extDrop.octetsFilterDrop
            ;
    }
    if (s.valid.ipf) {
        std::cout
            << ',' << prefix << "_ipFragTableFirstHit="   << s.ipf.ipFragTableFirstHit
            << ',' << prefix << "_ipFragTableFirstNoHit=" << s.ipf.ipFragTableFirstNoHit
            << ',' << prefix << "_ipFragTableMidHit="     << s.ipf.ipFragTableMidHit
            << ',' << prefix << "_ipFragTableMidNoHit="   << s.ipf.ipFragTableMidNoHit
            << ',' << prefix << "_ipFragTableLastHit="    << s.ipf.ipFragTableLastHit
            << ',' << prefix << "_ipFragTableLastNoHit="  << s.ipf.ipFragTableLastNoHit
            ;
    }
}

static void print_color_stats(const NtColorStatistics_s &s, const char *prefix)
{
    std::cout
               << prefix << "_pkts="   << s.pkts
        << ',' << prefix << "_octets=" << s.octets
        ;
}

static void print_stats(const NtStatisticsQuery_v3_s::NtStatisticsQueryResult_v3_s &s)
{
    for (uint8_t i = 0; i < s.port.numPorts; ++i) {
        const NtStatGroupport_v2_s &p = s.port.aPorts[i];
        std::cout << "nt_port_stats,port=" << +i << ' ';
        std::cout << "link_down=" << p.linkDownCounter;
        print_port_stats(p.rx, "rx");
        print_port_stats(p.tx, "tx");
        std::cout << ' ' << linux::time(0) << "000000000" << std::endl;
    }
    for (uint8_t i = 0; i < 4; ++i) {
        const NtStatGroupStream_s &p = s.stream;
        std::cout << "nt_stream_stats,stream=" << +i << ' ';
        print_color_stats(p.streamid[i].forward, "forward");
        std::cout << ',';
        print_color_stats(p.streamid[i].flush, "flush");
        std::cout << ',';
        print_color_stats(p.streamid[i].drop, "drop");
        std::cout << ' ' << linux::time(0) << "000000000" << std::endl;
    }
    {
        const NtStatGroupStream_s &p = s.stream;
        std::cout << "nt_stream_stats,stream=256 ";
        print_color_stats(p.Unassigned.forward, "forward");
        std::cout << ',';
        print_color_stats(p.Unassigned.flush, "flush");
        std::cout << ',';
        print_color_stats(p.Unassigned.drop, "drop");
        std::cout << ' ' << linux::time(0) << "000000000" << std::endl;
    }
}

static void print_buf_stats(const NtStatisticsUsageData_v0_s::NtStatUsageData_s::NtStatHostBufferUsage_s &s)
{
    std::cout
               << "deQueued="           << s.deQueued
        << ',' << "enQueued="           << s.enQueued
        << ',' << "enQueuedAdapter="    << s.enQueuedAdapter
        << ',' << "adapterNo="          << +s.adapterNo
        << ',' << "numaNode="           << +s.numaNode
        << ',' << "hostBufferSize="     << s.hostBufferSize
        << ',' << "numStreams="         << s.numStreams

        << ',' << "onboard_used="       << s.onboardBuffering.used
        << ',' << "onboard_size="       << s.onboardBuffering.size
        << ',' << "onboard_crcErrors="  << s.onboardBuffering.crcErrors

        << ',' << "rx_received_bytes="  << s.stat.rx.bytes
        << ',' << "rx_received_frames=" << s.stat.rx.frames

        << ',' << "rx_dropped_bytes="   << s.stat.drop.bytes
        << ',' << "rx_dropped_frames="  << s.stat.drop.frames
        ;
}

static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    setup_signal_handlers();

    nt::Library lib;
    nt::Stat_Stream stats("collect_nt_stats");
    stats.reset();

    int tfd = linux::timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec tspec = {
        .it_interval = { .tv_sec = args.interval_s },
        .it_value    = { .tv_sec = args.interval_s }
    };
    linux::timerfd_settime(tfd, 0, &tspec, 0);

    for (unsigned k = 0;; ++k) {
        for (uint8_t i = 0; i < 4; ++i) {
            NtStatistics_t breq {
                .cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0,
                    .u = { .usageData_v0 = { .streamid = i } }
            };
            stats.read(breq);
            uint32_t m = breq.u.usageData_v0.data.numHostBufferUsed;
            for (uint32_t j = 0; j < m; ++j) {
                std::cout << "nt_buf_stats,stream=" << +i
                    << ",hostbuf=" << j << ' ';
                print_buf_stats(breq.u.usageData_v0.data.hb[j]);
                std::cout << ' ' << linux::time(0) << "000000000" << std::endl;
            }
        }

        if (k % args.mult == 0) {
            NtStatistics_t req {
                .cmd = NT_STATISTICS_READ_CMD_QUERY_V3,
                    .u = { .query_v3 = { .poll  = 1, } }
            };
            stats.read(req);
            print_stats(req.u.query_v3.data);
        }

        uint64_t expirations = 0;
        ssize_t l = read(tfd, &expirations, sizeof expirations);
        if (globally_interrupted)
            break;
        if (l == -1) {
            if (errno != EINTR)
                throw linux::Error(linux::errno_to_str("read tfd", errno));
        }

    }

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
