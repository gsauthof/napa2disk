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
    unsigned interval_s {60};
    bool auto_reset     {false};
    bool reset_ts_stats {false};

    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " [OPT..]\n"
            "\n"
            "Options:\n"
            "  -C                      auto reset time-sync stats at midnight UTC\n"
            "  -c                      reset time-sync stats at start\n"
            "  -i INTERVAL_SECS        set query interval (default: 60 s)\n"
            "\n"
            "2022-01-11, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '-' prefix: no reordering of arguments, non-option arguments are
        // returned as argument to the 1 option
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "-Cchi:")) != -1) {
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
                    auto_reset = true;
                    break;
                case 'c':
                    reset_ts_stats = true;
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

static unsigned count_adapters(nt::Info_Stream &info)
{
    NtInfo_t req {
        .cmd  = NT_INFO_CMD_READ_SYSTEM
    };
    info.read(req);
    return req.u.system.data.numAdapters;
}

static const char *subtype2cstr(NtSensorSubType_e e)
{
    switch (e) {
        case NT_SENSOR_SUBTYPE_POWER_OMA: return "_OMA";
        case NT_SENSOR_SUBTYPE_POWER_AVERAGE: return "_AVG";
        case NT_SENSOR_SUBTYPE_POWER_TOTAL: return "_total";
        default: return "";
    }
}
static const char *type2cstr(NtSensorType_e e)
{
    switch (e) {
        case NT_SENSOR_TYPE_TEMPERATURE: return "_dC";
        case NT_SENSOR_TYPE_VOLTAGE: return "_mV";
        case NT_SENSOR_TYPE_CURRENT: return "_uA";
        case NT_SENSOR_TYPE_POWER: return "_duW";
        case NT_SENSOR_TYPE_FAN: return "_rpm";
        case NT_SENSOR_TYPE_HIGH_POWER: return "_mW";
        default: return "";
    }
}

static void sanitize(const char *field, std::string &result)
{
    result = field;
    for (auto &c : result)
        switch (c) {
            case '+': c = 'p'; break;
            case ' ': c = '_'; break;
        }
}

static void print_sensor(std::ostream &o, const NtInfoSensor_t &s, unsigned &k)
{
    std::string name;
    if (s.value != NT_SENSOR_NAN) {
        if (k++)
            o << ',';
        sanitize(s.name, name);
        o << name << subtype2cstr(s.subType) << type2cstr(s.type) << "=" << s.value;
    }
    if (s.valueLowest != NT_SENSOR_NAN) {
        if (k++)
            o << ',';
        sanitize(s.name, name);
        o << name << subtype2cstr(s.subType) << type2cstr(s.type) << "_low=" << s.valueLowest;
    }
    if (s.valueHighest != NT_SENSOR_NAN) {
        if (k++)
            o << ',';
        sanitize(s.name, name);
        o << name << subtype2cstr(s.subType) << type2cstr(s.type) << "_high=" << s.valueHighest;
    }
}
static void print_ts(std::ostream &o, const NtInfoTimeSync_v4_s &s)
{
    o
        << ",pps_enabled=" << ((s.timeSyncPpsEnable == NT_TIMESYNC_PPS_STATUS_ENABLED) ? "t" : "f")
        << ",pps_present=" << ((s.timeSyncCurrentConStatus == NT_TIMESYNC_CONNECTOR_STATUS_SIGNAL_PRESENT) ? "t" : "f")
        << ",in_sync=" << ((s.timeSyncInSyncStatus == NT_TIMESYNC_INSYNC_STATUS_IN_SYNC) ? "t": "f")
        << ",ts_ref=" << s.timeRef
        << ",freq_ref=" << s.freqRef
        ;
}
static void print_ts_stats(std::ostream &o, const NtInfoTimeSyncStatistics_s &s)
{
    o << ",ts_samples=" << s.samples
        << ",skew=" << s.skew
        << ",skew_min=" << s.min
        << ",skew_max=" << s.max
        << ",skew_jitter=" << s.jitter
        // std-deviation square root?
        << ",skew_dev=" << s.stdDevSqr
        << ",ts_sig_lost=" << s.signalLostCnt
        << ",ts_sync_lost=" << s.syncLostCnt
        << ",ts_reset=" << s.hardResetCnt;
}
static void print_ptp_stats(std::ostream &o, const NtPTPPortStat_s &s)
{
    if (s.txGoodBytes)
        o << ",ptp_txGoodBytes=" << s.txGoodBytes;
    if (s.txGoodBroadcast)
        o << ",ptp_txGoodBroadcast=" << s.txGoodBroadcast;
    if (s.txGoodMulticast)
        o << ",ptp_txGoodMulticast=" << s.txGoodMulticast;
    if (s.txGoodUnicast)
        o << ",ptp_txGoodUnicast=" << s.txGoodUnicast;
    if (s.rxGoodBytes)
        o << ",ptp_rxGoodBytes=" << s.rxGoodBytes;
    if (s.rxGoodBroadcast)
        o << ",ptp_rxGoodBroadcast=" << s.rxGoodBroadcast;
    if (s.rxGoodMulticast)
        o << ",ptp_rxGoodMulticast=" << s.rxGoodMulticast;
    if (s.rxGoodUnicast)
        o << ",ptp_rxGoodUnicast=" << s.rxGoodUnicast;
    if (s.rxGoodLegalLength)
        o << ",ptp_rxGoodLegalLength=" << s.rxGoodLegalLength;
    if (s.rxFragmented)
        o << ",ptp_rxFragmented=" << s.rxFragmented;
    if (s.rxJabber)
        o << ",ptp_rxJabber=" << s.rxJabber;
    if (s.rxBadBytes)
        o << ",ptp_rxBadBytes=" << s.rxBadBytes;
    if (s.rxDiscarded)
        o << ",ptp_rxDiscarded=" << s.rxDiscarded;
}
static void print_port(std::ostream &o, const NtInfoPort_v9_s &s)
{
    o
        << "type=" << s.type
        << ",state=" << s.state
        << ",speed=" << s.speed
        << ",full_duplex=" << ((s.duplex == NT_LINK_DUPLEX_FULL) ? "t" : "f")
        ;
}

static void reset_ts_stats(unsigned n)
{
        nt::Config_Stream cfg("collect_nt_sensors_cfg");
        for (uint8_t i = 0; i < n; ++i) {
            NtConfig_t req = {
                .parm = NT_CONFIG_PARM_ADAPTER_TIMESYNC_RESET,
                .u = { .timesyncReset = {
                    .adapter = i,
                    .resetCmd = NT_TIMESYNC_RESET_TS_STATISTICS  } }
            };
            std::cerr << "Resetting timesync stats on adapter " << i << std::endl;

            // XXX also reset NT_TIMESYNC_RESET_PTP_PORT_STAT ?
            cfg.write(req);
        }
}


static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    setup_signal_handlers();

    nt::Library lib;
    nt::Info_Stream info("collect_nt_sensors_info");

    unsigned n = count_adapters(info);

    if (args.reset_ts_stats)
        reset_ts_stats(n);

    int tfd = linux::timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec tspec = {
        .it_interval = { .tv_sec = args.interval_s },
        .it_value    = { .tv_sec = args.interval_s }
    };
    linux::timerfd_settime(tfd, 0, &tspec, 0);


    unsigned last_reset = 0;
    for (;;) {

        for (uint8_t i = 0; i < n; ++i) {
            std::cout << "nt_sensors,adapter=" << unsigned(i) << ' ';
            NtInfo_t areq {
                .cmd  = NT_INFO_CMD_READ_ADAPTER_V6,
                    .u = { .adapter_v6 = { .adapterNo = i } }
            };
            info.read(areq);
            unsigned m = areq.u.adapter_v6.data.numLevel1Sensors;
            unsigned k = 0;
            for (unsigned j = 0; j < m; ++j) {
                NtInfo_t req {
                    .cmd  = NT_INFO_CMD_READ_SENSOR,
                        .u = { .sensor = {
                            .source = NT_SENSOR_SOURCE_LEVEL1_ADAPTER,
                            .sourceIndex = areq.u.adapter_v6.adapterNo,
                            .sensorIndex = j
                        } }
                };
                info.read(req);
                if (req.u.sensor.data.state == NT_SENSOR_STATE_NOT_PRESENT)
                    continue;

                auto &s = req.u.sensor.data;

                print_sensor(std::cout, s, k);
            }
            {
                NtInfo_t req {
                    .cmd  = NT_INFO_CMD_READ_TIMESYNC_V4 ,
                        .u = { .timeSyncStat = { .adapterNo = i } }
                };
                info.read(req);
                auto &s = req.u.timeSync_v4.data;
                print_ts(std::cout, s);
            }
            {
                NtInfo_t req {
                    .cmd  = NT_INFO_CMD_READ_TIMESYNC_STAT,
                        .u = { .timeSyncStat = { .adapterNo = i } }
                };
                info.read(req);
                auto &s = req.u.timeSyncStat.data;
                print_ts_stats(std::cout, s);
            }
            {
                NtInfo_t req {
                    .cmd  = NT_INFO_CMD_READ_PTP_V2,
                        .u = { .ptp_v2 = { .adapterNo = i } }
                };
                info.read(req);
                auto &s = req.u.ptp_v2.data.ptpPortStat;
                print_ptp_stats(std::cout, s);
            }
            std::cout << ' ' << linux::time(0) << "000000000" << std::endl;


            for (uint8_t j = 0; j < areq.u.adapter_v6.data.numPorts; ++j) {
                uint8_t port_off = areq.u.adapter_v6.data.portOffset;
                NtInfo_t preq {
                    .cmd = NT_INFO_CMD_READ_PORT_V9,
                        .u = { .port_v9 = { .portNo = uint8_t(port_off + j) } }
                };
                info.read(preq);
                std::cout << "nt_port_sensors,adapter=" << unsigned(i) << ",port=" << unsigned(j) << ' ';
                print_port(std::cout, preq.u.port_v9.data);
                unsigned m = preq.u.port_v9.data.numLevel1Sensors;
                unsigned z = 1;
                for (unsigned k = 0; k < m; ++k) {
                    NtInfo_t req  {
                        .cmd = NT_INFO_CMD_READ_SENSOR,
                            .u = { .sensor = {
                                .source = NT_SENSOR_SOURCE_LEVEL1_PORT,
                                .sourceIndex = uint8_t(port_off + j),
                                .sensorIndex = k
                            } }
                    };
                    info.read(req);
                    if (req.u.sensor.data.state == NT_SENSOR_STATE_NOT_PRESENT)
                        continue;
                    auto &s = req.u.sensor.data;
                    print_sensor(std::cout, s, z);
                }
                std::cout << ' ' << linux::time(0) << "000000000" << std::endl;
            }
        }

        if (args.auto_reset) {
            auto now = linux::time(0);
            if (now % (24 * 3600) < 300 && now - last_reset > 300) {
                reset_ts_stats(n);
                last_reset = now;
            }
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
