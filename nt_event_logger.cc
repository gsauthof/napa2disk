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
    unsigned timeout_ms {1500};
    bool systemd {false};

    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " [OPT..]\n"
            "\n"
            "Options:\n"
            "  -D                      integrate with systemd (i.e. notify etc.)\n"
            "  -t TIMEOUT_MSECS        set event query timeout (default: " << timeout_ms << " ms)\n"
            "                          NB: setting it too low wastes CPU cycles, settting it too high\n"
            "                              blocks program termination by that amount\n"
            "\n"
            "2022-06-22, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '-' prefix: no reordering of arguments, non-option arguments are
        // returned as argument to the 1 option
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "-Dht:")) != -1) {
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
                case 't':
                    timeout_ms = atoi(optarg);
                    if (timeout_ms > 60000) {
                        std::ostringstream o;
                        o << "a timeout value > 60000 ms (60 s) is too high";
                        throw std::runtime_error(o.str());
                    }
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


namespace nt {

    class Event_Stream {
        public:
            Event_Stream(const char *name, uint32_t mask = NT_EVENT_SOURCE_ALL)
            {
                int status = NT_EventOpen(&stream, name, mask);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            ~Event_Stream()
            {
                if (stream)
                    NT_EventClose(stream);
            }
            Event_Stream(const Event_Stream &) =delete;
            Event_Stream &operator=(const Event_Stream &) =delete;

            void close()
            {
                int status = NT_EventClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            // NB: During timeout, process can't even be interrupted via SIGKILL
            bool read(NtEvent_t &event, uint32_t timeout_ms = 1000)
            {
                int status = NT_EventRead(stream, &event, timeout_ms);
                if (status == NT_STATUS_TIMEOUT)
                    return false;
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                return true;
            }

        private:
            NtEventStream_t stream {0};
    };
}


inline std::ostream &operator<<(std::ostream &o, NtEventPort_e e)
{
    switch (e) {
        case NT_EVENT_PORT_LINK_UP: o << "LINK_UP"; break;
        case NT_EVENT_PORT_LINK_DOWN: o << "LINK_DOWN"; break;
        case NT_EVENT_RXAUI_LINK_ERROR: o << "RXAUI_LINK_ERROR"; break;
        case NT_EVENT_PORT_BYPASS_ACTIVATED: o << "BYPASS_ACTIVATED"; break;
        case NT_EVENT_PORT_BYPASS_DEACTIVATED: o << "BYPASS_DEACTIVATED"; break;
        case NT_EVENT_PORT_NIM_INSERTED: o << "NIM_INSERTED"; break;
        case NT_EVENT_PORT_NIM_REMOVED: o << "NIM_REMOVED"; break;
    }
    return o;
}

inline std::ostream &operator<<(std::ostream &o, NtSensorSource_e e)
{
    switch (e) {
        case NT_SENSOR_SOURCE_UNKNOWN: o << "UNKNOWN"; break;
        case NT_SENSOR_SOURCE_PORT: o << "PORT"; break;
        case NT_SENSOR_SOURCE_LEVEL1_PORT: o << "LEVEL1_PORT"; break;
        case NT_SENSOR_SOURCE_LEVEL2_PORT: o << "LEVEL2_PORT"; break;
        case NT_SENSOR_SOURCE_ADAPTER: o << "ADAPTER"; break;
        case NT_SENSOR_SOURCE_LEVEL1_ADAPTER: o << "LEVEL1_ADAPTER"; break;
        case NT_SENSOR_SOURCE_LEVEL2_ADAPTER: o << "LEVEL2_ADAPTER"; break;
    }
    return o;
}
inline std::ostream &operator<<(std::ostream &o, NtEventSensor_e e)
{
    switch (e) {
        case NT_EVENT_SENSOR_ALARM_STATE_ENTRY: o << "ENTRY"; break;
        case NT_EVENT_SENSOR_ALARM_STATE_EXIT: o << "EXIT"; break;
    }
    return o;
}
inline std::ostream &operator<<(std::ostream &o, NtSensorType_e e)
{
    switch (e) {
        case NT_SENSOR_TYPE_UNKNOWN: o << "unk"; break;
        case NT_SENSOR_TYPE_TEMPERATURE: o << "dC"; break;
        case NT_SENSOR_TYPE_VOLTAGE: o << "mV"; break;
        case NT_SENSOR_TYPE_CURRENT: o << "uA"; break;
        case NT_SENSOR_TYPE_POWER: o << "duW"; break;
        case NT_SENSOR_TYPE_FAN: o << "rpm"; break;
        case NT_SENSOR_TYPE_HIGH_POWER: o << "mW"; break;
        case NT_SENSOR_TYPE_NUMBER: break;
    }
    return o;
}
inline std::ostream &operator<<(std::ostream &o, NtSensorSubType_e e)
{
    switch (e) {
        case NT_SENSOR_SUBTYPE_NA: break;
        case NT_SENSOR_SUBTYPE_POWER_OMA: o << "OMA"; break;
        case NT_SENSOR_SUBTYPE_POWER_AVERAGE: o << "AVG"; break;
        case NT_SENSOR_SUBTYPE_POWER_TOTAL: o << "total"; break;
    }
    return o;
}

inline std::ostream &operator<<(std::ostream &o, NtConfigParm_e e)
{
    switch (e) {
        case NT_CONFIG_PARM_UNKNOWN: o << "UNKNOWN"; break;
        case NT_CONFIG_PARM_PORT_COMPAT_0: o << "PORT_COMPAT_0"; break;
        case NT_CONFIG_PARM_ADAPTER_TIMESTAMP: o << "ADAPTER_TIMESTAMP"; break;
        case NT_CONFIG_PARM_ADAPTER_TIMESYNC: o << "ADAPTER_TIMESYNC"; break;
        case NT_CONFIG_PARM_SENSOR: o << "SENSOR"; break;
        case NT_CONFIG_PARM_RESERVED_0: o << "RESERVED_0"; break;
        case NT_CONFIG_PARM_BYPASS_ADAPTER: o << "BYPASS_ADAPTER"; break;
        case NT_CONFIG_PARM_BYPASS_PORT: o << "BYPASS_PORT"; break;
        case NT_CONFIG_PARM_BYPASS_ADAPTER_WATCHDOG_TIMEOUT: o << "BYPASS_ADAPTER_WATCHDOG_TIMEOUT"; break;
        case NT_CONFIG_PARM_BYPASS_PORT_WATCHDOG_TIMEOUT: o << "BYPASS_PORT_WATCHDOG_TIMEOUT"; break;
        case NT_CONFIG_PARM_BYPASS_ADAPTER_WATCHDOG_TIMER: o << "BYPASS_ADAPTER_WATCHDOG_TIMER"; break;
        case NT_CONFIG_PARM_BYPASS_PORT_WATCHDOG_TIMER: o << "BYPASS_PORT_WATCHDOG_TIMER"; break;
        case NT_CONFIG_PARM_ADAPTER_GLOBAL_SYNC: o << "ADAPTER_GLOBAL_SYNC"; break;
        case NT_CONFIG_PARM_NIM_ACCESS: o << "NIM_ACCESS"; break;
        case NT_CONFIG_PARM_VPD: o << "VPD"; break;
        case NT_CONFIG_PARM_PTP_PORT: o << "PTP_PORT"; break;
        case NT_CONFIG_PARM_ADAPTER_TIMESYNC_RESET: o << "ADAPTER_TIMESYNC_RESET"; break;
        case NT_CONFIG_PARM_ADAPTER_PTP_IMPL_CFG: o << "ADAPTER_PTP_IMPL_CFG"; break;
        case NT_CONFIG_PARM_PORT_COMPAT_1: o << "PORT_COMPAT_1"; break;
        case NT_CONFIG_PARM_ADAPTER_MONITOR: o << "ADAPTER_MONITOR"; break;
        case NT_CONFIG_PARM_PORT_TRANSMIT_ON_TIMESTAMP: o << "PORT_TRANSMIT_ON_TIMESTAMP"; break;
        case NT_CONFIG_PARM_PORT_SETTINGS_V2: o << "PORT_SETTINGS_V2"; break;
    }
    return o;
}

inline std::ostream &operator<<(std::ostream &o, NtEventTimeSyncStateMachine_e e)
{
    switch (e) {
        case NT_EVENT_TIMESYNC_TIME_REFERENCE_LOST: o << "TIME_REFERENCE_LOST"; break;
        case NT_EVENT_TIMESYNC_TIME_REFERENCE_SELECT: o << "TIME_REFERENCE_SELECT"; break;
        case NT_EVENT_TIMESYNC_TIME_REFERENCE_SELECT_FAIL: o << "TIME_REFERENCE_SELECT_FAIL"; break;
        case NT_EVENT_TIMESYNC_TIME_IN_SYNC: o << "TIME_IN_SYNC"; break;
        case NT_EVENT_TIMESYNC_TIME_OUT_OF_SYNC: o << "TIME_OUT_OF_SYNC"; break;
        case NT_EVENT_TIMESYNC_PTP_STATE_CHANGE: o << "PTP_STATE_CHANGE"; break;
        case NT_EVENT_TIMESYNC_TIME_STAMP_CLOCK_SET: o << "TIME_STAMP_CLOCK_SET"; break;
        case NT_EVENT_TIMESYNC_EXTERNAL_DEVICE_LOST_SYNC_SIGNAL: o << "EXTERNAL_DEVICE_LOST_SYNC_SIGNAL"; break;
        case NT_EVENT_TIMESYNC_EXTERNAL_DEVICE_OUT_OF_SYNC: o << "EXTERNAL_DEVICE_OUT_OF_SYNC"; break;
        case NT_EVENT_TIMESYNC_EXTERNAL_DEVICE_LOST_TIME_OF_DAY: o << "EXTERNAL_DEVICE_LOST_TIME_OF_DAY"; break;
    }
    return o;
}
inline std::ostream &operator<<(std::ostream &o, NtTimeSyncReference_e e)
{
    switch (e) {
        case NT_TIMESYNC_REFERENCE_INVALID: o << "INVALID"; break;
        case NT_TIMESYNC_REFERENCE_FREE_RUN: o << "FREE_RUN"; break;
        case NT_TIMESYNC_REFERENCE_PTP: o << "PTP"; break;
        case NT_TIMESYNC_REFERENCE_INT1: o << "INT1"; break;
        case NT_TIMESYNC_REFERENCE_INT2: o << "INT2"; break;
        case NT_TIMESYNC_REFERENCE_EXT1: o << "EXT1"; break;
        case NT_TIMESYNC_REFERENCE_OSTIME: o << "OSTIME"; break;
    }
    return o;
}
inline std::ostream &operator<<(std::ostream &o, NtPTPPortState_e e)
{
    switch (e) {
        case NT_PTP_PORT_STATE_NA: o << "NA"; break;
        case NT_PTP_PORT_STATE_INIT: o << "INIT"; break;
        case NT_PTP_PORT_STATE_FAULTY: o << "FAULTY"; break;
        case NT_PTP_PORT_STATE_DISABLED: o << "DISABLED"; break;
        case NT_PTP_PORT_STATE_LISTENING: o << "LISTENING"; break;
        case NT_PTP_PORT_STATE_PRE_MASTER: o << "PRE_MASTER"; break;
        case NT_PTP_PORT_STATE_MASTER: o << "MASTER"; break;
        case NT_PTP_PORT_STATE_PASSIVE: o << "PASSIVE"; break;
        case NT_PTP_PORT_STATE_UNCALIBRATED: o << "UNCALIBRATED"; break;
        case NT_PTP_PORT_STATE_SLAVE: o << "SLAVE"; break;
        case NT_PTP_PORT_STATE_INACTIVE: o << "INACTIVE"; break;
    }
    return o;
}

static void print_event(std::ostream &o, nt::Info_Stream &info, const NtEvent_t &e)
{
    switch (e.type) {
        case NT_EVENT_SOURCE_NONE:
        case NT_EVENT_SOURCE_ALL:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER0:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER1:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER2:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER3:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER4:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER5:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER6:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ADAPTER7:
        case NT_EVENT_LISTEN_TIMESTAMP_SAMPLE_ALL:
            // ignore
            break;
        case NT_EVENT_SOURCE_PORT:
            o << "Port " << unsigned(e.u.portEvent.portNo) << ": " << e.u.portEvent.action << '\n';
            break;
        case NT_EVENT_SOURCE_SENSOR:
            {
            NtInfo_t req {
                .cmd  = NT_INFO_CMD_READ_SENSOR,
                    .u = { .sensor = {
                        .source = e.u.sensorEvent.source,
                        .sourceIndex = e.u.sensorEvent.sourceIndex,
                        .sensorIndex = e.u.sensorEvent.sensorIndex
                    } }
            };
            info.read(req);
            const char *name = "NA";
            if (req.u.sensor.data.state != NT_SENSOR_STATE_NOT_PRESENT)
                name = req.u.sensor.data.name;
            o << "Sensor " << name  << "(" << e.u.sensorEvent.sensorIndex << "@"
                << e.u.sensorEvent.source << " " << e.u.sensorEvent.sourceIndex
                << ") value alarm: " << e.u.sensorEvent.value;
            if (req.u.sensor.data.state != NT_SENSOR_STATE_NOT_PRESENT)
                o << ' ' << req.u.sensor.data.type;
            if (req.u.sensor.data.subType != NT_SENSOR_SUBTYPE_NA)
                o << ' ' << req.u.sensor.data.subType;
            o << " [" << e.u.sensorEvent.action << " state]\n";
            }
            break;
        case NT_EVENT_SOURCE_CONFIG:
            o << "Configuration changed: " << e.u.configEvent.parm << '\n';
            break;
        case NT_EVENT_SOURCE_TIMESYNC:
            // ignore since it's too much noise and has low entropy
            // o << "      timesync action:  " << e.u.timeSyncEvent.action << '\n';
            break;
        case NT_EVENT_SOURCE_SDRAM_FILL_LEVEL:
            {
            const NtSDRAMFillLevel_s &s = e.u.sdramFillLevelEvent;
            o << "Buffer alarm for stream ID " <<  s.streamsId
                << " (adapter " << unsigned(s.adapterNo) << "): "
                // i.e. s.size is the SDRAM amount that is reserved for this hostbuffer
                << s.used*100/s.size << "% SDRAM usage (" << s.size << " bytes total), "
                << s.hb.deQueued*100/s.hb.size << "% Hostbuffer usage (" << s.hb.size << " bytes total), "
                << s.hb.enQueued*100/s.hb.size << "% HB-driver usage, "
                << s.hb.enQueuedAdapter*100/s.hb.size << "% HB-adapter usage";
            for (uint32_t i = 0; i < s.numStreams; ++i) {
                o << ", " << s.aStreams[i].enQueued * 100 / s.hb.size  << " % usage of streamIndex " << s.aStreams[i].streamIndex  << " (PID " << s.aStreams[i].processID << ')';
            }
            o << '\n';
            }
            break;
        case NT_EVENT_SOURCE_PTP_PORT:
            o << "PTP Port " << unsigned(e.u.ptpPortEvent.portNo)
                << " (Adapter " << unsigned(e.u.ptpPortEvent.adapterNo) << "): "
                << e.u.ptpPortEvent.action << '\n';
            break;
        case NT_EVENT_SOURCE_TIMESYNC_STATE_MACHINE:
            {
            const NtEventTimeSyncStateMachine_s &t = e.u.timeSyncStateMachineEvent;
            o << "Timesync " << t.action << " (adapter " << unsigned(t.adapter) << "): "
                << t.timeReference << ' ';
            if (t.action == NT_EVENT_TIMESYNC_PTP_STATE_CHANGE)
                o << t.ptpState[0] << " -> " << t.ptpState[1];
            else
                o << "@ " << t.timeStampClock << " ns";
            o << '\n';
            }
            break;
    }
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


static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    setup_signal_handlers();

    if (args.systemd) {
        linux::sd_notify(0, "READY=1");
        linux::sd_notify(0, "STATUS=opening streams");
    }

    nt::Library lib;
    nt::Event_Stream events("nt_event_logger", NT_EVENT_SOURCE_ALL & ~NT_EVENT_SOURCE_TIMESYNC);
    nt::Info_Stream info("nt_event_logger_info");

    std::ostream &o = std::cerr;

    if (args.systemd)
        linux::sd_notify(0, "STATUS=listening");

    while (!globally_interrupted) {
        NtEvent_t e = {NT_EVENT_SOURCE_NONE};
        if (!events.read(e, args.timeout_ms)) {
            continue;
        }

        print_event(o, info, e);
    }
    if (args.systemd) {
        linux::sd_notify(0, "STATUS=done");
        linux::sd_notify(0, "STOPPING=1");
    }

    info.close();
    events.close();
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
