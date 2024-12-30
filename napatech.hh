#ifndef NAPATECH_HH
#define NAPATECH_HH

// SPDX-License-Identifier: BSL-1.0
//
// 2022, Georg Sauthoff


#include <nt.h>

#include <exception>
#include <string>

namespace nt {
    inline std::string status_to_str(int status)
    {
        char buf[NT_ERRBUF_SIZE];
        NT_ExplainError(status, buf, sizeof buf);
        return std::string(buf);
    }

    class Error : public std::exception {
        public:
            Error(std::string &&m)
                :
                    m(std::move(m))
            {
            }
            const char *what() const noexcept override
            {
                return m.c_str();
            }
        private:
            std::string m;
    };

    inline void init()
    {
        int status = NT_Init(NTAPI_VERSION);
        if (status != NT_SUCCESS)
            throw Error(status_to_str(status));
    }

    class Library {
        public:
            Library()
            {
                init();
            }
            ~Library()
            {
                // NT_Done is specified to always return NT_SUCCESS
                NT_Done();
            }
    };

    class Config_Stream {
        public:
            Config_Stream(const char *name)
            {
                int status = NT_ConfigOpen(&stream, name);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            void close()
            {
                int status = NT_ConfigClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            void write(NtConfig_t &data)
            {
                int status = NT_ConfigWrite(stream, &data);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            ~Config_Stream()
            {
                if (stream)
                    NT_ConfigClose(stream);
            }
            operator NtConfigStream_t() const { return stream; }

            Config_Stream(const Config_Stream &) =delete;
            Config_Stream &operator=(const Config_Stream &) =delete;
        private:
            NtConfigStream_t stream {0};
    };


    class Info_Stream {
        public:
            Info_Stream(const char *name)
            {
                int status = NT_InfoOpen(&stream, name);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            ~Info_Stream()
            {
                if (stream)
                    NT_InfoClose(stream);
            }
            Info_Stream(const Info_Stream &) =delete;
            Info_Stream &operator=(const Info_Stream &) =delete;

            void close()
            {
                int status = NT_InfoClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            void read(NtInfo_t &cmd)
            {
                int status = NT_InfoRead(stream, &cmd);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }

        private:
            NtInfoStream_t stream {0};
    };

    class Stat_Stream {
        public:
            Stat_Stream(const char *name)
            {
                int status = NT_StatOpen(&stream, name);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            void close()
            {
                int status = NT_StatClose(stream);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
                stream = 0;
            }
            ~Stat_Stream()
            {
                if (stream)
                    NT_StatClose(stream);
            }
            void read(NtStatistics_t &s)
            {
                int status = NT_StatRead(stream, &s);
                if (status != NT_SUCCESS)
                    throw Error(status_to_str(status));
            }
            void reset()
            {
                NtStatistics_t s = {
                    .cmd = NT_STATISTICS_READ_CMD_QUERY_V3,
                    .u = { .query_v3 = {
                        .poll  = 1,
                        .clear = 1
                      }
                    }
                };
                read(s);
            }

            Stat_Stream(const Stat_Stream &) =delete;
            Stat_Stream &operator=(const Stat_Stream &) =delete;
        private:
            NtStatStream_t stream {0};
    };

}


#endif // NAPATECH_HH
