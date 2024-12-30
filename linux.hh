#ifndef LINUX_HH
#define LINUX_HH

// SPDX-License-Identifier: BSL-1.0
//
// 2022, Georg Sauthoff

#include <exception>
#include <string>
#include <sstream>
#include <signal.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <string.h> // strerror()

#include <systemd/sd-daemon.h> // sd_notify()

// GCC defines it in some -std= settings
#ifdef linux
    #undef linux
#endif
namespace linux {


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

    inline std::string errno_to_str(const char *name, int e)
    {
        std::ostringstream o;
        o << name << ": " << strerror(e);
        return o.str();
    }

    inline void sd_notify(int unset_environment, const char *state)
    {
        int r = ::sd_notify(unset_environment, state);
        if (r == -1)
            throw Error(errno_to_str("sd_notify", errno));
    }

    inline void sigaction(int signum, const struct sigaction *act,
        struct sigaction *oldact)
    {
        int r = ::sigaction(signum, act, oldact);
        if (r == -1)
            throw Error(errno_to_str("sigaction", errno));
    }

    inline int socket(int domain, int type, int protocol)
    {
        int r = ::socket(domain, type, protocol);
        if (r == -1)
            throw Error(errno_to_str("socket", errno));
        return r;
    }

    inline int timerfd_create(int clockid, int flags)
    {
        int r = ::timerfd_create(clockid, flags);
        if (r == -1)
            throw Error(errno_to_str("timerfd_create", errno));
        return r;
    }

    inline void  timerfd_settime(int fd, int flags,
            const struct itimerspec *new_value,
            struct itimerspec *old_value)
    {
        int r = ::timerfd_settime(fd, flags, new_value, old_value);
        if (r == -1)
            throw Error(errno_to_str("timerfd_settime", errno));
    }

    inline time_t time(time_t *t)
    {
        time_t r = ::time(t);
        if (r == (time_t)-1)
            throw Error(errno_to_str("time_t", errno));
        return r;
    }

}

#endif // LINUX_HH
