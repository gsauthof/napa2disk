// SPDX-License-Identifier: BSL-1.0
//
// 2022, Georg Sauthoff


#include "linux.hh"


#include <spawn.h>
#include <sys/un.h>
#include <unistd.h>


#include <exception>
#include <iostream>
#include <sstream>
#include <vector>


#include "napa2disk.hh"


extern char **environ;



struct Args {
    int         argc     {0}; 
    char      **argv     {0};
    bool        systemd  {false};
    std::string uds_path { "/var/run/napa2disk/socket" };

    void help(std::ostream &o, const char *argv0)
    {
        o << "Usage: " << argv0 << " -u UDS COMMAND [ARG..]\n"
            "\n"
            "Options:\n"
            "  -D                      integrate with systemd (i.e. notify etc.)\n"
            "  -u UDS                  path to unix domain socket (default: " << uds_path  << ")\n"
            "\n"
            "An arg %%p argument is substituted with the UDS payoad.\n"
            "\n"
            "2023-03-22, Georg Sauthoff\n";
    }
    Args(int argc, char **argv)
    {
        char c = 0;
        // '+' prefix: no reordering of arguments
        // ':': preceding option takes a mandatory argument
        while ((c = getopt(argc, argv, "+Du:")) != -1) {
            switch (c) {
                case '?':
                    {
                        std::ostringstream o;
                        o << "unexpected option : -" << char(optopt) << '\n';
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
                case 'u':
                    uds_path = optarg;
                    if (uds_path.size() > 107)
                        throw std::runtime_error("UDS path too long");
                    break;
            }
        }
        if (optind >= argc) {
            throw std::runtime_error("post-rotate command missing");
        }
        this->argv = argv + optind;
        this->argc = argc - optind;
    }
};


namespace linux {

    inline void bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    {
        int r = ::bind(sockfd, addr, addrlen);
        if (r == -1)
            throw Error(errno_to_str("bind", errno));
    }

    inline ssize_t read(int fd, void *buf, size_t count)
    {
        ssize_t r = ::read(fd, buf, count);
        if (r == -1)
            throw Error(errno_to_str("read", errno));
        return r;
    }

    inline void posix_spawnp(pid_t *pid, const char *path,
	      const posix_spawn_file_actions_t *file_actions,
	      const posix_spawnattr_t *attrp,
	      char ** argv, char **envp)
    {
        int r = ::posix_spawnp(pid, path, file_actions, attrp, argv, envp);
        if (r)
            throw Error(errno_to_str("posix_spawnp", r));
    }

}

static void exit_handler(int)
{
    _exit(0);
}

static void setup_signal_handlers()
{
    {
        struct sigaction sa = { 0 };
        sa.sa_handler = exit_handler;
        for (auto i : { SIGINT, SIGTERM })
            linux::sigaction(i, &sa, 0);
    }

    // auto-reap children
    {
        struct sigaction sa = {
            .sa_flags   = SA_NOCLDWAIT
        };
        sa.sa_handler = SIG_DFL;
        linux::sigaction(SIGCHLD, &sa, 0);
    }
}

static void spawn_cmd(char **argv, char *filename, std::vector<char *> child_argv)
{
    for (size_t i = 0; i < child_argv.size() - 1; ++i) {
        if (strcmp(argv[i], "%p"))
            child_argv[i] = argv[i];
        else
            child_argv[i] = filename;
    }
    pid_t pid = 0;
    linux::posix_spawnp(&pid, child_argv[0], 0, 0, child_argv.data(), environ);
}

static int mainP(int argc, char **argv)
{
    setup_signal_handlers();
    Args args(argc, argv);

    int fd = linux::socket(AF_LOCAL, SOCK_DGRAM, 0);
    struct sockaddr_un addr = {
        .sun_family = AF_LOCAL,
    };
    strcpy(addr.sun_path, args.uds_path.c_str());

    // deliberately ignoring unlink errors
    unlink(addr.sun_path);
    linux::bind(fd, (struct sockaddr*) &addr, sizeof addr);

    if (args.systemd) {
        linux::sd_notify(0, "READY=1");
        linux::sd_notify(0, "STATUS=listening");
    }

    char buf[N2D_FILENAME_MAX] = {0};
    std::vector<char *> child_argv(args.argc + 1);

    for (;;) {
        ssize_t l = linux::read(fd, buf, sizeof buf);
        if (l)
            buf[l-1] = 0;
        else
            buf[0] = 0;
        spawn_cmd(args.argv, buf, child_argv);
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
