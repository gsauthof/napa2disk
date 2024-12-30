
CPPFLAGS = -I$(N2D_NT_PREFIX)/opt/napatech3/include -D_NT_NTAPI_NO_COMPAT
LDFLAGS  = -L$(N2D_NT_PREFIX)/opt/napatech3/lib -Wl,-rpath-link=$(N2D_NT_PREFIX)/opt/napatech3/lib -Wl,-R/opt/napatech3/lib
LDLIBS   = -lntapi -lsystemd -pthread
CXXFLAGS_OPT = -O3
CXXFLAGS = $(CXXFLAGS_MARCH) $(CXXFLAGS_OPT) -g $(CXXFLAGSW_GCC)


CXXFLAGSW_GCC = -Wall -Wextra -Wno-missing-field-initializers \
    -Wno-parentheses -Wno-missing-braces \
    -Wno-unused-local-typedefs \
    -Wfloat-equal \
    -Wpointer-arith -Wcast-align \
    -Wnull-dereference \
    -Wnon-virtual-dtor -Wmissing-declarations \
    -Werror=multichar -Werror=sizeof-pointer-memaccess -Werror=return-type \
    -Werror=delete-non-virtual-dtor \
    -fstrict-aliasing



.PHONY: all
all: napa2disk collect_nt_sensors collect_nt_stats nt_event_logger nt_beacon n2d_spawner

temp = napa2disk napa2disk.o collect_nt_sensors collect_nt_sensors.o collect_nt_stats collect_nt_stats.o nt_event_logger nt_event_logger.o n2d_spawner n2d_spawner.o nt_beacon nt_beacon.o

.PHONY: clean
clean:
	rm -rf $(temp)



n2d_spawner: LDLIBS = -lsystemd

