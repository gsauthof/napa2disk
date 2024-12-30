The purpose of the `n2d_spawner` process is to spawn a
post-rotate command whenever a PCAP file is rotated.

## Example

```
# cat <<EOF > /etc/sysconfig/n2d_spawner 
n2d_spawner_flags = /path/to/cmd/like/some-queue-client add %p
EOF
# systemctl enable n2d_spawner -now
# cat <<EOF > /etc/sysconfig/napa2disk@0 
n2d_flags = -u /run/napa2disk/socket
EOF
# systemctl restart napa2disk@0
```

## How it Works

When supplying the `-u` option, napa2disk non-blocking sends to
the specified unix domain socket (UDS) each finished PCAP filename.
When the `n2d_spawner` service is running, it listens on that
socket and spawns the configured command while substituting the
`%p` placeholder with that finished PCAP filename.

NB: by default, relative filename are sent, cf. the `-f` option
for specifying an absolute path pattern.

Note that it doesn't matter whether the UDS exists or not when
napa2disk starts. It's created and removed by the `n2d_spawner`
service and since napa2disk uses non-blocking sends to an
unconnected UDS, `n2d_spawner` starts/resumes to receive
filenames whenever it's started and those filenames are simply
lost in space whenever it's stopped (i.e. without impacting the
sender).

This UDS design is used to avoid any side-effects from forking
directly out of the capture process, such as having to reason about
fork-safety and blocking of the capturing due to forking on a
busy system.
IOW, this design retains the robustness of the capturing system.

NB: On a reasonable busy capturing port, the minute rotation
happens just an epsilon away from the start of the minute.
However, when the port has periods were really zero packets are
arriving, the next rotation really happens whenever the next
packet in another minute arrived.
Thus, it's also possible to have a rotation from minute x to x+2,
or similar.
