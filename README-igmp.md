When capturing multicast traffic there are basically two
possibilities how to connect a capture port:

1) using some kind of TAP device that mirrors the multicast
   traffic that is subscribed by other entities
2) connecting to a normal L2 switch port like a normal
   participant and actively subscribing to all interesting
   multicast groups

The primary purpose of the `nt_beacon` service is to periodically
transmit LLDP frames for easier identification of the capture
ports on L1 and L2 switches.

However, it also supports transmitting IGMP v2 membership reports
for setups where the captured multicast traffic need to be
explicitly subscribed (i.e. when there are TAPs/static
subscriptions, cf. the 2nd bullet point).

## Example IGMP Setup

Specify source IP addresses and all multicast IP addresses that
should be subscribed for each capture port in - say -
`/etc/sysconfig/nt_beacon_igmp.ini` - which might look like this:


```
[port0]
source 203.0.113.23

join 239.23.23.128
join 239.23.23.129


[port1]
source 203.0.113.42

join 239.23.23.137
join 239.23.23.138
join 239.23.23.139
```

As you see it's a simple INI-style configuration file where a `#`
starts a line comment.

To activate the configuration it has to be referenced from
`/etc/sysconfig/nt_beacon` like this:

```
nt_beacon_flags = -i /etc/sysconfig/nt_mcast.ini
```

Finally, the `nt_beacon` service has to be restarted:

```
systemctl restart nt_beacon
```


## How it works

The `nt_beacon` service transmits LLDP frames every 30 seconds
on each port, relative to its program start time.

For each specified multicast IP address (cf. `join` directive) it
sends a IGMP v2 membership report to the group's address (cf.
the `source` directive). Those report frames are evenly
distributed over the specified IGMP transmission window (cf. the
`-w` option, the default is 10 seconds).


