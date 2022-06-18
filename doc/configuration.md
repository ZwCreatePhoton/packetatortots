<div align="center">
 <h3>Packetatortots Configuration</h3>
</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#command-line">Command Line</a>
    </li>
    <li>
      <a href="#network-interface-configuration">Network Interface Configuration</a>
    </li>
    <li>
      <a href="#filter-traffic">Filter Traffic</a>
    </li>
    <li>
      <a href="#modes">Modes</a>
    </li>
    <li>
      <a href="#mode-configuration">Mode Configuration</a>
    </li>
    <li>
      <a href="#additional-configuration-notes">Additional Configuration Notes</a>
    </li>
</ol>
</details>

## Command Line

```text
./packetatortots.py --help
usage: packetatortots [-h] [--version] [-d] [-N N] [-t seconds] [-dm {MIN,L3,L4,L5,MAX}] [-m FILE] [-j N] [-o FILE] [-od DIR] [-zd DIR] [-b FILE] [-rm] [-ri6] -i
                      FILE
                      pcaps_path [packetator_args ...]

positional arguments:
  pcaps_path            pcap or directory of pcaps to replay
  packetator_args       "--" followed by arguments to pass along to packetator for all replays. run: "packetator --help" for more info (default: None)

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -d, --debug           debug output ; replay errors are not treated as replay failures (default: False)
  -N N, --iterations N  Number of iterations (default: 3)
  -t seconds, --timeout seconds
                        Timeout to wait for the packetator subprocess to complete. Useful for when reply gets stuck in a loop (default: 600)
  -dm {MIN,L3,L4,L5,MAX}, --dmode {MIN,L3,L4,L5,MAX}
                        Default mode to replay pcaps in (default: L4)
  -m FILE, --modes FILE
                        Line delimited file that maps pcap filenames to a minimum and maximum mode: example.pcap,L4,L5 (default: example_modes.csv)
  -j N, --jobs N        Number of pcaps to replay in parallel (default: 80)
  -o FILE, --outfile FILE
                        output file, in CSV format. (Columns: pcap basename, mode, success count, number of iterations, overall result, result 1, result 2, ...,
                        ip addresses 1, ip addresses 2, ...) (default: None)
  -od DIR, --outdir DIR
                        output directory (default: out)
  -zd DIR, --zipdir DIR
                        output directory to place compressed zips of any generated pcaps (default: None)
  -b FILE, --blocklist FILE
                        yaml document with addresses to blocklist. (default: None)
  -rm, --randommac      use random mac addresses. promiscuous mode is required (default: False)
  -ri6, --randomip6     randomize the last 3 bytes of IPv6 addresses as well. promiscuous mode is required (default: False)
  -i FILE, --interfaces FILE  YAML document that specifies the interface(s) to use (default: example_nics.yaml)
```

To define which interfaces to use, use the `-i` / `--interfaces` flag to specify the interface configuration YAML file.
See [Interface Configuration](#interface-configuration) for more details.

To define the number of pcaps to replay in parallel use the `-j` flag.
As a rule of thumb, use 10 * number of logical cores or greater.
This is the default.
_Packetatortots_ is CPU intensive so increasing this number might not
speed up the replays unless if a high timeout is set and if an in-line
device is blocking the majority of the traffic.

To filter out incoming traffic, use the -b switch to specify a block yaml file.
See the [Filter Traffic](#filter-traffic) section for more details.
This option can be used to fix inaccurate replays with the `--ccm FourTuple`
_packetator_ option.

To define the replay mode(s) to use, use the `-dm` flag to define the default mode
and the `-m` flag to define mode ranges for specific pcaps.
See [Mode Configuration](#mode-configuration) for more details.

To define the directory used for saving pcaps, use the `-od` flag.
Pcaps will be saved to path that follows the below format:
```text
{directory specified by -od}/{pcap file name}/{iteration number}/{original ip address}_{replayed ip address}.pcap
```

All arguments after the `pcaps_path` argument will be passed to _packetator_.

For additional parameters, vist the _packetatortot_'s help menu using the `--help` flag.


## Network Interface Configuration

The interfaces _packetatortots_ uses are defined using a yaml file.
```yaml
interfaces: # number of interfaces must be 2
  - name: "ens19" # name of the interface
    subnet: "192.168.0.0/24" # IPv4 subnet in CIDR notation
    subnet_v6: "fdda:dddd:bbbb:3333::1:1/64" # IPv6 subnet in CIDR notation
    gateway: "192.168.0.1" # default IPv4 gateway
    gateway_v6: "fdda:dddd:bbbb:3333::1:1" # default IPv6 gateway
    last_bytes_v6: 0xcccccc # last bytes for the random IPv6 addresses generated ; Needs to match at the last 3 bytes of an IPv6 address assigned to this interface
  - name: "ens20"
    subnet: "192.168.0.0/24"
    subnet_v6: "fdda:dddd:bbbb:3333::1:1/64"
    gateway: "192.168.0.1"
    gateway_v6: "fdda:dddd:bbbb:3333::1:1"
    last_bytes_v6: 0xaaaaaa
```
To replay IPv6 traffic, each interface used should have an IPv6 address
assigned and the last 3 bytes of the address should be the value of the
`last_bytes_v6` filed in the interface config file.

## Filter Traffic

See [packetator Filter Traffic](https://github.com/ZwCreatePhoton/packetator/blob/main/doc/configuration.md#filter-traffic).


## Modes

The available modes are:
- MIN
- L3
- L4
- L5
- MAX


Modes are ordered with the following order:
```text
MIN = L3 < L4 < L5 = MAX
```

Higher modes will result in a greater difference between the traffic
in the capture files and the traffic on the wire. Also, higher modes
will be more resilient to changes an inline device might make to the
traffic.

#### MIN
This is defined to be the lowest mode. Currently, L3.

#### L3
This mode uses packet count to determine what and when to replay
traffic.
Transport layer data is replayed as-is. Transport layer state is
not considered.
IP addresses will be randomized.
Only use this mode when necessary since packet counting is not a
dependable validation metric.
If a pcap contains fragments and if the fragments are essential,
then this mode must be used.
See L3.yaml and the config settings from [packetator's
documentation](https://github.com/ZwCreatePhoton/packetator/blob/main/doc/configuration.md#config-settings)
for lower-level details on how this mode works.

#### L4
This mode uses Transport level state to determine what and when
to replay traffic.
Application layer data is replayed as-is. Application layer
state is not considered.
IP addresses will be randomized.
This mode randomizes client port numbers, corrects acknowledgment
numbers, and corrects timestamps.
This mode is resilient to changes a TCP proxy might make to fields
such as seq/ack, options, client’s source ports.
This mode is the de facto standard mode.
See L4.yaml and the config settings from [packetator's
documentation](https://github.com/ZwCreatePhoton/packetator/blob/main/doc/configuration.md#config-settings)
for lower-level details on how this mode works.

#### L5
This mode uses Application layer state in addition to some Transport
layer state to determine what and when to replay traffic.
Only pcaps with UDP:DNS, TCP:HTTP, or TCP:FTP protocols will benefit
from this mode.
IP addresses will be randomized.
Application layer data may be altered.
This mode is resilient to changes a DNS proxy might make to fields.
This mode is resilient to changes an HTTP proxy might make such as
changes to the headers or normalization of the body.
This mode should be used if an intermediary device modifies
application layer data.
This mode should not be used when replaying pcaps that contain HTTP
or DNS DoS exploits that DoS _packetator_ (program may crash or halt
forever). 
This mode comes at the cost of performance and should be used on a
case by case basis.
If a pcap contains Passive FTP, this mode should be used to replay
correctly.
See L5.yaml and the config settings from [packetator's
documentation](https://github.com/ZwCreatePhoton/packetator/blob/main/doc/configuration.md#config-settings)
for lower-level details on how this mode works.

#### MAX
This is defined to be the highest mode. Currently, L5.


## Mode Configuration

Modes can be set on a per pcap basis using a csv file with rows
with the format: 
```text
<pcap filename>,<minimum mode>,<maximum mode>
```
Any pcaps not defined in the modes csv file will run in the
default mode.


## Additional Configuration Notes

Use of a high timeout (`-t`) is recommended.
For example, 5 minutes or 300 seconds.
This high timeout is so that a single run doesn't get stuck and ruin the batch run.

The recommended number of iterations (`-N`) is 3.
Not all pcaps replay with 100% reliability.
Reliability decreases when you introduce a firewall in and when you replay at max load.
To compensate, 3 iterations is sufficient.
A replay success is defined as a replay success in any of the 3 runs.

Use L4 as the default mode (-dm).
Modes higher than L4 will not provide any benefit and will hurt performance for the
majority of pcaps.
See the L3 and L5 mode descriptions for exception cases.
<br>
In general:
- Pcaps with fragments should be played in mode: <= L3
- Pcaps with SCTP should be played (due to lack of an SCTP implementation) in mode: <= L3
- Pcaps without transport layer protocols should be played in mode: <= L3 (but > L3 would still work)
- Pcaps with passive FTP should be played in mode: >= L5
- Some application layer DoS exploits should be played in mode: < L5

If an inline device has different 5 tuples on both sides of their UDP/TCP proxies then you must use
the _packetator_ parameter: `--ccm FourTuple` otherwise use `--ccm FiveTuple`.

For example, a layer 2 firewall may implement a TCP proxy that alters the client's source port. In this case, use `--ccm FourTuple`.
