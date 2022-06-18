<div align="center">
 <h3>Packetatortots Usage</h3>
</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#example-usage-1">Example Usage 1</a>
    </li>
    <li>
      <a href="#example-usage-2">Example Usage 2</a>
    </li>
</ol>
</details>

## Example Usage 1

#### Pcap
In this example we will replay the pcap chunked_16_mal.pcap from _packetator_'s documentation.
<br>
In this pcap, a client (10.141.41.101/24) send a GET request for an Internet Explorer exploit to an HTTP server (10.141.41.1/24).
<br>
The server declares the response chunked and sends the exploit in 16-byte chunks.

#### Replay Config
We will replay this pcap on a packetator node with 2 NICs (ens19, ens20) connected to a switch.
<br>
There is no layer 2 firewall, so we expect the client to receive the exploit completely unmodified.

The replay network is clear of other layer 3 hosts, so we can replay with either CCM `FourTuple` or `FiveTuple` without the need to create a block filter file (`-b`).

We will replay in the default mode L4 since there is no need to replay this pcap in L3 or L5 mode. (See [Additional Configuration Notes](configuration.md#additional-configuration-notes))

We will use the below network interface config file named `~/interface.yaml`:
```yaml
interfaces:
  - name: "ens19" # name of the interface
    subnet: "192.168.0.0/24"
    subnet_v6: "fdda:dddd:bbbb:3333::1:1/64"
    gateway: "192.168.0.1"
    gateway_v6: "fdda:dddd:bbbb:3333::1:1"
    last_bytes_v6: 0xcccccc
  - name: "ens20"
    subnet: "192.168.0.0/24"
    subnet_v6: "fdda:dddd:bbbb:3333::1:1/64"
    gateway: "192.168.0.1"
    gateway_v6: "fdda:dddd:bbbb:3333::1:1"
    last_bytes_v6: 0xaaaaaa
```

#### Command:

```shell
sudo ./packetatortots.py -od ~/output -i ~/interfaces.yaml /opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap
```

#### Explanation

- `-od`: `/tmp/output` will be used for any output files.
- `-i`: Use the interface configuration specified in interfaces.yaml
- `/opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap`: Replay this pcap.

#### Result

A successful replay will print:
```text
[+]     Replaying pcaps...
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00,  5.54it/s]
========== Result Count Summary ==========
        replay success: 1/1
        replay failure: 0/1
          not replayed: 0/1
```

In this case the expected result is `replay success: 1/1`,
since there were no security controls in place.


## Example Usage 2

#### Pcap
In this example we will replay a general set of pcaps such as the pcaps from _packetator_'s documentation.
<br>
The contents of the pcaps are not known ahead of time.
<br>

#### Replay Config
We will replay this pcap on a packetator node with 2 NICs (ens19, ens20) connected to a layer 2 device that
may or may not modify traffic.
<br>
So we will assume we must replay with CCM `FourTuple`.

The replay network is NOT clear of other traffic from other hosts,
so we need to create a block filter file (`-b`).

The block file named `~/block.yaml`:
```yaml
---
mac:
  - "00:50:cc:cc:cc:cc"
  - "00:50:cc:cc:cc:dd"
  - "00:50:cc:cc:cc:ee"
ipv4:
  - "192.168.0.99"
  - "192.168.0.123"
ipv6:
  - "fdda:dddd:bbbb:3333::1:2/64"
```

Some of the pcaps in the set may need to be replayed in a mode other than the default mode L4.
We will need to create a modes csv. (See [Additional Configuration Notes](configuration.md#additional-configuration-notes))

For this example, we'll assume that chunked_16_mal.pcap must be replayed in L5 mode,
even though that is not the case.
<br>
The modes file named `~/modes.csv`:
```csv
chunked_16_mal.pcap,L5,MAX
```

We will use the network interface config file defined in [Example Usage 1](#example-usage-1).

#### Command:

```shell
sudo ./packetatortots.py -d -t 300 -N 3 -b ~/block.yaml -o ~/results.csv -dm L4 -m ~/modes.csv -od ~/output -j 40 -zd ~/zips -i ~/interfaces.yaml /opt/packetator/share/doc/packetator/pcap -- --ccm FourTuple -w
```

#### Explanation

- `-d`: Run in debug mode. An additional file named `debug.txt` will be created in each run's output directory.
- `-t 300`: Set a timeout of 300 seconds for each pcap replay. After 300 seconds the specific timed out replay will be terminated.
- `-N 3`: Replay each pcap a total of 3 times.
- `-b ~/block.yaml`: Block traffic from the other hosts on the replay network listed using blocklists defined in `~/block.yaml`. 
- `-o ~/results.csv`: Output the results in csv format to `~/results.csv`.
- `-dm L4`: Run pcaps in L4 mode.
- `-m ~/modes.csv`: For pcaps with an entry in `~/modes.csv`, the specified minimum and maximum modes will be applied.
- `-od ~/output`: The `~/output` directory will be used for any output files.
- `-j 40`: Replay upto 40 pcaps in parallel.
- `-zd ~/zips`: The `~/zips` directory will be used for the archives of the packet captures of the replayed traffic.
- `-i ~/interfaces.yaml`: Use the interface configuration specified in `~/interfaces.yaml`.
- `/opt/packetator/share/doc/packetator/pcap`: Replay this directory of pcaps.
- `--`: The arguments after this will be passed onto the _packetator_ program.
- `--ccm FourTuple`: Use the 4-tuple `(sip, dip, serverport, proto)` instead of the 5-tuple `(sip, dip, sport, dport, proto)` to correlate connections between the pcap and live traffic. `--ccm FourTuple` is required when an inline TCP or UDP proxy changes the connection 5-tuples across each side of the proxy.
- `-w`: Take a packet capture of the replayed traffic. For each pcap run, each host will have its own packet capture file.

If promiscuous mode was enabled, then one might take advantage of the following arguments (before `--`):
- `-rm`: Randomize MAC addresses.
- `-ri6`: Randomize the last 3 bytes of IPv6 addresses.

If the replay network was routed, then one must add (after `--`):
- `-r`: Run in routed mode and use the gateway that was specified in `~/interfaces.yaml`.

#### Result

A successful replay will print:
```text
[+]     Replaying pcaps...
100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 18/18 [00:01<00:00, 12.99it/s]
[+]     Compressing pcaps...
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6/6 [00:00<00:00, 405.83it/s]
========== Result Summary ==========
        replay success: 6/6
        replay failure: 0/6
          not replayed: 0/6
```
