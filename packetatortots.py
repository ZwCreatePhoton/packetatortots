#!/usr/bin/python3

from multiprocessing import cpu_count
from multiprocessing.pool import ThreadPool
from subprocess import run, TimeoutExpired
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address
from random import getrandbits, randrange
from operator import itemgetter
from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
from zipfile import ZIP_DEFLATED, ZipFile
from shutil import which
from os import walk, listdir, mkdir
from os.path import abspath, expanduser, join, basename, isdir, splitext, realpath, dirname


import dpkt
import tqdm
import yaml


# global constants
DEBUG_FILENAME = "debug.txt"

PCAP_FILE_EXTENSIONS = [".pcap"]

REPLAY_SUCCESS = "replay success"
REPLAY_FAILURE = "replay failure"
REPLAY_NOT = "not replayed"
REPLAY_ERROR = "replay error"
REPLAY_UNKNOWN = "unknown replay result"


# globals
results = dict()
debug = None
output_dir = None
timeout = None
packetator = None


def search_directory(path, target):
    for p, d, f in walk(path):
        for x in (d + f):
            if x == target:
                return join(p, x)


def locate_packetator():
    binary_name = "packetator"
    config_name = "L4.yaml"

    def locate_packetator_install_directory(install_dir=None):
        potential_install_dirs = [
            "/opt/packetator",
            "/opt",
            "/usr/local",
            "/usr",
        ]
        which_packetator = which(binary_name)
        if which_packetator is not None:
            real_bin_path = realpath(which_packetator)
            which_install_path = realpath(join(real_bin_path, "..", ".."))
            potential_install_dirs = potential_install_dirs.insert(0, abspath(which_install_path))
        if install_dir is not None:
            potential_install_dirs = potential_install_dirs.insert(0, abspath(install_dir))
        for potential_install_dir in potential_install_dirs:
            packetator_binary_path = search_directory(potential_install_dir, binary_name)
            if packetator_binary_path is not None:
                return potential_install_dir
        raise Exception("Count not locate packetator installation in any of the directories: {}"
                        .format(potential_install_dirs))

    install_dir = locate_packetator_install_directory()
    binary_path = search_directory(install_dir, binary_name)
    config_dir = dirname(search_directory(install_dir, config_name))
    if config_dir is None:
        raise Exception("Count not locate the configs directory in the installation directory: {}"
                        .format(install_dir))
    modes = [config.split(".")[0] for config in listdir(config_dir)]
    return {
        "binary_path": binary_path,
        "config_dir": config_dir,
        "modes": modes
    }


packetator = locate_packetator()


def run_packetator(arguments):
    cmd = tuple(arguments[0])
    meta = arguments[1]
    iteration_count = meta["iteration_count"]

    pcap_path_index = None
    for i in range(len(cmd)):
        if cmd[i] == "-p":
            pcap_path_index = i + 1
            break
    pcap_filepath = cmd[pcap_path_index]
    if "'" in pcap_filepath:
        pcap_filepath = pcap_filepath.split("'")[1]
    base = basename(pcap_filepath)
    pcap_output_dir = join(output_dir, base)
    try:
        mkdir(pcap_output_dir)
    except:
        pass
    pcap_output_dir = join(pcap_output_dir, str(iteration_count))
    try:
        mkdir(pcap_output_dir)
    except:
        pass

    cmdline = " ".join(c.replace(' ', '\\ ') for c in cmd)  # escape spaces
    result = REPLAY_UNKNOWN
    stdout = ""
    stderr = ""
    returncode = 0
    try:
        completed_process = run(cmd, capture_output=True, text=True, cwd=pcap_output_dir, timeout=timeout)
        stdout = completed_process.stdout
        stderr = completed_process.stderr
        returncode = completed_process.returncode
        if "Packet replay was successful" in stdout:
            result = REPLAY_SUCCESS
        elif "Packet replay was not successful" in stdout:
            result = REPLAY_FAILURE
        else:
            if returncode != 0:
                if debug:
                    result = "error (" + str(returncode) + ")"
                else:
                    result = REPLAY_FAILURE
            else:
                result = REPLAY_UNKNOWN
    except TimeoutExpired:
        returncode = 1001
        if debug:
            result = "error (" + str(returncode) + ")"
        else:
            result = REPLAY_FAILURE

    results[cmd] = result
    with open(join(pcap_output_dir, "result.txt"), "w") as f:
        f.write(result)

    if debug:
        with open(join(pcap_output_dir, DEBUG_FILENAME), "w") as f:
            f.write("Cmdline: " + cmdline + "\n")
            f.write("Exit code: " + str(returncode) + "\n")
            f.write("Stdout:" + "\n")
            f.write(stdout)
            f.write("Stderr:" + "\n")
            f.write(stderr)


# returns the number of edges connected to vertex v
def count_pairs(E, v):
    count = 0
    for e in E:
        if v in e:
            count += 1
    return count


# returns the node/vertex with the greatest number of edges to other nodes/vertices
def most_popular_node(V, E):
    count_map = {v: count_pairs(E, v) for v in V}  # maps host -> count
    if len(count_map) == 0:
        return None
    return max(count_map.items(), key=itemgetter(1))[0]


def distribute_nodes(N, V, E):
    """
    Graph-theory based algorithm to determine the interfaces to use for each replayed host.
    Ensures that each replayed connection traverses the switch or firewall.
    Only tested against the easier case where there are at most 2 networks (N = 2)
    This function assumes that N = 2.

    :param N: number of partitions
    :param V: set of vertices used to define the graph
    :param E: set of edges (2-tuple) that define the graph
    :return: N element list of sets of hosts if successful, otherwise return None when it is impossible to distribute
    the nodes across the N partitions
    """
    assert N == 2
    partitions = [set() for n in range(N)]
    popular_node = most_popular_node(V, E)
    if popular_node is None:
        partitions[0].update(V)
        return partitions
    partitions[0].add(popular_node)
    processed_nodes = set()
    while any((current_node := v) not in processed_nodes for i in range(len(partitions)) for v in partitions[i]):
        current_partition_index = None
        for i in range(len(partitions)):
            if current_node in partitions[i]:
                current_partition_index = i
        for e in E:
            if e[0] == current_node:
                partitions[(current_partition_index + 1) % len(partitions)].add(e[1])
            elif e[1] == current_node:
                partitions[(current_partition_index + 1) % len(partitions)].add(e[0])
        processed_nodes.add(current_node)
    if len(V) != len(processed_nodes):
        # The remaining nodes are not connected to the nodes already processed
        V2 = {h for h in V if h not in processed_nodes}
        E2 = {p for p in E for h in processed_nodes if h not in p}
        result2 = distribute_nodes(N, V2, E2)
        if result2 is None:
            return None
        for i in range(len(partitions)):
            partitions[i].update(result2[i])
    return partitions


def test_distribute_nodes():
    test_cases = [
        (2, {}, {}),
        (2, {"A"}, {}),
        (2, {"A", "B"}, {}),
        (2, {"A", "B"}, {("A", "B")}),
        (2, {"A", "B", "C"}, {("A", "B")}),
        (2, {"A", "B", "C"}, {("A", "B"), ("B", "C")}),
        (2, {"A", "B", "C"}, {("A", "B"), ("B", "C"), ("C", "A")}),
        (2, {"A", "B", "C", "D"}, {("A", "B")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "A")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "D")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "A")}),
        (2, {"A", "B", "C", "D", "E"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "A")}),
        (2, {"A", "B", "C", "D", "E", "F"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "A")}),
        (2, {"A", "B", "C", "D", "E", "F", "G"},
         {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "G"), ("G", "A")}),
        (2, {"A", "B", "C", "D", "E", "F", "G", "H"},
         {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "G"), ("G", "H"), ("H", "A")}),
    ]
    for test_case in test_cases:
        N, V, E = test_case
        results = distribute_nodes(N, V, E)
        contradiction = False
        for v in V:
            partitions = [p for p in results if v in p]
            if len(partitions) > 1:
                contradiction = True
                break
        print(test_case)
        print("\t" + ("*" if contradiction else "") + str(results))


def random_bytes(num=6):
    return [randrange(256) for _ in range(num)]


def generate_mac(uaa=False, multicast=False, oui=None, separator=':', byte_fmt='%02x'):
    mac = random_bytes()
    if oui:
        if type(oui) == str:
            oui = [int(chunk) for chunk in oui.split(separator)]
        mac = oui + random_bytes(num=6 - len(oui))
    else:
        if multicast:
            mac[0] |= 1  # set bit 0
        else:
            mac[0] &= ~1  # clear bit 0
        if uaa:
            mac[0] &= ~(1 << 1)  # clear bit 1
        else:
            mac[0] |= 1 << 1  # set bit 1
    return separator.join(byte_fmt % b for b in mac)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    try:
        return inet_ntop(AF_INET, inet)
    except ValueError:
        return inet_ntop(AF_INET6, inet)


# returns a 2-tuple where
# 0.) set of hosts
# 1.) set of 2-tuples of two connected hosts
def parse_pcap(pcap_path):
    H = set()
    E = set()
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6):
                if isinstance(eth.data, dpkt.ip6.IP6) and eth.data.p == 58:  # skipping ICMPv6 / NDP
                    continue
                src, dst = inet_to_str(eth.data.src), inet_to_str(eth.data.dst)
                H.add(src)
                H.add(dst)
                if (src, dst) not in E and (dst, src) not in E:
                    E.add((src, dst))
            else:
                pass
    return H, E


def random_ipv4_address(subnet_string):
    subnet = IPv4Network(subnet_string, False)
    bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen)
    addr = IPv4Address(subnet.network_address + bits)
    return str(addr)


def random_ipv6_address(subnet_string, lastbytes=b''):
    subnet = IPv6Network(subnet_string, False)
    bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen - len(lastbytes) * 8)
    addr = IPv6Address(subnet.network_address + (bits << len(lastbytes) * 8) + int.from_bytes(lastbytes, "big"))
    return str(addr)


def parse_interfaces(interfaces_yaml):
    interfaces = []
    with open(interfaces_yaml) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        for interface in data['interfaces']:
            interface['last_bytes_v6'] = interface['last_bytes_v6'].to_bytes((interface['last_bytes_v6'].bit_length() + 7) // 8, "big")
            interfaces.append(interface)
    return interfaces


def parse_blocklist(blocklist_yaml):
    with open(blocklist_yaml) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        return data


def compress_pcaps(zipdir, outdir, iteration_results, ip_maps):
    try:
        mkdir(zipdir)
    except:
        pass
    p_filepaths_dict = {}
    for pcap_filepath in iteration_results:
        pcap_basename = basename(pcap_filepath)
        p_filepaths = []
        for i in range(len(iteration_results[pcap_filepath])):
            ip_maps_key = (pcap_filepath, i)
            ip_map = ip_maps[ip_maps_key]
            for k, v in ip_map.items():
                p_filename = "{}_{}.pcap".format(k, v)
                p_filepath = join(outdir, pcap_basename, str(i + 1), p_filename)
                p_filepaths.append(p_filepath)
        if p_filepaths:
            p_filepaths_dict[pcap_basename] = p_filepaths

    def zip_files(args):
        zip_filename, filepaths, compresslevel = args
        if filepaths:
            compression = ZIP_DEFLATED
            zf = ZipFile(zip_filename, mode="w", compresslevel=compresslevel)
            try:
                for filepath in filepaths:
                    zf.write(filepath, basename(filepath), compress_type=compression, compresslevel=compresslevel)
            except FileNotFoundError:
                pass
            finally:
                zf.close()

    zip_files_arguments_list = [(join(zipdir, "{}.zip".format(k)), p_filepaths_dict[k], 9) for k in
                                p_filepaths_dict]
    zip_pool = ThreadPool(processes=cpu_count() + 1)
    return list(tqdm.tqdm(zip_pool.imap_unordered(zip_files, zip_files_arguments_list), total=len(p_filepaths_dict)))


if __name__ == '__main__':
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, prog='packetatortots')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    parser.add_argument('-d', '--debug', required=False, action='store_true',
                        help='debug output ; replay errors are not treated as replay failures')
    parser.add_argument('-N', '--iterations', required=False, type=int, default=3, help='Number of iterations',
                        metavar='N')
    parser.add_argument('-t', '--timeout', required=False, type=int, default=10*60, help='Timeout to wait for the packetator subprocess to complete. Useful for when reply gets stuck in a loop',
                        metavar='seconds')
    parser.add_argument('-dm', '--dmode', required=False, type=str, choices=["MIN"] + packetator["modes"] + ["MAX"], default="L4",
                        help='Default mode to replay pcaps in')
    parser.add_argument('-m', '--modes', required=False, type=str,
                        help='Line delimited file that maps pcap filenames to a minimum and maximum mode: example.pcap,L4,L5',
                        metavar='FILE')
    parser.add_argument('-j', '--jobs', required=False, type=int, default=10 * cpu_count(),
                        help='Number of pcaps to replay in parallel', metavar='N')
    parser.add_argument('-o', '--outfile', required=False, type=str, default=None,
                        help='output file, in CSV format. (Columns: pcap basename, mode, success count, number of iterations, overall result, result 1, result 2, ..., ip addresses 1, ip addresses 2, ...)', metavar='FILE')
    parser.add_argument('-od', '--outdir', required=False, default='out', help='output directory', metavar='DIR')
    parser.add_argument('-zd', '--zipdir', required=False, help='output directory to place compressed zips of any generated pcaps', metavar='DIR')
    parser.add_argument('-b', '--blocklist', required=False, help='yaml document with addresses to blocklist.',
                        metavar='FILE')
    parser.add_argument('-rm', '--randommac', required=False, action='store_true',
                        help='use random MAC addresses. Promiscuous mode is required ')
    parser.add_argument('-ri6', '--randomip6', required=False, action='store_true',
                        help='randomize the last 3 bytes of IPv6 addresses as well. Promiscuous mode is required')
    parser.add_argument('-i', '--interfaces', required=True, type=str,
                        help='YAML document that specifies the interface(s) to use', metavar='FILE')
    parser.add_argument("pcaps_path", help='pcap or directory of pcaps to replay')
    parser.add_argument('packetator_args', nargs='*',
                        help='"--" followed by arguments to pass along to packetator for all replays. run: "{0} --help" for more info'.format(
                            packetator["binary_path"]))
    args = parser.parse_args()

    timeout = args.timeout

    consumed_addresses = set()

    if args.blocklist:
        blocklist_data = parse_blocklist(args.blocklist)
        mac_bl, ipv4_bl, ipv6_bl = blocklist_data["mac"], blocklist_data["ipv4"], blocklist_data["ipv6"]
        for a in mac_bl:
            consumed_addresses.add(a)
        for a in ipv4_bl:
            consumed_addresses.add(a)
        for a in ipv6_bl:
            consumed_addresses.add(a)

        if "-b" not in args.packetator_args and "--blocklist" not in args.packetator_args:
            args.packetator_args += ["-b", abspath(args.blocklist)]

    debug = args.debug

    interfaces = parse_interfaces(args.interfaces)
    assert len(interfaces) == 2
    for interface in interfaces:
        if interface["gateway"]:
            consumed_addresses.add(interface["gateway"])
        if interface["gateway_v6"]:
            consumed_addresses.add(interface["gateway_v6"])

    output_dir = abspath(args.outdir)
    try:
        mkdir(output_dir)
    except:
        pass

    pool = ThreadPool(processes=args.jobs)

    cmdlines = []

    pcap_paths = []
    if isdir(args.pcaps_path):
        for (dirpath, dirnames, filenames) in walk(args.pcaps_path):
            for filename in filenames:
                if splitext(filename)[-1] in PCAP_FILE_EXTENSIONS:
                    pcap_paths.append(abspath(join(dirpath, filename)))
    else:
        if splitext(args.pcaps_path)[-1] in PCAP_FILE_EXTENSIONS:
            pcap_paths.append(abspath(args.pcaps_path))

    modes_file_map = dict()
    if args.modes is not None:
        with open(expanduser(args.modes), "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            for line in lines:
                tokens = [t.strip() for t in line.rstrip('\n').split(",")]
                if len(tokens) == 3:
                    pcap_name, min_mode, max_mode = tokens
                    if min_mode == "MIN": min_mode = packetator["modes"][0]
                    if max_mode == "MAX": max_mode = packetator["modes"][-1]
                    if min_mode not in packetator["modes"] or max_mode not in packetator["modes"]:
                        print("invalid line in " + args.modes + ":\n" + line)
                        exit(1)
                    modes_file_map[pcap_name] = (min_mode, max_mode)
                elif len(tokens) == 2:
                    pcap_name, max_mode = tokens
                    min_mode = packetator["modes"][0]
                    if max_mode == "MAX": max_mode = packetator["modes"][-1]
                    if min_mode not in packetator["modes"] or max_mode not in packetator["modes"]:
                        print("invalid line in " + args.modes + ":\n" + line)
                        exit(1)
                    modes_file_map[pcap_name] = (min_mode, max_mode)
                elif len(tokens) == 0:
                    pass
                else:
                    print("invalid line in " + args.modes + ":\n" + line)
                    exit(1)

    default_mode = args.dmode
    if default_mode == "MIN": default_mode = packetator["modes"][0]
    if default_mode == "MAX": default_mode = packetator["modes"][-1]
    pcap_modes = dict()
    for pcap_path in pcap_paths:
        pcap_name = basename(pcap_path)
        if pcap_name in modes_file_map:
            min_mode, max_mode = modes_file_map[pcap_name]
            if packetator["modes"].index(default_mode) < packetator["modes"].index(min_mode):
                pcap_modes[pcap_path] = min_mode
            elif packetator["modes"].index(default_mode) > packetator["modes"].index(max_mode):
                pcap_modes[pcap_path] = max_mode
            else:
                pcap_modes[pcap_path] = default_mode
        else:
            pcap_modes[pcap_path] = default_mode

    ip_maps = dict()  # (pcap, iteration) -> ip_map

    for x in range(args.iterations):
        for pcap_path in pcap_paths:
            hosts, host_pairs = parse_pcap(pcap_path)
            if len(hosts) == 0:
                # These can possibly be replayed with an "L2" mode if it were implemented
                # For now, skip this and assign the result REPLAY_NOT.
                print("[!]\tNo IP or IPv6 hosts found for " + pcap_path)
                # fake the results & ip_map
                fake_cmd_args = ("-p", pcap_path, x)  # iteration number ("x") to make key unique
                results[fake_cmd_args] = REPLAY_NOT
                ip_maps_key = (pcap_path, x)
                ip_maps[ip_maps_key] = {}
                continue
            partitions = distribute_nodes(len(interfaces), hosts, host_pairs)
            ip_map = {}
            replayed_address_interface_map = {}  # replayed -> interface["name"] mapping
            is_ipv4 = "." in next(iter(hosts))  # can only replay pcaps with either all IPv4 or all IPv6
            for original_address in hosts:
                index = None
                for i in range(len(partitions)):
                    if original_address in partitions[i]:
                        index = i
                interface = interfaces[index]
                while True:
                    random_address = random_ipv4_address(interface["subnet"]) if is_ipv4 else random_ipv6_address(
                        interface["subnet_v6"], b"" if args.randomip6 else interface["last_bytes_v6"])
                    if random_address in consumed_addresses:
                        continue
                    else:
                        ip_map[original_address] = random_address
                        replayed_address_interface_map[random_address] = interface["name"]
                        consumed_addresses.add(random_address)
                        break

            cmdline = [packetator["binary_path"], ] + args.packetator_args
            mode = pcap_modes[pcap_path]
            mode_config = mode + ".yaml"
            mode_config = join(packetator["config_dir"], mode_config)
            cmdline += ["-c", mode_config]
            cmdline += ["-p", pcap_path]
            for original_address, replayed_address in ip_map.items():
                cmdline += ["-m", original_address + "=" + replayed_address]

            for interface in interfaces:
                cmdline += ["-i", interface["name"], "-s", interface["subnet"] if is_ipv4 else interface["subnet_v6"]]
                if interface.get("gateway" if is_ipv4 else "gateway_v6", ""):
                    cmdline += ["-g", interface["gateway" if is_ipv4 else "gateway_v6"]]

            for original_address, replayed_address in ip_map.items():
                cmdline += ["-a", replayed_address + "," + replayed_address_interface_map[replayed_address] + (
                    "," + generate_mac(oui="00") if args.randommac else "")]

            cmdlines.append(cmdline)
            ip_maps_key = (pcap_path, x)
            ip_maps[ip_maps_key] = ip_map

    pcap_iteration_counts = dict()
    arguments_list = []
    for cmdline in cmdlines:
        pcap_path_index = None
        for i in range(len(cmdline)):
            if cmdline[i] == "-p":
                pcap_path_index = i + 1
                break
        pcap_filepath = cmdline[pcap_path_index]
        if pcap_filepath not in pcap_iteration_counts:
            pcap_iteration_counts[pcap_filepath] = 0
        pcap_iteration_counts[pcap_filepath] = pcap_iteration_counts[pcap_filepath] + 1
        iteration_count = pcap_iteration_counts[pcap_filepath]
        meta = dict()
        meta["iteration_count"] = iteration_count
        arguments = (cmdline, meta)
        arguments_list.append(arguments)

    print("[+]\tReplaying pcaps...")
    r = list(tqdm.tqdm(pool.imap_unordered(run_packetator, arguments_list), total=len(arguments_list)))

    iteration_results = dict()

    for result in results:
        cmd = result
        cmd_args = cmd
        pcap_path_index = None
        for i in range(len(cmd_args)):
            if cmd_args[i] == "-p":
                pcap_path_index = i + 1
                break
        pcap_filepath = cmd_args[pcap_path_index]

        # error codes that may require environment changes to fix
        if results[cmd] == "error (-6)":
            print("[!]\tError: Interfaces are not up. Please bring up the interfaces. File: " + pcap_filepath)
        if results[cmd] == "error (2)":
            print("[!]\tError: Message too long. MTU may be too small. File: " + pcap_filepath)
        if results[cmd] == "error (3)":
            print("[!]\tError: No packets to replay. File: " + pcap_filepath)
        if results[cmd] == "error (1001)":
            print("[!]\tError: Process timed out. File: " + pcap_filepath)

        if pcap_filepath not in iteration_results:
            iteration_results[pcap_filepath] = []

        iteration_results[pcap_filepath].append(results[cmd])

    results_output = []

    for pcap_filepath in iteration_results:
        success_count = 0
        for result in iteration_results[pcap_filepath]:
            if result == REPLAY_SUCCESS:
                success_count += 1
        not_replayed = False
        if success_count == 0:
            for result in iteration_results[pcap_filepath]:
                not_replayed = result == REPLAY_NOT

        # pcap basename,
        # mode,
        # success count,
        # number of iterations,
        # overall result,
        # result 1,
        # result 2, ...,
        # ip addresses 1,
        # ip addresses 2, ...
        result_output = [basename(pcap_filepath),
                         pcap_modes[pcap_filepath],
                         success_count,
                         args.iterations,
                         (REPLAY_SUCCESS if success_count > 0 else (REPLAY_NOT if not_replayed else REPLAY_FAILURE))]
        for i in range(len(iteration_results[pcap_filepath])):
            result = iteration_results[pcap_filepath][i]
            result_output.append(result)
        for i in range(len(iteration_results[pcap_filepath])):
            ip_maps_key = (pcap_filepath, i)
            ip_map = ip_maps[ip_maps_key]
            ip_map_items = sorted(ip_map.items(), key=lambda item: inet_pton(AF_INET if "." in item[0] else AF_INET6, item[0])) # sort addresses by ascending order of the original ip addresses
            ip_addresses = [item[1] for item in ip_map_items]
            result_output.append(" ".join(ip_addresses))
        results_output.append(result_output)

    if args.outfile:
        with open(expanduser(args.outfile), "w") as f:
            for result_output in results_output:
                f.write(",".join(str(x) for x in result_output) + "\n")

    if args.zipdir:
        print("[+]\tCompressing pcaps...")
        r = compress_pcaps(args.zipdir, output_dir, iteration_results, ip_maps)

    # summary
    success_count = 0
    failure_count = 0
    not_count = 0
    for result_output in results_output:
        overall_result = result_output[4]
        if overall_result == REPLAY_SUCCESS:
            success_count += 1
        elif overall_result == REPLAY_FAILURE:
            failure_count += 1
        elif overall_result == REPLAY_NOT:
            not_count += 1
    total_count = success_count + failure_count + not_count

    rjust = max(len(REPLAY_SUCCESS), len(REPLAY_FAILURE), len(REPLAY_NOT))
    print("="*10 + " Result Summary " + "="*10)
    print("\t{}: {}/{}".format(REPLAY_SUCCESS.rjust(rjust), success_count, total_count))
    print("\t{}: {}/{}".format(REPLAY_FAILURE.rjust(rjust), failure_count, total_count))
    print("\t{}: {}/{}".format(REPLAY_NOT.rjust(rjust), not_count, total_count))
