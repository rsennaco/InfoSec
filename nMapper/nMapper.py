#!/usr/bin/env python3
"""
nMapper - UX friendly Network Mapping
"""

import os
import re
import sys
import time
import tempfile
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class NMapInstaller:
    @staticmethod
    def installed():
        try:
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def install_nmap():
        return []


class IPValidator:
    @staticmethod
    def validate_targets(targets_in: str) -> List[str]:
        tokens: List[str] = []
        entries = [entry.strip() for entry in targets_in.split(',') if entry.strip()]

        for entry in entries:
            t = entry.strip()
            try:
                if '/' in t:
                    # CIDR
                    network = ipaddress.ip_network(t, strict=False)
                    tokens.append(str(network))
                elif '-' in t and t.count('.') >= 3:
                    # Range, possibly suffix form
                    start_ip, end_ip = [p.strip() for p in t.split('-', 1)]
                    if '.' not in end_ip:
                        prefix, _ = start_ip.rsplit('.', 1)
                        end_ip = f"{prefix}.{end_ip}"
                    # Validate endpoints
                    _ = ipaddress.ip_address(start_ip)
                    _ = ipaddress.ip_address(end_ip)
                    # Store normalized "start-end"
                    tokens.append(f"{start_ip}-{end_ip}")
                else:
                    # Single IP
                    ip = ipaddress.ip_address(t)
                    tokens.append(str(ip))
            except ValueError as e:
                print(f"{Colors.WARNING}Invalid target: {entry} - {e}{Colors.ENDC}")

        return tokens

    @staticmethod
    def expand_ips(targets: List[str]) -> List[str]:
        """Expand CIDRs, ranges, and pass through single IPs."""
        expanded: List[str] = []

        for target in targets:
            t = target.strip()
            try:
                if '/' in t:
                    network = ipaddress.ip_network(t, strict=False)
                    expanded.extend(str(ip) for ip in network.hosts())
                elif '-' in t and t.count('.') >= 3:
                    start_ip, end_ip = [oct.strip() for oct in t.split('-', 1)]
                    if '.' not in end_ip:
                        prefix, _ = start_ip.rsplit('.', 1)
                        end_ip = f"{prefix}.{end_ip}"
                    start = ipaddress.ip_address(start_ip)
                    end = ipaddress.ip_address(end_ip)
                    if int(end) < int(start):
                        raise ValueError("range end < start")
                    cur = int(start)
                    while cur <= int(end):
                        expanded.append(str(ipaddress.ip_address(cur)))
                        cur += 1
                else:
                    # Single IP
                    ipaddress.ip_address(t)  # validate
                    expanded.append(t)
            except ValueError as e:
                print(f"{Colors.WARNING}Error expanding target: {t} - {e}{Colors.ENDC}")

        return expanded

    @staticmethod
    def exclude_ips(ip_list: List[str], exclusions: List[str]) -> List[str]:
        """Remove excluded IPs from target list."""
        if not exclusions:
            return ip_list

        excluded_set = set()

        for exclusion in exclusions:
            x = exclusion.strip()
            try:
                if '/' in x:
                    network = ipaddress.ip_network(x, strict=False)
                    excluded_set.update(str(ip) for ip in network.hosts())
                elif '-' in x and x.count('.') >= 3:
                    start_ip, end_ip = [p.strip() for p in x.split('-', 1)]
                    if '.' not in end_ip:
                        prefix, _ = start_ip.rsplit('.', 1)
                        end_ip = f"{prefix}.{end_ip}"
                    start = ipaddress.ip_address(start_ip)
                    end = ipaddress.ip_address(end_ip)
                    if int(end) < int(start):
                        raise ValueError("range end < start")
                    cur = int(start)
                    while cur <= int(end):
                        excluded_set.add(str(ipaddress.ip_address(cur)))
                        cur += 1
                else:
                    ipaddress.ip_address(x)  # validate
                    excluded_set.add(x)
            except ValueError as e:
                print(f"{Colors.WARNING}Invalid exclusion: {x} - {e}{Colors.ENDC}")

        filtered = [ip for ip in ip_list if ip not in excluded_set]

        if excluded_set:
            removed_count = len(ip_list) - len(filtered)
            print(f"{Colors.BOLD}Excluded {Colors.OKGREEN}{removed_count}{Colors.ENDC}{Colors.BOLD} IP address(es){Colors.ENDC}")

        return filtered

    @staticmethod
    def group_ips(ip_list: List[str]) -> List[str]:
        """Group consecutive IPs back into ranges. Display only."""
        if not ip_list:
            return []
        sorted_ips = sorted((ipaddress.ip_address(ip) for ip in set(ip_list)), key=int)
        groups: List[str] = []
        start = end = sorted_ips[0]

        for ip in sorted_ips[1:]:
            if int(ip) == int(end) + 1:
                end = ip
            else:
                groups.append(str(start) if start == end else f"{start}-{end}")
                start = end = ip

        groups.append(str(start) if start == end else f"{start}-{end}")
        return groups


class NMapRunner:
    def __init__(self):
        self.parser = NMapParser()

    def ping_sweep(self, targets: List[str]) -> List[str]:
        """ICMP/ARP host discovery against a flat list of IPs."""
        if not targets:
            return []

        print(f"\n{Colors.HEADER}Stage 1: Discovering live hosts...{Colors.ENDC}")

        # Pretty print
        pretty = ', '.join(IPValidator.group_ips(targets))
        print(f"{Colors.BOLD}Running ping sweep on: {pretty}{Colors.ENDC}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output = temp_file.name

        try:
            nmap_cmd = [
                'nmap',
                '-sn',
                '-oX', xml_output,
                '--dns-servers', '8.8.4.4,8.8.8.8',
                '--stats-every', '10s',
            ] + targets

            process = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if process.returncode != 0:
                print(f"{Colors.WARNING}Ping sweep completed with warnings{Colors.ENDC}")
                if process.stderr:
                    print(f"{Colors.warning}stderr: {process.stderr[:200]}{Colors.ENDC}")

            live_hosts = NMapParser.parse_live_hosts(xml_output)
            print(f"{Colors.OKGREEN}Found {len(live_hosts)} live host(s){Colors.ENDC}")
            if live_hosts:
                print(f"{Colors.OKCYAN}Live hosts: {', '.join(live_hosts)}{Colors.ENDC}")
            return live_hosts

        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}Ping sweep timed out.{Colors.ENDC}")
            return []
        except Exception as e:
            print(f"{Colors.FAIL}Error running ping sweep: {e}{Colors.ENDC}")
            return []
        finally:
            try:
                os.unlink(xml_output)
            except:
                pass

    def port_discovery(self, hosts: List[str]) -> Dict[str, Dict]:
        """Fast port discovery on live hosts."""
        if not hosts:
            return {}

        print(f"\n{Colors.HEADER}Stage 2: Fast port discovery...{Colors.ENDC}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output = temp_file.name

        try:
            tcp_cmd = [
                'nmap',
                '-p1-1024',
                '-sS',
                '-T3',
                '--min-rate', '1000',
                '--open',
                '-Pn',
                '--disable-arp-ping',
                '--dns-servers', '8.8.4.4,8.8.8.8',
                '-oX', xml_output,
                '--stats-every', '30s',
            ] + hosts

            print(f"{Colors.BOLD}Fast TCP port scan on {len(hosts)} host(s){Colors.ENDC}")

            tcp_process = subprocess.run(
                tcp_cmd,
                capture_output=True,
                text=True,
                timeout=1200
            )

            if tcp_process.returncode != 0:
                print(f"{Colors.WARNING}TCP scan completed with warnings{Colors.ENDC}")

            udp_xml = f"{xml_output}_udp"
            udp_cmd = [
                'nmap',
                '-sU',
                '--top-ports', '100',
                '-T3',
                '--min-rate', '500',
                '--open',
                '-n',
                '-Pn',
                '--dns-servers', '8.8.4.4,8.8.8.8',
                '-oX', udp_xml,
            ] + hosts

            print(f"{Colors.BOLD}Fast UDP port scan on {len(hosts)} host(s){Colors.ENDC}")

            udp_process = subprocess.run(
                udp_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if udp_process.returncode != 0:
                print(f"{Colors.WARNING}UDP scan completed with warnings{Colors.ENDC}")

            results = NMapParser.parse_port_discovery(xml_output, udp_xml)

            tcp_ports = sum(len(h.get('tcp_ports', [])) for h in results.values())
            udp_ports = sum(len(h.get('udp_ports', [])) for h in results.values())
            print(f"{Colors.OKGREEN}Fast discovery found {tcp_ports} TCP and {udp_ports} UDP open ports{Colors.ENDC}")

            return results

        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}Port discovery timed out.{Colors.ENDC}")
            return {}
        except Exception as e:
            print(f"{Colors.FAIL}Error during port discovery: {e}{Colors.ENDC}")
            return {}
        finally:
            try:
                os.unlink(xml_output)
                os.unlink(f"{xml_output}_udp")
            except:
                pass

    def version_scan(self, ports: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Run version detection and OS fingerprinting."""
        if not ports:
            return []

        print(f"\n{Colors.HEADER}Stage 3: Version detection and OS fingerprinting...{Colors.ENDC}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output = temp_file.name

        try:
            results: List[Dict[str, Any]] = []

            for host, host_data in ports.items():
                tcp = host_data.get('tcp_ports', [])
                udp = host_data.get('udp_ports', [])
                if not tcp and not udp:
                    continue

                print(f"{Colors.BOLD}Scanning services on {Colors.OKCYAN}{host}{Colors.ENDC}")

                port_specs: List[str] = []
                if tcp:
                    tcp_list = ','.join(str(p['number']) for p in tcp)
                    port_specs.append(f"T:{tcp_list}")
                if udp:
                    udp_list = ','.join(str(p['number']) for p in udp)
                    port_specs.append(f"U:{udp_list}")
                port_spec = ','.join(port_specs)

                nmap_cmd = [
                    'nmap',
                    '-p', port_spec,
                    '-sV',
                    '-O',
                    '-sS',
                    '-sU',
                    '--version-intensity', '5',
                    '--dns-servers', '8.8.4.4,8.8.8.8',
                    '-oX', f"{xml_output}_{host}",
                    host
                ]

                try:
                    _ = subprocess.run(
                        nmap_cmd,
                        capture_output=True,
                        text=True,
                        timeout=600
                    )
                    host_results = NMapParser.parse_nmap_xml(f"{xml_output}_{host}")
                    results.extend(host_results)
                except subprocess.TimeoutExpired:
                    print(f"{Colors.WARNING}Version scan timed out for {host}{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.WARNING}Error scanning {host}: {e}{Colors.ENDC}")
                finally:
                    try:
                        os.unlink(f"{xml_output}_{host}")
                    except:
                        pass

            print(f"\n{Colors.OKGREEN}Version detection complete!{Colors.ENDC}")
            return results

        except Exception as e:
            print(f"{Colors.FAIL}Error during version detection: {e}{Colors.ENDC}")
            return []

    def scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Run three-stage optimized scan."""
        if not targets:
            print(f"{Colors.FAIL}No valid targets provided. Exiting...{Colors.ENDC}")
            return []

        live_hosts = self.ping_sweep(targets)

        if not live_hosts:
            print(f"{Colors.WARNING}No hosts responded to ping sweep.{Colors.ENDC}")
            print(f"\n{Colors.BOLD}There may be hosts that do not respond to ICMP{Colors.ENDC}")
            fallback = input(f"{Colors.BOLD}Proceed with direct scan anyway? (y/n): {Colors.ENDC}").lower()
            if fallback in ['y', 'yes']:
                return self.direct_scan(targets)
            else:
                print(f"{Colors.WARNING}Scan aborted. Exiting...{Colors.ENDC}")
                sys.exit(1)

        ports = self.port_discovery(live_hosts)
        if not ports:
            print(f"{Colors.WARNING}No open ports found.{Colors.ENDC}")
            return []

        results = self.version_scan(ports)
        return results

    def direct_scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Comprehensive scan when discovery yields nothing."""
        if not targets:
            return []

        print(f"\n{Colors.HEADER}Running direct comprehensive scan...{Colors.ENDC}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output = temp_file.name

        try:
            nmap_cmd = [
                'nmap',
                '-p1-1024',
                '-sU',
                '-O',
                '-sV',
                '-sS',
                '-T3',
                '--open',
                '--dns-servers', '8.8.4.4,8.8.8.8',
                '-oX', xml_output,
            ] + targets

            target_list = ', '.join(IPValidator.group_ips(targets))
            print(f"{Colors.BOLD}Running comprehensive scan on: {target_list}{Colors.ENDC}")
            print(f"{Colors.WARNING}This may take a while...{Colors.ENDC}")

            process = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=1800
            )

            if process.returncode != 0:
                print(f"{Colors.WARNING}Scan completed with warnings{Colors.ENDC}")

            results = NMapParser.parse_nmap_xml(xml_output)
            return results

        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}Scan timed out.{Colors.ENDC}")
            return []
        except Exception as e:
            print(f"{Colors.FAIL}Error during scan: {e}{Colors.ENDC}")
            return []
        finally:
            try:
                os.unlink(xml_output)
            except:
                pass


class NMapParser:
    @staticmethod
    def parse_live_hosts(xml_file: str) -> List[str]:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            live_hosts: List[str] = []
            for host in root.findall('host'):
                state = host.find('status')
                if state is not None and state.get('state') == 'up':
                    address = host.find('address')
                    if address is not None:
                        live_hosts.append(address.get('addr'))
            return live_hosts
        except ET.ParseError as e:
            print(f"{Colors.FAIL}Error parsing ping sweep XML: {e}{Colors.ENDC}")
            return []
        except Exception as e:
            print(f"{Colors.FAIL}Unexpected error parsing ping sweep: {e}{Colors.ENDC}")
            return []

    @staticmethod
    def parse_port_discovery(tcp_xml_file: str, udp_xml_file: str) -> Dict[str, Dict]:
        results: Dict[str, Dict] = {}

        # TCP
        try:
            if os.path.exists(tcp_xml_file):
                tree = ET.parse(tcp_xml_file)
                root = tree.getroot()
                for host in root.findall('host'):
                    state = host.find('status')
                    if state is not None and state.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            ip = address.get('addr')
                            results.setdefault(ip, {'tcp_ports': [], 'udp_ports': []})
                            ports = host.find('ports')
                            if ports is not None:
                                for port in ports.findall('port'):
                                    state_elem = port.find('state')
                                    if (state_elem is not None and
                                        state_elem.get('state') in ['open', 'open|filtered'] and
                                        port.get('protocol') == 'tcp'):
                                        results[ip]['tcp_ports'].append({
                                            'number': port.get('portid'),
                                            'protocol': 'tcp'
                                        })
        except Exception as e:
            print(f"{Colors.WARNING}Error parsing TCP discovery results: {e}{Colors.ENDC}")

        # UDP
        try:
            if os.path.exists(udp_xml_file):
                tree = ET.parse(udp_xml_file)
                root = tree.getroot()
                for host in root.findall('host'):
                    state = host.find('status')
                    if state is not None and state.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            ip = address.get('addr')
                            results.setdefault(ip, {'tcp_ports': [], 'udp_ports': []})
                            ports = host.find('ports')
                            if ports is not None:
                                for port in ports.findall('port'):
                                    state_elem = port.find('state')
                                    if (state_elem is not None and
                                        state_elem.get('state') in ['open', 'open|filtered'] and
                                        port.get('protocol') == 'udp'):
                                        results[ip]['udp_ports'].append({
                                            'number': port.get('portid'),
                                            'protocol': 'udp'
                                        })
        except Exception as e:
            print(f"{Colors.WARNING}Error parsing UDP discovery results: {e}{Colors.ENDC}")

        return results

    @staticmethod
    def parse_nmap_xml(xml_file: str) -> List[Dict[str, Any]]:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            results: List[Dict[str, Any]] = []

            for host in root.findall('host'):
                host_info: Dict[str, Any] = {}

                address = host.find('address')
                if address is not None:
                    host_info['ip'] = address.get('addr')

                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_info['hostname'] = hostname.get('name')

                os_info = host.find('os')
                if os_info is not None:
                    osmatch = os_info.findall('osmatch')
                    if osmatch:
                        osmatch.sort(key=lambda x: int(x.get('accuracy', 0)), reverse=True)
                        if len(osmatch) == 1 and int(osmatch[0].get('accuracy', 0)) > 80:
                            host_info['os'] = osmatch[0].get('name')
                        else:
                            guess = [f"{g.get('name')} ({g.get('accuracy')}%)" for g in osmatch[:3]]
                            host_info['os'] = f"Unsure - Top guesses: {', '.join(guess)}"
                ports = host.find('ports')
                tcp: List[Dict[str, Any]] = []
                udp: List[Dict[str, Any]] = []

                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            'number': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': port.find('state').get('state') if port.find('state') is not None else 'unknown'
                        }
                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = service.get('name', 'unknown')
                            port_info['version'] = service.get('version', 'unknown')
                            port_info['product'] = service.get('product', 'unknown')
                            port_info['extrainfo'] = service.get('extrainfo', '')
                        else:
                            port_info['service'] = 'unknown'
                            port_info['version'] = 'unknown'
                            port_info['product'] = 'unknown'
                            port_info['extrainfo'] = ''
                        if port_info['state'] in ['open', 'open|filtered']:
                            if port_info['protocol'] == 'tcp':
                                tcp.append(port_info)
                            elif port_info['protocol'] == 'udp':
                                udp.append(port_info)

                host_info['tcp_ports'] = tcp
                host_info['udp_ports'] = udp

                state = host.find('status')
                if state is not None and state.get('state') == 'up':
                    results.append(host_info)

            return results

        except ET.ParseError as e:
            print(f"{Colors.FAIL}Error parsing nmap XML output: {e}{Colors.ENDC}")
            return []
        except Exception as e:
            print(f"{Colors.FAIL}Unexpected error parsing results: {e}{Colors.ENDC}")
            return []


class OutputFormatter:
    @staticmethod
    def format(results: List[Dict[str, Any]]) -> str:
        if not results:
            return f"{Colors.WARNING}No hosts found or all hosts are down.{Colors.ENDC}"

        lines: List[str] = []
        lines.append(f"\n{Colors.HEADER}{'='*60}")
        lines.append(f"{' '*10}nMapper Scan Results - {len(results)} host(s) found")
        lines.append(f"{'='*60}{Colors.ENDC}")

        for i, host in enumerate(results, 1):
            lines.append(f"\n{Colors.BOLD}[{i}] Host: {host.get('ip', 'Unknown')}{Colors.ENDC}")

            if 'hostname' in host:
                lines.append(f"     Hostname: {Colors.OKCYAN}{host['hostname']}{Colors.ENDC}")

            os_info = host.get('os', 'Unknown')
            lines.append(f"     OS: {Colors.OKGREEN}{os_info}{Colors.ENDC}")

            tcp = host.get('tcp_ports', [])
            if tcp:
                lines.append(f"\n     {Colors.BOLD}TCP Ports ({len(tcp)} open):{Colors.ENDC}")
                for port in tcp:
                    service = port.get('service', 'unknown')
                    version = port.get('version', 'unknown')
                    product = port.get('product', 'unknown')
                    service_info = service
                    if product != 'unknown' and version != 'unknown':
                        service_info = f"{service} ({product}) {version}"
                    elif product != 'unknown':
                        service_info = f"{service} ({product})"
                    elif version != 'unknown':
                        service_info = f"{service} {version}"
                    lines.append(f"     {Colors.OKBLUE}{port['number']}/tcp{Colors.ENDC} - {service_info}")
            else:
                lines.append(f"\n     {Colors.WARNING}No open TCP ports found{Colors.ENDC}")

            udp_ports = host.get('udp_ports', [])
            if udp_ports:
                lines.append(f"\n     {Colors.BOLD}UDP Ports ({len(udp_ports)} open):{Colors.ENDC}")
                for port in udp_ports:
                    service = port.get('service', 'unknown')
                    version = port.get('version', 'unknown')
                    product = port.get('product', 'unknown')
                    service_info = service
                    if product != 'unknown' and version != 'unknown':
                        service_info = f"{service} ({product}) {version}"
                    elif product != 'unknown':
                        service_info = f"{service} ({product})"
                    elif version != 'unknown':
                        service_info = f"{service} {version}"
                    lines.append(f"     {Colors.OKBLUE}{port['number']}/udp{Colors.ENDC} - {service_info}")
            else:
                lines.append(f"\n     {Colors.WARNING}No open UDP ports found{Colors.ENDC}")

            if i < len(results):
                lines.append(f"\n{Colors.HEADER}{'-'*60}{Colors.ENDC}")

        return '\n'.join(lines)

    @staticmethod
    def save(results: List[Dict[str, Any]], output: str):
        if not results:
            return
        save = input(f"\n{Colors.BOLD}Save results to a file? (y/n): {Colors.ENDC}").lower()
        if save in ['y', 'yes']:
            filename = input(f"{Colors.BOLD}Enter path/filename (default: ./nmap_results.txt): {Colors.ENDC}").strip()
            if not filename:
                filename = "nmap_results.txt"
            try:
                clean = re.sub(r'\033\[[0-9;]*m', '', output)
                with open(filename, 'w') as f:
                    f.write(clean)
                print(f"{Colors.OKGREEN}Results saved to: {filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}Error saving file: {e}{Colors.ENDC}")


def main():
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("      ::::    :::   :::   :::       :::     :::::::::  :::::::::  :::::::::: :::::::::")
    print("     :+:+:   :+:  :+:+: :+:+:    :+: :+:   :+:    :+: :+:    :+: :+:        :+:    :+:")
    print("    :+:+:+  +:+ +:+ +:+:+ +:+  +:+   +:+  +:+    +:+ +:+    +:+ +:+        +:+    +:+ ")
    print("   +#+ +:+ +#+ +#+  +:+  +#+ +#++:++#++: +#++:++#+  +#++:++#+  +#++:++#   +#++:++#:   ")
    print("  +#+  +#+#+# +#+       +#+ +#+     +#+ +#+        +#+        +#+        +#+    +#+   ")
    print(" #+#   #+#+# #+#       #+# #+#     #+# #+#        #+#        #+#        #+#    #+#    ")
    print("###    #### ###       ### ###     ### ###        ###        ########## ###    ###     ")
    print(f"{Colors.OKGREEN}")
    print("         ┏━┓╻┏┳┓┏━┓╻  ┏━╸   ┏┓╻┏━╸╺┳╸╻ ╻┏━┓┏━┓╻┏    ┏┳┓┏━┓┏━┓┏━┓╻┏┓╻┏━╸")
    print("         ┗━┓┃┃┃┃┣━┛┃  ┣╸    ┃┗┫┣╸  ┃ ┃╻┃┃ ┃┣┳┛┣┻┓   ┃┃┃┣━┫┣━┛┣━┛┃┃┗┫┃╺┓")
    print("         ┗━┛╹╹ ╹╹  ┗━╸┗━╸   ╹ ╹┗━╸ ╹ ┗┻┛┗━┛╹┗╸╹ ╹   ╹ ╹╹ ╹╹  ╹  ╹╹ ╹┗━┛")
    print(f"{Colors.ENDC}")

    installer = NMapInstaller()
    if not installer.installed():
        installer.install_nmap()

    print(f"\n{Colors.BOLD}Enter IP addresses, IP ranges, or CIDR blocks (comma-separated):{Colors.ENDC}")
    print(f"{Colors.HEADER}Examples:{Colors.ENDC}")
    print(f"  Single IP: {Colors.OKCYAN}192.168.1.1{Colors.ENDC}")
    print(f"  Range:     {Colors.OKCYAN}192.168.1.1-10{Colors.ENDC}")
    print(f"  CIDR:      {Colors.OKCYAN}192.168.1.0/24{Colors.ENDC}")
    print(f"  Multiple:  {Colors.OKCYAN}192.168.1.1, 192.168.1.0/24, 10.0.0.1-5{Colors.ENDC}")

    targets_in = input(f"\n{Colors.BOLD}{Colors.OKGREEN}Targets: {Colors.ENDC}").strip()
    if not targets_in:
        print(f"{Colors.FAIL}No targets provided. Exiting.{Colors.ENDC}")
        sys.exit(1)

    validator = IPValidator()
    validated = validator.validate_targets(targets_in)
    if not validated:
        print(f"{Colors.FAIL}No valid targets found. Exiting.{Colors.ENDC}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}Enter IP addresses to exclude (optional, comma-separated):{Colors.ENDC}")
    print(f"\n{Colors.HEADER}Examples:{Colors.ENDC}   {Colors.OKCYAN}192.168.1.1, 192.168.1.0/28, 10.0.0.1-5{Colors.ENDC}")
    exclusions = input(f"\n{Colors.BOLD}{Colors.OKGREEN}Exclusions {Colors.ENDC}{Colors.BOLD}(Press Enter to Skip): {Colors.ENDC}").strip()
    exclusions_list = [e.strip() for e in exclusions.split(',') if e.strip()] if exclusions else []

    expanded = validator.expand_ips(validated)
    # dedup + sort numerically
    final_ips = sorted(set(expanded), key=lambda x: int(ipaddress.ip_address(x)))
    final_ips = validator.exclude_ips(final_ips, exclusions_list)
    final_ips = sorted(set(final_ips), key=lambda x: int(ipaddress.ip_address(x)))

    if not final_ips:
        print(f"{Colors.FAIL}All IP addresses were excluded. No targets remain. Exiting.{Colors.ENDC}")
        sys.exit(1)

    total_ips = len(final_ips)
    display_groups = IPValidator.group_ips(final_ips)

    print(f"\n{Colors.HEADER}Final Scan Summary:{Colors.ENDC}")
    print(f"{Colors.BOLD}Total IP addresses to scan: {Colors.OKGREEN}{total_ips}{Colors.ENDC}")
    print(f"This action will scan the following IP space(s): {Colors.OKCYAN}{', '.join(display_groups)}{Colors.ENDC}")
    if exclusions_list:
        print(f"{Colors.BOLD}{Colors.OKGREEN}Excluding:{Colors.ENDC}    {Colors.BOLD}{Colors.WARNING}{', '.join(exclusions_list)}{Colors.ENDC}")

    proceed = input(f"\n{Colors.BOLD}Proceed with scan? (y/n): {Colors.ENDC}").strip().lower()
    if proceed in ['n', 'no']:
        print(f"{Colors.WARNING}Scan aborted by user.{Colors.ENDC}")
        sys.exit(0)

    print(f"\n{Colors.OKGREEN}Starting scan on {total_ips} IP address{'es' if total_ips != 1 else ''}.{Colors.ENDC}")

    runner = NMapRunner()
    results = runner.scan(final_ips)

    formatter = OutputFormatter()
    output = formatter.format(results)
    print(output)

    OutputFormatter.save(results, output)

    print(f"\n{Colors.BOLD}Scan completed!{Colors.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)
