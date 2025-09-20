#!/usr/bin/env python3
"""
nMapper - UX friendly Network Mapping
"""

import os
import re
import sys
import tempfile
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

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
  """Checks for NMap, installs it if not present"""

  @staticmethod
  def installed():
    """Checks if nmap is installed"""
    try:
      result = subprocess.run(['nmap', '--version'],
                              capture_output=True, text=True, timeout=5)
      return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
      return False

  @staticmethod
  def install_nmap():
    """To-Do"""
    return []
  
class IPValidator:

  @staticmethod
  def validate_targets(targets_in: str) -> List[str]:
    """Validate IP inputs"""
    targets = []
    entries = [entry.strip() for entry in targets_in.split(',') if entry.strip()]

    for entry in entries:
      try:
        # Checking for CIDR block
        if '/' in entry:
          network = ipaddress.ip_network(entry, strict=False)
          targets.append(str(network))
        # Checking for range (e.g., 192.168.1.1-192.168.1.10 or 192.168.1.1-10)
        elif '-' in entry and entry.count('.') >= 3:
          start_ip, end_ip = entry.split('-')
          start_ip = start_ip.strip()
          end_ip = end_ip.strip()

          # If end_ip is just a number, complete it with start_ip's prefix
          if '.' not in end_ip:
            ip_parts = start_ip.split('.')
            end_ip = '.'.join(ip_parts[:-1]) + '.' + end_ip

          # Validate both IPs
          start = ipaddress.ip_address(start_ip)
          end = ipaddress.ip_address(end_ip)

          if int(start) <= int(end):
            targets.append(f"{start_ip}-{end_ip}")
          else:
            print(f"{Colors.WARNING}Invalide range: {start} > {end}{Colors.ENDC}")
        else:
          # Single IP
          ip = ipaddress.ip_address(entry)
          targets.append(str(ip))
      except ValueError as e:
        print(f"{Colors.WARNING}Invalid target: {entry} - {e}{Colors.ENDC}")

    return targets

  @staticmethod
  def expand_ips(targets: List[str]) -> List[str]:
    """Expand all target formats"""
    expanded = []

    for target in targets:
      try:
        # Check for CIDR
        if '/' in target:
          network = ipaddress.ip_network(target, strict=False)
          expanded.extend([str(ip) for ip in network.hosts()])
        # Check for range
        elif '-' in target and target.count('.') >= 3:
          start_ip, end_ip = target.strip()
          start_ip = start_ip.strip()
          end_ip = end_ip.strip()

          # If end_ip is just a number, complete with start_ip's prefix
          if '.' not in end_ip:
            ip_parts = start_ip.split('.')
            end_ip = '.'.join(ip_parts[:-1]) + '.' + end_ip

            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)

            # Generate all IPs in range
            current = int(start)
            while current <= int(end):
              expanded.append(str(ipaddress.ip_address(current)))
              current += 1
        else:
          # Single IP
          expanded.append(target)
      except ValueError as e:
        print(f"{Colors.WARNING}Error expanding target: {target} - {e}{Colors.ENDC}")

    return expanded
  
  @staticmethod
  def exclude_ips(ip_list: List[str], exclusions: List[str]) -> List[str]:
    """Remove excluded IPs from target list"""
    excluded_set = set()

    for exclusion in exclusions:
      try:
        # check if exclusion is a CIDR
        if '/' in exclusion:
          network = ipaddress.ip_network(exclusion, strict=False)
          excluded_set.update([str(ip) for ip in network.hosts()])
        # Check if exclusion is a range
        elif '-' in exclusion and exclusion.count('.') < 4:
          start_ip, end_ip = exclusion.split('-')
          start_ip = start_ip.strip()
          end_ip = end_ip.strip()

          # If last octet is just a number, fix the thang
          if '.' not in end_ip:
            ip_parts = start_ip.split('.')
            end_ip = '.'.join(ip_parts[:-1]) + '.' + end_ip

          start = ipaddress.ip_address(start_ip)
          end = ipaddress.ip_address(end_ip)

          # Generate all IPs in range to exclude
          current = int(start)
          while current <= int(end):
            excluded_set.add(str(ipaddress.ip_address(current)))
            current += 1
        else:
          # Single IP
          excluded_set.add(exclusion)

      except ValueError as e:
        print(f"{Colors.WARNING}Invalid exclusion: {exclusion} - {e}{Colors.ENDC}")

    # Remove excluded IPs
    filtered = [ip for ip in ip_list if ip not in excluded_set]

    if excluded_set:
      removed_count = len(ip_list) - len(filtered)
      print(f"{Colors.BOLD}Excluded {Colors.OKGREEN}{removed_count}{Colors.ENDC}{Colors.BOLD} IP address(es){Colors.ENDC}")

    return filtered
  
#  @staticmethod
# def group_ips(ip_list: List[str]) -> List[str]:


class NMapRunner:
  """Executes main program functions"""

  def __init__(self):
    self.parser = NMapParser()

  def ping_sweep(self, targets: List[str], exclusions: List[str] = None) -> List[str]:
    """initial scan to identify live hosts within target IP spaces"""
    if not targets:
      return []
    
    print(f"\n{Colors.HEADER}Stage 1: Discovering live hosts...{Colors.ENDC}")

    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
      xml_output = temp_file.name

    try:
      target_str = ' '.join(targets)
      nmap_cmd = [
        'nmap',
        '-sn',
        '-oX', xml_output,
        '--dns-servers', '8.8.4.4,8.8.8.8',
        '--stats-every', '10s',
      ]

      # Adding exclusions if provided
      if exclusions:
        exclusion_str = ','.join(exclusions)
        nmap_cmd.extend(['--exclude', exclusion_str])
        print(f"{Colors.BOLD}Running ping sweep on: {target_str} (excluding: {exclusion_str}){Colors.ENDC}")
      else:
        print(f"{Colors.BOLD}Running ping sweep on: {target_str}{Colors.ENDC}")

      nmap_cmd.extend(targets)

      process = subprocess.run(
        nmap_cmd,
        capture_output=True,
        text=True,
        timeout=300
      )

      if process.returncode != 0:
        print(f"{Colors.WARNING}Ping sweep completed with errors{Colors.ENDC}")
        if process.stderr:
          print(f"{Colors.WARNING}stderr: {process.stderr[:200]}...{Colors.ENDC}")

      # Parse results to get live hosts
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
    """Fast port discovery on only live hosts"""
    if not hosts:
      return {}
    
    print(f"\n{Colors.HEADER}Stage 2: Fast port discovery...{Colors.ENDC}")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
      xml_output = temp_file.name

    try:
      # TCP Port Discovery
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

      print(f"{Colors.BOLD}Fast TCP port scan on {len(hosts)} host(s)")

      # Run TCP Scan
      tcp_process = subprocess.run(
        tcp_cmd,
        capture_output=True,
        text=True,
        timeout=1200 # 20 minute timeout
      )

      if tcp_process.returncode != 0:
        print(f"{Colors.WARNING}TCP scan completed with warnings{Colors.ENDC}")

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
        '-oX', xml_output + '_udp',
      ] + hosts

      print(f"{Colors.BOLD}Fast UDP port scan on {len(hosts)} host(s)")

      # Run UDP scan
      udp_process = subprocess.run(
        udp_cmd,
        capture_output=True,
        text=True,
        timeout=600 # 10 minute timeout
      )

      if udp_process.returncode != 0:
        print(f"{Colors.WARNING}UDP scan copmleted with warnings{Colors.ENDC}")

      # Parse port discovery results
      results = NMapParser.parse_port_discovery(xml_output, xml_output + 'udp')

      # Show discovered ports summary
      tcp_ports = sum(len(host_data.get('tcp_ports', [])) for host_data in results.values())
      udp_ports = sum(len(host_data.get('udp_ports', [])) for host_data in results.values())
      print(f"{Colors.OKGREEN}Fast discovery found {tcp_ports} TCP and {udp_ports} UDP open ports")

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
        os.unlink(xml_output + '_udp')
      except:
        pass

  def version_scan(self, ports: Dict[str, Dict]) -> List[Dict[str, Any]]:
    """Run version detection and OS fingerprinting"""
    if not ports:
      return []
    
    print(f"\n{Colors.HEADER}Stage 3: Version detection and OS fingerprinting...{Colors.ENDC}")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
      xml_output = temp_file.name

    try:
      # Building scan commands
      results = []

      for host, host_data in ports.items():
        tcp = host_data.get('tcp_ports', [])
        udp = host_data.get('udp_ports', [])

        if not tcp and not udp:
          continue

        print(f"{Colors.BOLD}Scanning services on {Colors.OKCYAN}{host}...{Colors.ENDC}")

        # Build port list
        port_specs = []
        if tcp:
          tcp = ','.join([str(p['number']) for p in tcp])
          port_specs.append(f"T:{tcp}")

        if udp:
          udp = ','.join([str(p['number']) for p in udp])
          port_specs.append(f"U:{udp}")

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
          scan = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=600 # 10 minute timeout per host
          )

          # Parse results per host
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

      print(f"\n{Colors.OKGREEN}Version detectoin complete!{Colors.ENDC}")
      return results
    
    except Exception as e:
      print(f"{Colors.FAIL}Error during verison detection: {e}{Colors.ENDC}")
      return []

  def scan(self, targets: List[str], exclusions: List[str] = None) -> List[Dict[str, Any]]:
    """Run three-stage optimized scan with fallback"""
    if not targets:
      print(f"{Colors.FAIL}No valid targets provided. Exiting...{Colors.ENDC}")
      return []
    
    print(f"\n{Colors.HEADER}Starting optimized three-stage scan...{Colors.ENDC}")

    # Stage 1: Ping sweep to find live hosts
    live_hosts = self.ping_sweep(targets, exclusions)

    if not live_hosts:
      print(f"{Colors.WARNING}No hosts responded to ping sweep.{Colors.ENDC}")
      print(f"\n{Colors.BOLD}There may be hosts in this network that do not respond to ICMP requests{Colors.ENDC}")
      fallback = input(f"{Colors.BOLD}Would you still like to proceed with the fallback plan? (y/N): {Colors.ENDC}").lower()

      if fallback in ['y', 'yes']:
        print(f"\n{Colors.WARNING} == FALLBACK INITIATED == {Colors.ENDC}")
        print(f"{Colors.BOLD}Falling back to direct scan without optimization{Colors.ENDC}")
        # Running direct comprehensive scan
        return self.direct_scan(targets, exclusions)
      else:
        print(f"{Colors.WARNING}Scan aborted. Exciting...{Colors.ENDC}")
        sys.exit(1)

    # Stage 2: Port discovery
    ports = self.port_discovery(live_hosts)
    if not ports:
      print(f"{Colors.WARNING}No open ports found.{Colors.ENDC}")
      return []
    
    # Stage 3: Targeted version detection and OS fingerprints
    results = self.version_scan(ports)

    return results

  def direct_scan(self, targets: List[str], exclusions: List[str] = None) -> List[Dict[str, Any]]:
    """Run Scan when ping sweep fails"""
    if not targets:
      return []
    
    print(f"\n{Colors.HEADER}Running direct comprehensive scan...{Colors.ENDC}")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
      xml_output = temp_file.name
    
    try:
      # Building nmap command
      target_list = ' '.join(targets)
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
      ]

      if exclusions:
        exclusion_list = ','.join(exclusions)
        nmap_cmd.extend(['--exclude', exclusion_list])
        print(f"{Colors.BOLD}Running comprehensive scan on: {target_list} (excluding: {Colors.WARNING}{exclusion_list}{Colors.ENDC}{Colors.BOLD}){Colors.ENDC}")
      else:
        print(f"{Colors.BOLD}Running comprehensive scan on: {target_list}")

      nmap_cmd.extend(targets)

      print(f"{Colors.WARNING}This may take some time as we're scanning potentially unresponsive hosts...{Colors.ENDC}")

      # Run comprehensive scan
      process = subprocess.run(
        nmap_cmd,
        capture_output=True,
        text=True,
        timeout=1800 # 30 minute timeout
      )

      if process.returncode != 0:
        print(f"{Colors.WARNING}Scan completed with warnings{Colors.ENDC}")

      # Parse output
      results = NMapParser.parse_nmap_xml(xml_output)
      return results
    
    except subprocess.TimeoutExpired:
      print(f"{Colors.FAIL}Scan timed out.{Colors.ENDC}")
    except Exception as e:
      print(f"{Colors.FAIL}Error during scan: {e}{Colors.ENDC}")
      return []
    finally:
      try:
        os.unlink(xml_output)
      except:
        pass

class NMapParser:
  """Parses nmap output and prepares for formatting"""

  @staticmethod
  def parse_live_hosts(xml_file: str) -> List[str]:
    """Parse ping sweep results to get live hosts"""
    try:
      tree = ET.parse(xml_file)
      root = tree.getroot()

      live_hosts = []

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
    """Parse port discovery results"""
    results = {}

    # Parse TCP results
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
              if ip not in results:
                results[ip] = {'tcp_ports': [], 'udp_ports': []}

              ports = host.find('ports')
              if ports is not None:
                for port in ports.findall('port'):
                  state_elem  = port.find('state')
                  if (state_elem is not None and
                      state_elem.get('state') in ['open', 'open|filtered'] and
                      port.get('protocol') == 'tcp'):

                      results[ip]['tcp_ports'].append({
                        'number': port.get('portid'),
                        'protocol': 'tcp'
                      })

    except Exception as e:
      print(f"{Colors.WARNING}Error parsing TCP discover results: {e}{Colors.ENCD}") 

    # Parse UDP
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
              if ip not in results:
                results[ip] = {'tcp_ports': [], 'udp_ports': []}

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
    """Parse nmap XML output file"""
    try:
      tree = ET.parse(xml_file)
      root = tree.getroot()

      results = []

      for host in root.findall('host'):
        host_info = {}

        # Get IP address
        address = host.find('address')
        if address is not None:
          host_info['ip'] = address.get('addr')

        # Get hostname
        hostnames = host.find('hostnames')
        if hostnames is not None:
          hostname = hostnames.find('hostname')
          if hostname is not None:
            host_info['hostname'] = hostname.get('name')

        # Get OS detection
        os_info = host.find('os')
        if os_info is not None:
          osmatch = os_info.findall('osmatch')
          if osmatch:
            # Sort by accuracy
            osmatch.sort(key=lambda x: int(x.get('accuracy', 0)), reverse=True)

            if len(osmatch) == 1 and int(osmatch[0].get('accuracy', 0)) > 80:
              host_info['os'] = osmatch[0].get('name')
            else:
              # Show top 3 guesses
              guess = [f"{os_guess.get('name')} ({os_guess.get('accuracy')}%)"
                       for os_guess in osmatch[:3]]
              host_info['os'] = f"Unsure - Top guesses: {', '.join(guess)}"

        # Get Ports
        ports = host.find('ports')
        tcp = []
        udp = []

        if ports is not None:
          for port in ports.findall('port'):
            port_info = {
              'number': port.get('portid'),
              'protocol': port.get('protocol'),
              'state': port.find('state').get('state') if port.find('state') is not None else 'unknown'
            }

            # Get service info
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

        # Only add hosts that are up
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
  """Format and display results"""

  @staticmethod
  def format(results: List[Dict[str, Any]]) -> str:
    """Format scan results"""
    if not results:
      return f"{Colors.WARNING}No hosts found or all hosts are down.{Colors.ENDC}"
    
    output_lines = []
    output_lines.append(f"\n{Colors.HEADER}{'='*60}")
    output_lines.append(f"{' '*10}nMapper Scan Results - {len(results)} host(s) found")
    output_lines.append(f"{'='*60}{Colors.ENDC}")

    for i, host in enumerate(results, 1):
      output_lines.append(f"\n{Colors.BOLD}[{i}] Host: {host.get('ip', 'Unknown')}{Colors.ENDC}")

      # Hostname
      if 'hostname' in host:
        output_lines.append(f"     Hostname: {Colors.OKCYAN}{host['hostname']}{Colors.ENDC}")

      # OS Detection
      os_info = host.get('os', 'Unknown')
      output_lines.append(f"     OS: {Colors.OKGREEN}{os_info}{Colors.ENDC}")
      
      # TCP Ports
      tcp = host.get('tcp_ports', [])
      if tcp:
        output_lines.append(f"\n     {Colors.BOLD}TCP Ports ({len(tcp)} open):{Colors.ENDC}")
        for port in tcp:
          service = port.get('service', 'unknown')
          version = port.get ('version', 'unknown')
          product = port.get('product', 'unknown')

          service_info = service
          if product != 'unknown' and version != 'unknown':
            service_info = f"{service} ({product}) {version})"
          elif product != 'unknown':
            service_info = f"{service} ({product})"
          elif version != 'unknown':
            service_info = f"{service} {version}"

          output_lines.append(f"     {Colors.OKBLUE}{port['number']}/tcp{Colors.ENDC} - {service_info}")
      else:
        output_lines.append(f"\n     No open TCP ports found{Colors.ENDC}")

    # UDP Ports
    udp_ports = host.get('udp_ports', [])
    if udp_ports:
      output_lines.append(f"\n     {Colors.BOLD}UDP Ports ({len(udp_ports)} open):{Colors.ENDC}")
      for port in udp_ports:
        service = port.get('service', 'unknown')
        version = port.get('version', 'unknown')
        product = port.get('product', 'unknown')

        service_info = service
        if product != 'unknown' and version != 'unknown':
          service_info = f"{service} ({product}) {version})"
        elif product != 'unknown':
          service_info = f"{service} ({product})"
        elif version != 'unknown':
          service_info = f"{service} {version}"

        output_lines.append(f"     {Colors.OKBLUE}{port['number']}/udp{Colors.ENDC} - {service_info}")
      else:
        output_lines.append(f"\n     {Colors.WARNING}No open UDP ports found{Colors.ENDC}")

      if i < len(results):
        output_lines.append(f"\n{Colors.HEADER}{'-'*60}{Colors.ENDC}")

    return '\n'.join(output_lines)

  @staticmethod
  def save(results: List[Dict[str, Any]], output: str):
    """Save results to file"""
    if not results:
      return
    
    save = input(f"\n{Colors.BOLD}Would you like to save these results to a file? (y/N): {Colors.ENDC}").lower()

    if save in ['y', 'yes']:
      filename = input(f"{Colors.BOLD}Enter filename/path (default: nmap_results.txt): {Colors.ENDC}").strip()
      if not filename:
        filename = "nmap_results.txt"

      try:
        # Remove ANSI color codes for file output
        clean = re.sub(r'\033\[[0-9;]*m', '', output)

        with open(filename, 'w') as f:
          f.write(clean)

        print(f"{Colors.OKGREEN}Results saved to: {filename}{Colors.ENDC}")
      except Exception as e:
        print(f"{Colors.FAIL}Error saving file: {e}{Colors.ENDC}")

def main():
  """Main program entry point"""
  print(f"{Colors.HEADER}{Colors.BOLD}")
  print("╔══════════════════════════════════════╗")
  print("║              nMapper                 ║")
  print("║       Better Network Mapping         ║")
  print("╚══════════════════════════════════════╝")
  print(f"{Colors.ENDC}")

  # Check for NMap
  installer = NMapInstaller()
  if not installer.installed():
    installer.install_nmap()

  # Get targets from user
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

  # Validate input
  validator = IPValidator()
  validated = validator.validate_targets(targets_in)

  if not validated:
    print(f"{Colors.FAIL}No valid targets found. Exciting.{Colors.ENDC}")
    sys.exit(1)

  # Get exclusions from user
  print(f"\n{Colors.BOLD}Enter IP addresses to exclude (optional, comma-separated):{Colors.ENDC}")
  print(f"\n{Colors.HEADER}Examples:{Colors.ENDC} {Colors.OKCYAN}192.168.1.1, 192.168.1.0/28, 10.0.0.1-5{Colors.ENDC}")
  exclusions = input(f"\n{Colors.BOLD}{Colors.OKGREEN}Exclusions {Colors.ENDC}{Colors.BOLD}(Press Enter to Skip): {Colors.ENDC}").strip()

  # Expand targets to individual IPs for count
  expanded = validator.expand_ips(validated)

  if not expanded:
    print(f"{Colors.FAIL}No IP addresses could be expanded from targets. Exiting.{Colors.ENDC}")
    sys.exit(1)

  # Apply exclusions if provided
  exclusions_list = None
  if exclusions:
    exclusions_list = [entry.strip() for entry in exclusions.split(',') if entry.strip()]

    # For display, calculate how many IPs are excluded
    expanded = validator.expand_ips(validated)
    expanded = validator.exclude_ips(expanded, exclusions_list)

    if not expanded:
      print(f"{Colors.FAIL}All IP addresses were excluded. No targets remain. Exiting...{Colors.ENDC}")
      sys.exit(1)

    total_ips = len(expanded)
  else:
    # Calculate total IPs when no exclusions
    expanded = validator.expand_ips(validated)
    total_ips = len(expanded)

  # Show final target list
  print(f"\n{Colors.HEADER}Final Scan Summary:{Colors.ENDC}")
  print(f"{Colors.BOLD}Total IP addresses to scan: {Colors.OKGREEN}{total_ips}{Colors.ENDC}")
  print(F"This action will scan the following IP space(s): {Colors.OKCYAN}{targets_in}{Colors.ENDC}")

  if exclusions:
    print(f"{Colors.BOLD}{Colors.OKGREEN}Excluding:{Colors.ENDC} {Colors.BOLD}{Colors.WARNING}{exclusions}{Colors.ENDC}")

  # Get confirmation from user
  proceed = input(f"\n{Colors.BOLD}Proceed with scan? (y/N): {Colors.ENDC}").strip().lower()
  if proceed in ['n', 'no']:
    print(f"{Colors.WARNING}Scan abored by user.{Colors.ENDC}")
    sys.exit(0)
  
  if total_ips > 1:
    print(f"\n{Colors.OKGREEN}Starting scan on {total_ips} IP addresses.{Colors.ENDC}")
  else:
    print(f"\n{Colors.OKGREEN}Starting scan on {total_ips} IP address.{Colors.ENDC}")
  
  # Run Scan
  runner = NMapRunner()
  results = runner.scan(validated, exclusions_list)

  # Format and display results
  formatter = OutputFormatter()
  output = formatter.format(results)
  print(output)

  # Offer to save results
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