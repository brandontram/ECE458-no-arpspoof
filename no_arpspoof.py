import sys, argparse, os, nmap, netifaces, socket, threading, math

parser = argparse.ArgumentParser(description="Detect active man in the middle attacks")
parser.add_argument("-d", "--debug", action="store_true", help="Debug Mode")
PURIFY_RETRIES = 3

args = parser.parse_args()
debug = args.debug
nm = nmap.PortScanner()

def main():
	gateway = netifaces.gateways()['default']
	if len(gateway) < 1:
		print("No gateway found")
		sys.exit()

	gateway_ip  = gateway[netifaces.AF_INET][0]

	if detect_arp_spoof(gateway_ip):
		purify_arp_cache(gateway_ip)
	else:
		threading.Timer(1, main).start()

def detect_arp_spoof(gateway_ip):
	scan_result = nm.scan(hosts = gateway_ip, arguments = '-sP -n')
	true_mac_address = get_true_mac(gateway_ip)
	arp_mac_address = get_mac_from_arp(gateway_ip)

	arp_spoof_detected = not compare_mac(true_mac_address, arp_mac_address)
	if not arp_spoof_detected:
		print(true_mac_address + " == " + arp_mac_address + " (YOU ARE NOT BEING WATCHED)")
	else:
		print(true_mac_address + " != " + arp_mac_address + " (WATCH OUT! YOU ARE BEING WATCHED)")

	return arp_spoof_detected

def compare_mac(nmap_mac, arp_mac):
	nmap_mac_as_array = nmap_mac.split(':')
	arp_mac_as_array = arp_mac.split(':')

	if len(nmap_mac_as_array) != len(arp_mac_as_array):
		return False

	for nmap_token, arp_token in zip(nmap_mac_as_array, arp_mac_as_array):
		if math.fabs(len(nmap_token) - len(arp_token)) == 1:
			# ARP crops 0s; bc:16:65:f4:d0:00 (nmap) bc:16:65:f4:d0:0 (arp). Use a basic similarity check
			if nmap_token != '0' + arp_token and nmap_token != arp_token + '0':
				return False
		elif nmap_token != arp_token:
			return False

	return True

def get_true_mac(ip):
	scan_result = nm.scan(hosts = ip, arguments = '-sP -n')
	return str(scan_result['scan'][ip]['addresses']['mac'].lower())

def get_mac_from_arp(ip):
	arp_table_raw = os.popen('arp -a')
	for line in arp_table_raw:
		parsed_entry = line.split(' ')
		ip_string = '(' + ip + ')'
		if ip_string in parsed_entry:
			index = parsed_entry.index(ip_string)
			arp_mac_address = str(parsed_entry[index + 2]) # mac address is always 2 tokens after IP

	return arp_mac_address

def purify_arp_cache(poisoned_arp_ip):
	for i in range(0, PURIFY_RETRIES):
		print("ARP CACHE PURIFY ATTEMPT " + str(i))
		os.system("arp -S " + poisoned_arp_ip + " " + get_true_mac(poisoned_arp_ip))

		if not detect_arp_spoof(poisoned_arp_ip):
			print("ARP CACHE ENTRY PURIFIED. IP: " + poisoned_arp_ip + ", MAC: " + get_mac_from_arp(poisoned_arp_ip))
			break
		else:
			if i == PURIFY_RETRIES - 1:
				print("ARP CACHE COULD NOT BE PURIFIED. GET OFF THE NETWORK.")
			else:
				print("ARP CACHE ENTRY NOT PURIFIED. Retrying...")

if __name__ == '__main__':
	main()