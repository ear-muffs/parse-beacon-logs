#!/usr/bin/python3

import os
import re
import time

def get_beacon_events():
    name = 'events.log'
    path = 'logs'
    result = []

    if not os.path.isdir(path):
        print('The \'logs\' directory from a Cobalt Strike Team Server must exist in cwd for successful parsing. Re-run from different location.')
        exit()

    print('*** Generating list of all initial beacon connections from events.log files...')
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))

    initial_beacon_regex = re.compile('.*initial beacon.*')
    initial_beacon_list = [] # instantiate list
    for r in result: # iterate through all event.log 
        with open(r, 'r') as log:
            events = log.readlines()
            initial_beacon_list.extend((filter(initial_beacon_regex.match,events)))

    print('===================================')
    print('========= INITIAL BEACONS =========')
    print('===================================\n')

    for b in initial_beacon_list:
        print(b, end='')

    return initial_beacon_list
    
def get_logs_for_important_hosts(beaconing_hosts):
    path = 'logs'

    print('===================================')
    print('========== UNIQUE  HOSTS ==========')
    print('===================================')
    
    for k in beaconing_hosts.keys():
        print(k)

    print('\n')

    important_hosts = input('Which of these hosts do you care about? Enter a comma-delimited list: ').split(',')
    
    print('\n')
    print('*** Identifying beacon logs for designated hosts...')

    # lookup IPs for designated hosts
    for h in important_hosts:
        important_ips = [] # reset values for each host iteration
        h = h.replace(' ', '') # get rid of any extra spaces
        important_ips.extend(beaconing_hosts[h])
    
        result = []
        logs_list = []
        # find logs for all IPs associated with a given host
        for i in important_ips:
            i = i.replace(' ','') # get rid of any extra spaces
            for root, dirs, files in os.walk(path):
                if i in dirs: # find IP address folder
                    for root, dirs, files in os.walk(os.path.join(root,i)):
                        for f in files: # find beacon logs within IP folder
                            logs_list.append(os.path.join(root,f))

        print('===================================')
        print('========== BEACON  LOGS  ==========')
        print('===================================')
    
        print('*** Log files for host ' + h + ' are:')
        for l in logs_list:
            print(l)

        extract_key_commands(h, logs_list) # pass current host and list of logfiles
    
def extract_key_commands(h, logs_list):
    print('\n===================================')
    print('============= OUTPUT ==============')
    print('===================================')

    print('*** Extracting the following commands: run, execute-assembly, socks, upload, mkdir from all beacon logs for host ' + h)

    # if you want to add more commands to extract, they go here!
    extracted_commands_regex = re.compile('.*((> run)|(> execute-assembly)|(> socks)|(> upload)|(> mkdir)|(beacon arch:)).*')
    
    extracted_list = []
    full_list = []

    for l in logs_list:
        f = open(l,'r').readlines()
        full_list.extend(f)
        extracted_list.extend(list(filter(extracted_commands_regex.match,f)))

    outfilename_extracted = h+'_extracted_'+time.strftime('%Y%m%d-%H%M%S')+'.txt'
    outfilename_full = h+'_full_'+time.strftime('%Y%m%d-%H%M%S')+'.txt'
    outfile_extracted = open(outfilename_extracted,'a')
    outfile_full = open(outfilename_full,'a')
    
    for i in sorted(extracted_list):
        outfile_extracted.write(i)

    for i in full_list:
        outfile_full.write(i)

    outfile_extracted.close()
    outfile_full.close()

    print('*** Extracted output for host ' + h + ' can be found in the file: ' + outfilename_extracted + '. This file is sorted chronologically.')
    print('*** Full output for host ' + h + ' can be found in the file: ' + outfilename_full + '. This file is NOT sorted chronologically.\n')

def main():
    beacons = get_beacon_events()

    print('\n')

    beaconing_hosts_dict = {}
    
    for b in beacons:
        ip = re.search('@(.+?) ',b).group(1)
        host = re.search('\((.*?)\)\\n',b).group(1)
    
        if host in beaconing_hosts_dict:
            if ip not in beaconing_hosts_dict[host]:
                beaconing_hosts_dict[host].append(ip)
        else:
            beaconing_hosts_dict[host] = [ip]

    get_logs_for_important_hosts(beaconing_hosts_dict) 
    
main()
