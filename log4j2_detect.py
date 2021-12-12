#!/usr/bin/env python3
"""
Script to detect exploitation attempts of
CVE-2021-44228: Log4j RCE Vulnerability
NOTE that teams must have had enabled
saving log information as files for scan
to be conducted.
"""

import os
import sys
import copy
import gzip
import urllib.parse
import argparse
from datetime import datetime, timedelta
import traceback
import base64

EXPLOIT_STRINGS = ['${jndi:ldap:/', '${jndi:rmi:/', '${jndi:ldaps:/', '${jndi:dns:/', '$%7Bjndi:ldap://', '%2524%257Bjndi:ldap:/', '%2F%252524%25257Bjndi%3Aldap%3A%2F', '%2F%252524%25257Bjndi%3Aldaps%3A%2F', '%2F%252524%25257Bjndi%3Adns%3A%2F'
'%2F%252524%25257Bjndi%3Armi%3A%2F']
DEFAULT_PATHS = ['/var/log', '/storage/log/vmware', '/var/atlassian/application-data/jira/log', '[/home/logs]']
INSTALL_PATHS = ['/usr/local']


def log4j_version_detect():
    """
    Detect the version of log4j instance
    in the default install paths
    """
    for pathx in INSTALL_PATHS:
        if not os.path.isdir(pathx):
            print("Installation path for Log4j %s not found" % pathx)
        else:
            subfolders = [ f.path for f in os.scandir(pathx) if f.is_dir() ]
            for folder in subfolders:
                if "log4j" in folder:
                    print("Detected log4j installation in %s " % folder)
                    version = folder.partition('log4j-')[2]
                    if version:
                        if version[1] == '1':
                            print("Your found log4j installation is series 1.x.x, it is not affected")
                        elif version!='2.15.0':
                            print("Your found log4j installation is %s " % version)

def base64_decode(log):
    payload = ""
    if "Base64" in log:
        payload = base64.decodebytes(log.split("Base64/")[1].split("}")[0].encode()).decode()
    return payload

def check_line(line, detection_pad):
    """
    Check line and identify presence of
    a character present in exploit string.
    Look for the next consecutive character
    within the maximum distance
    :param line:    single line from a log file
    :type  line:    str
    :param detection_pad:    dictionary created from attack string
    :type  detection_pad:    dict
    :return:    detection string if found
    :rtype:     str
    """
    line = urllib.parse.unquote(line)
    linechars = list(line)
    # temporary detection pad
    dp = copy.deepcopy(detection_pad)
    # Walk over characters
    for c in linechars:
        for exploit_string in dp:
            # If the character in the line matches the character in the detection
            if c == dp[exploit_string]["chars"][dp[exploit_string]["level"]]:
                dp[exploit_string]["level"] += 1
                dp[exploit_string]["current_distance"] = 0
            # If level > 0 count distance to the last char
            if dp[exploit_string]["level"] > 0:
                dp[exploit_string]["current_distance"] += 1
                # If distance is too big, reset level to zero
                if dp[exploit_string]["current_distance"] > dp[exploit_string]["maximum_distance"]:
                   dp[exploit_string]["current_distance"] = 0
                   dp[exploit_string]["level"] = 0
            # Is the pad completely empty?
            if len(dp[exploit_string]["chars"]) == dp[exploit_string]["level"]:
                return exploit_string

def scan_path(path, detection_pad, fast, debug):
    """
    Give a path, scan all files to check if
    an exploit string is written/obfuscated
    in it via detection pads
    :param path:    single line from a log file
    :type  path:    str
    :param detection_pad:    dictionary created from attack string
    :type  detection_pad:    dict
    :param fast:    fast check enable/disable
    :type  fast:    bool
    :param debug:    debug enable/disable
    :type  debug:    bool
    :return:    number of detections
    :rtype:     int
    """
    number_of_detections = 0
    # Loop over files
    for root, directories, files in os.walk(path, followlinks=False):
        for filename in files:
            file_path = os.path.join(root, filename)
            print("Processing %s ..." % file_path)
            if debug:
                print("Processing %s ..." % file_path)
            try:
                # Gzipped logs
                if file_path.endswith(".log.gz"):
                    with gzip.open(file_path, 'rt') as gzlog:
                        c = 0
                        for line in gzlog:
                            c += 1
                            # Fast mode - timestamp check
                            if fast and not "2021" in line and not "2022" in line:
                                continue
                            # Analyze the line
                            result = check_line(line.lower(), detection_pad)
                            if result:
                                payload = base64_decode(line.rstrip())
                                number_of_detections += 1
                                print("Warning: Exploitation attempt detected FILE: %s LINE_NUMBER: %d LINE: %s DEOBFUSCATED_STRING: %s DECODED_PAYLOAD: %s" %
                                (file_path, c, line.rstrip(), result))
                # Plain Text
                else:
                    with open(file_path, 'r') as logfile:
                        c = 0
                        for line in logfile:
                            c += 1
                            # Fast mode - timestamp check
                            if fast and not "2021" in line and not "2022" in line:
                                continue
                            # Analyze the line
                            result = check_line(line.lower(), detection_pad)
                            if result:
                                payload = base64_decode(line.rstrip())
                                number_of_detections += 1
                                print("Warning: Exploitation attempt detected FILE: %s LINE_NUMBER: %d LINE: %s DEOBFUSCATED_STRING: %s DECODED_PAYLOAD: %s" %
                                (file_path, c, line.rstrip(), result, payload))
            except UnicodeDecodeError as e:
                if args.debug:
                    print("Unable to process FILE: %s REASON: most likely not an ASCII based log file" % file_path)
            except Exception as e:
                print("Unable to process FILE: %s REASON: %s" % (file_path, traceback.print_exc()))
    # Result
    if number_of_detections > 0:
        print("Warning: %d exploitation attempts detected in PATH: %s" % (number_of_detections, path))
    else:
        print("No Log4Shell exploitation attempts detected in path PATH: %s" % path)
    return number_of_detections

def prepare_detections(maximum_distance):
    """
    Deconstruct exploit string
    to form detection pads
    :param dist:    maximum distance
    :type  dist:    int
    :return:    detection pads
    :rtype:     dict
    """
    detection_pad = {}
    for ex in EXPLOIT_STRINGS:
        detection_pad[ex] = {}
        detection_pad[ex] = {
            "chars": list(ex),
            "maximum_distance": maximum_distance,
            "current_distance": 0,
            "level": 0
        }
    return detection_pad

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Log4Shell Exploitation Detection')
    parser.add_argument('-p', nargs='+', help='Path to scan', metavar='path', default='')
    parser.add_argument('-d', help='Maximum distance between each character, Default=30', metavar='distance', default=30)
    parser.add_argument('--fast', action='store_true', default=False, help="Skip log lines that don't contain a 2021 or 2022 time stamp")
    parser.add_argument('--defaultpaths', action='store_true', default=False, help='Scan a set of default paths known to contain relevant log files.')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if not args.p and not args.defaultpaths:
        parser.print_help(sys.stderr)
        print("")
        print("Must specify at least one folder to scan with -p target-folder or use --defaultpaths")
        sys.exit(1)

    print("")
    date_scan_start = datetime.now()
    print("Scan initiated at DATE: %s" % date_scan_start)
    log4j_version_detect()

    # Prepare the detection pads
    detection_pad = prepare_detections(int(args.d))

    # Counter
    all_detections = 0

    # Scan paths
    paths = args.p
    if args.defaultpaths:
        paths = DEFAULT_PATHS
    for path in paths:
        if not os.path.isdir(path):
            print("Path %s doesn't exist" % path)
            if not args.defaultpaths:
                print("Path %s doesn't exist" % path)
            continue
        print("Scanning FOLDER: %s ..." % path)
        detections = scan_path(path, detection_pad, args.fast, args.debug)
        all_detections += detections

    # Finish
    if all_detections > 0:
        print("Warning: %d exploitation attempts detected in the complete scan" % all_detections)
    else:
        print("No exploitation attempts detected in the scan")
    date_scan_end = datetime.now()
    print("Scan completed DATE: %s" % date_scan_end)
