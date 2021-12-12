# Log4j2 RCE Exploitation Detection

This script conducts a passive scan to detect exploitation attempts for the CVE-2021-44228 log4j2 RCE.

## Pre-requisites

Requires python3 installed to be run.

## Usage

```python
$ python log4j2_detect.py [-h] [-p path] [-d maxdis] [--fast] [--debug] [--defaultpaths]

Log4Shell Exploitation Detection

optional arguments:
  -h, --help  show this help message and exit
  -p path     Path to scan
  -d maxdis   Maximum distance between characters
  --debug     Debug output
  --fast      Skip log entries that are timestamped not in Years 2021/2022.
```

## Summary

Given the path to "log4j" log files, example: /var/log,
The script searches each log file for exploit strings

( ${jndi:ldap:/', '${jndi:rmi:/', '${jndi:ldaps:/', '${jndi:dns:/ )

Note that the string characters could be disperesed across the file line by line.
Use the maxdis argument to specify the maxiumum distance expected between characters. Default = 20.
