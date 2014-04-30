*keys_checker*

Simple scanner that scans authorized_keys file and enforces
from= limitation and reports alien IPs in from= field

    authorized_keys scanner

    Usage :

    -v  --verbose       Enable verbose output/debugging
    -h  --help          Display this message
    -m  --mail          Send alert mail rather than print to stdout
    -f  --file          path to authorized_keys file to check (root's authorized_keys is default)
    -l  --lock          Lock down keys if found (apply from= restriction)
    -s  --scan          Scan for IPs in from= limitation not in our allowed list

