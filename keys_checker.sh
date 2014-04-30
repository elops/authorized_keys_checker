#!/bin/bash
# author        : Hrvoje Spoljar <hrvoje.spoljar@gmail.com>
# description   : checker for authorized_keys file

# Settings
alert_mail="hrvoje.spoljar@gmail.com"

# Array with our IPs which are allowed in from= limitation
allowed_hosts=(
    "127.0.0.1"
    "::ffff:127.0.0.1"
    )

# Array with our IPs which will be enforced on keys which have no from= limitation
enforce_hosts=(
    "127.0.0.1"
    "::ffff:127.0.0.1"
    )

wiki_url="http://docs_for_this_are_found_here"
verbose=0
mail=0
lock=0
scan=0
warn_handler_called=0
lock_dir_created=0
authorized_keys_file="/root/.ssh/authorized_keys"
lock_dir='/tmp/akey_check.lock'

# Functions
warn_handler()
{
    warn_handler_called=1
    if [ "$mail" -eq 0 ]; then
        echo 'WARNING : '"$1"
    else
        mail_msg+='WARNING : '"$1"'\n'
    fi
}

verbose_handler()
{
    if [ "$verbose" -eq 1 ]; then
        echo 'DEBUG : '"$1"
    fi
}

# Exit handler; how we handle bad things and remove lock just before exit.
exit_handler()
{
    local rc=$?
    trap - EXIT

    if [ ! -z "$1" ];then
        echo "$1" 1>&2
        # if we had something to say it was likely error ; which should be raised 
        if [ "$rc" -eq 0 ];then
            local rc=1
        fi
    fi

    # cleanup LOCK only if we created it...
    if [ "$lock_dir_created" -eq 1 ]; then
        rm -rf "$lock_dir"
    fi

    exit "$rc"
}

in_array() {
    check_val="$1"
    declare -x my_array=("${!2}")

    for val in "${my_array[@]}"
    do
        if [ "$check_val" = "$val" ]; then
            return 0
        fi
    done
    return 1
}

help()
{
cat <<EOF

    authorized_keys scanner

    Usage :

    -v  --verbose       Enable verbose output/debugging
    -h  --help          Display this message
    -m  --mail          Send alert mail rather than print to stdout
    -f  --file          path to authorized_keys file to check (root's authorized_keys is default)
    -l  --lock          Lock down keys if found (apply from= restriction)
    -s  --scan          Scan for IPs in from= limitation not in our allowed list

EOF
}

scan()
{
    # check if we have lines without from limit 
    if unsecured_keys=$(egrep -v 'from=|^\ *#' "$authorized_keys_file" | egrep '[a-z0-9]'); then
        warn_handler 'Found root ssh keys without from= limit in '"$authorized_keys_file"' , please fix'
        warn_handler "$unsecured_keys"
    fi

    # ensure all from= fields are limited to our hosts listed in allowed_hosts[@]
    from_field_ips=( $(egrep -o 'from="[^\"]+"' "$authorized_keys_file" | cut -d\" -f2 | tr -s ',' '\n') )
    for ip in "${from_field_ips[@]}"
    do
        if ! in_array "$ip" allowed_hosts[@]; then
            # found strange IP in authorized_keys file
            warn_handler 'unknown IP : '"$ip"' found in authorized_keys file from= limitation'
        fi
    done
}

lock()
{
    # lock all keys without from= to hosts listed in enforce_hosts[@]
    # create backup of authorized_keys file if we are changing it...
    authorized_keys_dir=`readlink -f "$authorized_keys_file"  | egrep -o '^.*/'`
    basename_key_file=`basename "$authorized_keys_file"`
    backup_authorized_keys="$authorized_keys_dir""$basename_key_file"'.backup.'`date +%s`
    tmp_akey=`mktemp /tmp/.akey_backup.XXXXXXXXXX`

    # ensure there is no "$tmp_akey"
    if [ -e "$tmp_akey" ]; then
        rm "$tmp_akey" || exit_handler 'could not remove '"$tmp_akey"' before writing to it'
    fi

    # convert enforce_hosts[@] to string comma delimited
    limit_str=$( IFS=','; echo "${enforce_hosts[*]}" )

    # Insert from restriction to lines without restriction...
    awk -v limit_str="$limit_str" '{if (($0 !~ /^\ *#/) && ($0 ~ /ssh-(rsa|dss)/) && ($1 !~ /(^|,)from(=|,)/))
      { print "from=\""limit_str"\","$0 } else  { print $0 }  }' "$authorized_keys_file" | \
    # Ensure there is space before ssh-rsa/ssh-dss
    sed -r 's/([^\ ])ssh-(rsa|dss)/\1\ ssh-\2/' > "$tmp_akey"

    # if new file differs from backup, keep backup and update authorized_keys, else remove $tmp_akey and backup
    if ! diff "$tmp_akey" "$authorized_keys_file" 1>/dev/null 2>&1; then

        # files differed, keep backup and update authorized_keys
        verbose_handler 'Backing up '"$authorized_keys_file"' -> '"$backup_authorized_keys"
        cp "$authorized_keys_file" "$backup_authorized_keys"

        # update authorized_keys
        verbose_handler 'mv '"$tmp_akey"' -> '"$authorized_keys_file"
        mv "$tmp_akey" "$authorized_keys_file" || exit_handler 'move of file failed when trying to lock file '"$authorized_keys_file"
    else
        # files are the same, remove backup and $tmp_akey. We are leaving authorised_keys asis.
        rm "$tmp_akey"               || exit_handler 'could not remove tmp_akey'
    fi
}

if ! options=`getopt -o vhlsmf: -l verbose,help,lock,scan,mail,file: -- "$@"`
then
    # w00t!? something went wrong...
    help
    exit 1
fi

# setup TRAP
trap exit_handler HUP PIPE INT QUIT TERM EXIT

# ensure only one copy of script is running and create lock
if [ -e "$lock_dir" ]; then
    exit_handler "Another instance of script detected, exiting..."
elif ! mkdir "$lock_dir"; then
    exit_handler "Can't create lock dir"
else
    lock_dir_created=1
fi

set -- $options

while [ $# -gt 0 ]
do
    case $1 in
        -v|--verbose) verbose=1;;
        -h|--help) help; exit;;
        -l|--lock) lock=1;;
        -s|--scan) scan=1;;
        -m|--mail) mail=1;;
        -f|--file) authorized_keys_file=`echo "$2"| cut -d\' -f2`; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2;help; exit 1;;
        (*) break;;
    esac
    shift
done

if [ "$scan" -eq 1 -o "$lock" -eq 1 ] && [ ! -e "$authorized_keys_file" ]; then
    exit_handler "Can't"' find authorized_keys file '"$authorized_keys_file"
fi
if [ "$scan" -eq 1 ]; then
    scan
fi
if [ "$lock" -eq 1 ]; then
    lock
fi

if [ "$mail" -eq  1 ] && [ "$warn_handler_called" -eq 1 ]; then
    (echo 'Please check wiki page : '"$wiki_url"; echo -e "$mail_msg")| \
      mail -s "authorized_keys violation alert at `hostname`" "$alert_mail"
fi
# EOF
