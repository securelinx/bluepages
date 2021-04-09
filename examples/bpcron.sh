#!/bin/bash

# Set this if you want to get alerts by email if there is an issue
MAILTO="admins@example.com"

# Where your bluepages is installed
BP="/opt/securelinx/bluepages"

notify_error() {
        action=$1
        log=$2
        subject="Error during $action"

        echo "$subject" | logger -t 'BP'
        echo "$log" | logger -t 'BP'

        if [[ -z "$MAILTO" ]]; then
                return 0
        fi

        sendmail $MAILTO <<-EOM
                Subject: [BP] $subject
                To: $MAILTO

                $log
        EOM
}

# Do a sync
log=$($BP/syncbp.py 2>&1)
rc=$?

# If the sync fails then log this and exit
if [[ $rc -ne 0 ]]; then
    notify_error "sync" "$log"
    exit $rc
fi

# Do an update
log=$($BP/exportbp.py 2>&1)
rc=$?

# If the update fails then log this and exit
if [[ $rc -ne 0 ]]; then
    notify_error "update" "$log"
    exit $rc
fi

# make yp
log=$(/usr/bin/make -C /var/yp 2>&1)
rc=$?

# If the make fails then log this
if [[ $rc -ne 0 ]]; then
    notify_error "ypmake" "$log"
fi

exit $rc

