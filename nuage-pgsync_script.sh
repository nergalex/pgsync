#!/bin/bash

USR="root" # user that launch this instance
PYTHON_BIN="python3.6"
WORKING_REPOSITORY="/root/nuage-pgsync"
LOG_FILE_PATH="/root/nuage-pgsync/logs"
EVENT_STREAM_MODE="PUSH_CHANNEL" # Choices : 'AMQP' for Nuage 5.1.1 and above, or 'PUSH_CHANNEL' for backward compatibility
LOG_LEVEL="verbose" # Choices : 'debug', 'verbose' or 'warning' by default
INI_FILE="nuage-pgsync.ini"

#-------------------------------------DO NOT EDIT AFTER THIS LINE -----------------------------------------
LOG_FILE_EVENT_STREAM="${LOG_FILE_PATH}/event_stream.log"
LOG_FILE_STATE_ENGINE="${LOG_FILE_PATH}/state_engine.log"
LOG_FILE_LAUNCHER="${LOG_FILE_PATH}/launcher.log"
PID_event_stream="${WORKING_REPOSITORY}/event_stream.pid"
PID_state_engine="${WORKING_REPOSITORY}/state_engine.pid"
if [ ${EVENT_STREAM_MODE} == 'PUSH_CHANNEL' ] ; then
    EVENT_STREAM_SCRIPT="event_stream-push_channel.py"
else
    EVENT_STREAM_SCRIPT="event_stream-amqp.py"
fi
STATE_ENGINE_SCRIPT="state_engine.py"

PARAM=""
if [ ${LOG_LEVEL} == 'debug' ] ; then
    PARAM="${PARAM} --debug"
else
    if [ ${LOG_LEVEL} == 'verbose' ] ; then
        PARAM="${PARAM} --verbose"
    fi
fi
PARAM="${PARAM} --ini-file ${WORKING_REPOSITORY}/${INI_FILE}"
PARAM_event_stream="${PARAM} --log-file ${LOG_FILE_EVENT_STREAM}"
PARAM_state_engine="${PARAM} --log-file ${LOG_FILE_STATE_ENGINE}"
COMMAND_event_stream="${PYTHON_BIN} ${WORKING_REPOSITORY}/${EVENT_STREAM_SCRIPT} ${PARAM_event_stream}"
COMMAND_state_engine="${PYTHON_BIN} ${WORKING_REPOSITORY}/${STATE_ENGINE_SCRIPT} ${PARAM_state_engine}"
REGEX_RUNNING="^.*Running.*$"
REGEX_ERROR="^.*ERROR.*$"

status() {
	PID_NAME=$1
	PID_FILE=$2

    echo "     +-- $PID_NAME"
    if [ -f $PID_event_stream ]
    then
        echo "     |   +-- Pid file: $( cat $PID_FILE ) [$PID_FILE]"
        echo
        ps -ef | grep -v grep | grep $( cat $PID_FILE )
    else
        echo "     |   +-- No Pid file for ${PID_NAME}"
    fi
        echo "     |"
}

start() {
    echo
    echo "==== Start"

    # clear LOG_FILES
    echo "     +-- logs"
   	if [ -f ${LOG_FILE_LAUNCHER} ]
	    then
	    	echo "     |   +-- remove old launcher log-file"
	        /bin/rm ${LOG_FILE_LAUNCHER}
	        touch ${LOG_FILE_LAUNCHER}
	fi
   	if [ -f ${LOG_FILE_STATE_ENGINE} ]
	    then
	    	echo "     |   +-- remove old state-engine log-file"
	        /bin/rm ${LOG_FILE_STATE_ENGINE}
            touch ${LOG_FILE_STATE_ENGINE}
	fi
   	if [ -f ${LOG_FILE_EVENT_STREAM} ]
	    then
	    	echo "     |   +-- remove old event-stream log-file"
	        /bin/rm ${LOG_FILE_EVENT_STREAM}
            touch ${LOG_FILE_EVENT_STREAM}
	fi

    # launch state_engine
    echo "     +-- state_engine"
    if [ -f ${PID_state_engine} ]
    then
        echo
        echo "     |   +-- Already started. PID: [$( cat ${PID_state_engine} )]"
    else
        touch ${PID_state_engine}
        if nohup ${COMMAND_state_engine} >>${LOG_FILE_LAUNCHER} 2>&1 &
        then
        	echo $! >${PID_state_engine}
        	echo "     |   +-- $(date '+%Y-%m-%d %X'): START" >>${LOG_FILE_LAUNCHER}
        else
        	echo "     |   +-- Error... "
            /bin/rm ${PID_state_engine}
        fi
    fi

	# wait for state_engine started
    echo "     |   +-- state_engine is starting, please wait"
    printf "     |   |   "
	REGEX="^.*Running.*$"
	EVENT_STREAM_STARTED=false
	while [ ${EVENT_STREAM_STARTED} = false ]
	do
	    while read line
		do
			if [[ ${line} =~ ${REGEX_RUNNING} ]] ; then
                echo "     |   +-- done."
				EVENT_STREAM_STARTED=true
				break
			fi
			if [[ ${line} =~ ${REGEX_ERROR} ]] ; then
                echo "     |   +-- Ending with error, please check log files."
				exit
			fi
		done < ${LOG_FILE_STATE_ENGINE}
	done

    # launch event_stream
    echo "     +-- event_stream"
    if [ -f $PID_event_stream ] ; then
        echo "     |   +-- Already started. PID: [$( cat $PID_event_stream )]"
    else
        touch $PID_event_stream
        if nohup $COMMAND_event_stream >>$LOG_FILE_LAUNCHER 2>&1 &
        then
        	echo $! >$PID_event_stream
            echo "     |   +-- $(date '+%Y-%m-%d %X'): START" >>$LOG_FILE_LAUNCHER
        else
        	echo "     |   +-- Error... "
            /bin/rm $PID_event_stream
        fi
    fi

    # wait for event_stream started
    echo "     |   +-- event-stream is starting, please wait"
    printf "     |   |   "

	EVENT_STREAM_STARTED=false
	while [ ${EVENT_STREAM_STARTED} = false ]
	do
	    while read line
		do
			if [[ ${line} =~ ${REGEX_RUNNING} ]] ; then
                echo "     |   +-- done."
				EVENT_STREAM_STARTED=true
				break
			fi
			if [[ ${line} =~ ${REGEX_ERROR} ]] ; then
                echo "     |   +-- Ending with error, please check log files."
				exit
			fi
		done < ${LOG_FILE_EVENT_STREAM}
	done
}

kill_cmd() {
	PID_NAME=$1
	PID_SCRIPT=$2
	PID_FILE=$3

    SIGNAL=""; MSG="Killing "
    # kill event_stream
    while true
    do
        LIST=`ps -ef | grep -v grep | grep $PID_SCRIPT | grep -w $USR | awk '{print $2}'`
        if [ "$LIST" ]
        then
            echo; echo "$MSG $LIST" ; echo
            echo $LIST | xargs kill $SIGNAL
            sleep 2
            SIGNAL="-9" ; MSG="Killing $SIGNAL"
            if [ -f $PID_FILE ]
            then
                /bin/rm $PID_FILE
            fi
        else
           echo "     |   +-- All other ${PID_NAME} for user ${USR} was killed." ; echo
           break
        fi
    done
}

stop() {
	PID_NAME=$1
	PID_FILE=$2

    echo "     +-- ${PID_NAME}"
    if [ -f $PID_FILE ] ; then
        if kill $( cat $PID_FILE ) ; then
            echo "     |   +-- Known ${PID_NAME} was killed."
            echo "$(date '+%Y-%m-%d %X'): ${PID_NAME} STOP" >>$LOG_FILE_LAUNCHER
        fi
        /bin/rm $PID_FILE
        kill_cmd "${PID_NAME}" "${WORKING_REPOSITORY}/${PID_NAME}.py" "$PID_FILE"
    else
        echo "     |   +-- No pid file for ${PID_NAME}. Already stopped?"
    fi
}

case "$1" in
    'start')
            start
            ;;
    'stop')
			echo
		    echo "==== Stop"
            stop "event_stream" "$PID_event_stream"
            stop "state_engine" "$PID_state_engine"
            echo
            ;;
    'restart')
			echo
		    echo "==== Stop"
            stop "event_stream" "$PID_event_stream"
            stop "state_engine" "$PID_state_engine"
            echo
            echo "Sleeping..."; sleep 1 ;
            start
            ;;
    'status')
		    echo
		    echo "==== Status"
            status "event_stream" "$PID_event_stream"
            status "state_engine" "$PID_state_engine"
            echo
            ;;
    *)
            echo
            echo "Usage: $0 { start | stop | restart | status }"
            echo
            exit 1
            ;;
esac

exit 0
