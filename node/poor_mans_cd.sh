#!/bin/bash

start_process() {
    GOEXPERIMENT=arenas go run ./... &
    local process_pid=$!
    local child_process_pid=$(pgrep -P $process_pid)
    echo "Process started with PID $process_pid and child PID $child_process_pid"
}

is_process_running() {
    local process_pid=$(ps -ef | grep "exe/node" | grep -v grep | awk '{print $2}')
    ps -p $process_pid > /dev/null 2>&1
    return $?
}

kill_process() {
    local process_count=$(ps -ef | grep "exe/node" | grep -v grep | wc -l)
    local process_pids=$(ps -ef | grep "exe/node" | grep -v grep | awk '{print $2}' | xargs)

    if [ $process_count -gt 0 ]; then
        echo "killing processes $process_pids"
        kill $process_pids

        local child_process_count=$(pgrep -P $process_pids | wc -l)
        local child_process_pids=$(pgrep -P $process_pids | xargs)
        if [ $child_process_count -gt 0 ]; then
            echo "killing child processes $child_process_pids"
            kill $child_process_pids
        else
            echo "no child processes running"
        fi
    else
        echo "no processes running"
    fi
}

kill_process

start_process

while true; do
    if ! is_process_running; then
        echo "Process crashed or stopped. Restarting..."
        start_process
    fi

    git fetch

    local_head=$(git rev-parse HEAD)
    remote_head=$(git rev-parse @{u})

    if [ "$local_head" != "$remote_head" ]; then
        kill_process

        git pull

        start_process
    fi

    sleep 60
done
