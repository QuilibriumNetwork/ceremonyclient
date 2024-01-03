#!/bin/bash

start_process() {
    go run ./... &
    process_pid=$!
    child_process_pid=$(pgrep -P $process_pid)
}

is_process_running() {
    ps -p $process_pid > /dev/null 2>&1
    return $?
}

kill_process() {
    kill $process_pid
    kill $child_process_pid
}

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
