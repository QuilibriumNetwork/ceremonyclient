#!/bin/bash

start_process() {
    version=$(cat config/version.go | grep -A 1 "func GetVersion() \[\]byte {" | grep -Eo '0x[0-9a-fA-F]+' | xargs printf "%d.%d.%d")
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [[ $arch == arm* ]]; then
            ./node-$version-linux-arm64 &
        else
            ./node-$version-linux-amd64 &
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        ./node-$version-darwin-arm64 &
    else
        echo "unsupported OS for releases, please build from source"
        exit 1
    fi
    main_process_id=$!
    local child_process_pid=$(pgrep -P $main_process_id)
    echo "process started with PID $main_process_id and child PID $child_process_pid"
}

is_process_running() {
    ps -p $main_process_id > /dev/null 2>&1
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
        echo "process crashed or stopped. restarting..."
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
