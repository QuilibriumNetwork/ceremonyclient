#!/bin/bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    release_os="linux"
    if [[ $(uname -m) == "aarch64"* ]]; then
        release_arch="arm64"
    else
        release_arch="amd64"
    fi
else
    release_os="darwin"
    release_arch="arm64"
fi

start_process() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        chmod +x ./node-$version-$release_os-$release_arch
        ./node-$version-$release_os-$release_arch &
        main_process_id=$!
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "./node-$version-$release_os-$release_arch"
        chmod +x ./node-$version-$release_os-$release_arch
        ./node-$version-$release_os-$release_arch &
        main_process_id=$!
    else
        echo "unsupported OS for releases, please build from source"
        exit 1
    fi

    echo "process started with PID $main_process_id"
}

is_process_running() {
    ps -p $main_process_id > /dev/null 2>&1
    return $?
}

kill_process() {
    local process_count=$(ps -ef | grep "node-$version" | grep -v grep | wc -l)
    local process_pids=$(ps -ef | grep "node-$version" | grep -v grep | awk '{print $2}' | xargs)

    if [ $process_count -gt 0 ]; then
        echo "killing processes $process_pids"
        kill $process_pids
    else
        echo "no processes running"
    fi
}

fetch() {
    files=$(curl https://releases.quilibrium.com/release | grep $release_os-$release_arch)
    new_release=false

    for file in $files; do
        version=$(echo "$file" | cut -d '-' -f 2)
        if ! test -f "./$file"; then
            curl "https://releases.quilibrium.com/$file" > "$file"
            new_release=true
        fi
    done
}

fetch

kill_process

start_process

while true; do
    if ! is_process_running; then
        echo "process crashed or stopped. restarting..."
        start_process
    fi

    fetch

    if $new_release; then
        kill_process

        start_process
    fi

    sleep 43200
done
