#!/bin/bash

set -e

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Function to compile libraries
compile_libs() {
    # Install Rust packages
    echo "Starting VDF generation..."
    cd $PROJECT_DIR/vdf
    ./generate.sh > /dev/null 2>&1
    echo "VDF generation completed."

    echo "Starting BLS48581 generation..."
    cd $PROJECT_DIR/bls48581
    ./generate.sh > /dev/null 2>&1
    echo "BLS48581 generation completed."

    # Build node binary
    echo "Building node binary..."
    cd $PROJECT_DIR/node
    # The file path needs to be absolute to avoid issues with go build-- i.e. the variable needs to be expanded out when the command is run
    GOEXPERIMENT=arenas CGO_ENABLED=1 go build -ldflags "-linkmode 'external' -extldflags '-L$(echo $PROJECT_DIR)/target/release -lvdf -lbls48581 -ldl -lm'" -o node main.go
    echo "Node binary build completed."
}

get_peer_id() {
    local config_suffix=$1
    local output=$($PROJECT_DIR/node/node --signature-check=false --network=1 --config=.config$config_suffix --peer-id)
    echo "$output" | grep "Peer ID:" | awk '{print $3}'
}

# New variables for node count, cores per node, and CPU limit
NODE_COUNT=2
CORES_PER_NODE=4
CPU_LIMIT_PERCENT=25

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            --recompile-libs)
            RECOMPILE_LIBS=true
            shift
            ;;
            --reinstall-deps)
            REINSTALL_DEPS=true
            shift
            ;;
            --redo-config)
            REDO_CONFIG=true
            shift
            ;;
            --node-count)
            NODE_COUNT="$2"
            NODE_COUNT_SET=true
            shift 2
            ;;
            --cores-per-node)
            CORES_PER_NODE="$2"
            if [ "$CORES_PER_NODE" -lt 4 ]; then
                echo "Error: Minimum cores per node is 4. Setting to 4."
                CORES_PER_NODE=4
            fi
            CORES_PER_NODE_SET=true
            shift 2
            ;;
            --cpu-limit)
            CPU_LIMIT_PERCENT="$2"
            CPU_LIMIT_SET=true
            shift 2
            ;;
            --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
            --dry-run)
            DRY_RUN=true
            shift
            ;;
            *)
            echo "Unknown option: $key"
            exit 1
            ;;
        esac
    done
}

# Function to get current CPU utilization
get_cpu_utilization() {
    local cpu_idle=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print $1}')
    echo "$(awk "BEGIN {print 100 - $cpu_idle}")"
}

# Function to recommend node count and CPU limit
recommend_resources() {
    local total_cores=$(nproc)
    local total_memory=$(free -g | awk '/^Mem:/{print $2}')
    local current_cpu_usage=$(get_cpu_utilization)
    local available_cpu=$(awk "BEGIN {print 100 - $current_cpu_usage}")
    
    local recommended_nodes=$(( total_cores / 4 ))
    local recommended_cores_per_node=4  # Default to 4 cores per node (minimum required)
    local recommended_cpu_limit=$(awk "BEGIN {print int($available_cpu / $recommended_nodes)}")
    
    # Ensure we have at least 1 node and don't exceed 100% CPU
    recommended_nodes=$(( recommended_nodes > 0 ? recommended_nodes : 1 ))
    recommended_cpu_limit=$(( recommended_cpu_limit > 0 ? (recommended_cpu_limit < 100 ? recommended_cpu_limit : 100) : 10 ))
    
    echo "System resources:"
    echo "  Total CPU cores: $total_cores"
    echo "  Available memory: ${total_memory}GB"
    echo "  Current CPU usage: ${current_cpu_usage}%"
    echo "  Available CPU: ${available_cpu}%"
    echo ""
    echo "Recommended configuration:"
    echo "  Number of nodes: $recommended_nodes"
    echo "  Cores per node: $recommended_cores_per_node"
    echo "  CPU limit per node: ${recommended_cpu_limit}%"
    echo ""
    
    # Ask user if they want to use the recommended values
    read -p "Do you want to use these recommended values? (y/n) [y]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        # Prompt user for values
        read -p "Enter the number of nodes [$recommended_nodes]: " user_nodes
        NODE_COUNT=${user_nodes:-$recommended_nodes}
        
        while true; do
            read -p "Enter the number of cores per node (minimum 4) [$recommended_cores_per_node]: " user_cores
            CORES_PER_NODE=${user_cores:-$recommended_cores_per_node}
            if [ "$CORES_PER_NODE" -ge 4 ]; then
                break
            else
                echo "Error: Minimum cores per node is 4. Please enter a value of 4 or higher."
            fi
        done
        
        read -p "Enter the CPU limit per node (%) [$recommended_cpu_limit]: " user_cpu_limit
        CPU_LIMIT_PERCENT=${user_cpu_limit:-$recommended_cpu_limit}
    else
        NODE_COUNT=$recommended_nodes
        CORES_PER_NODE=$recommended_cores_per_node
        CPU_LIMIT_PERCENT=$recommended_cpu_limit
    fi
    
    echo "Configuration set:"
    echo "  Number of nodes: $NODE_COUNT"
    echo "  Cores per node: $CORES_PER_NODE"
    echo "  CPU limit per node: ${CPU_LIMIT_PERCENT}%"
    echo ""
    echo "To start with these values next time, use the following command:"
    echo "$0 --node-count $NODE_COUNT --cores-per-node $CORES_PER_NODE --cpu-limit $CPU_LIMIT_PERCENT"
}

# Function to check available resources
check_resources() {
    local total_cores=$(nproc)
    local total_memory=$(free -g | awk '/^Mem:/{print $2}')
    local required_cpu=$((NODE_COUNT * CPU_LIMIT_PERCENT))
    local required_memory=$((NODE_COUNT * 2)) # Assuming each node needs 2GB of RAM

    if [ $required_cpu -gt 100 ]; then
        echo "Error: Total CPU usage exceeds 100%. Required: $required_cpu%, Available: 100%"
        exit 1
    fi

    if [ $required_memory -gt $total_memory ]; then
        echo "Error: Not enough memory available. Required: ${required_memory}GB, Available: ${total_memory}GB"
        exit 1
    fi

    echo "Resource check passed. Available cores: $total_cores, Available memory: ${total_memory}GB"
}

# Function to setup configuration
setup_config() {
    cd $PROJECT_DIR/node
    # Delete any existing config directories
    rm -rf .config*
    peer_ids=()
    
    # Step 1: Generate configs and collect peer IDs
    for i in $(seq 1 $NODE_COUNT); do
        if [[ $i -eq 1 ]]; then
            CONFIG_SUFFIX=""
        else
            CONFIG_SUFFIX="$i"
        fi
        
        # Get the peer ID for the config
        peer_ids[$i]=$(get_peer_id "$CONFIG_SUFFIX")
        echo "Peer ID for node $i: ${peer_ids[$i]}"

        # Remove existing bootstrap peers
        sed -i '/bootstrapPeers:/,/^  listenMultiaddr:/!b;/^  listenMultiaddr:/!d;/^  listenMultiaddr:/s/^/  bootstrapPeers:\n/' $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml

        # Update listen address
        sed -i "s|^  listenMultiaddr: /ip4/0.0.0.0/udp/8336/quic-v1|  listenMultiaddr: /ip4/127.0.0.1/tcp/833$i|" $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml
        # Calculate the starting dataworker port for this node
        START_PORT=$((40000 + (i - 1) * CORES_PER_NODE))
        
        # Remove the default empty array for dataWorkerMultiaddrs
        sed -i 's/^  dataWorkerMultiaddrs: \[\]/  dataWorkerMultiaddrs:/' $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml
        
        # Add dataWorkerMultiaddrs for each worker
        for j in $(seq 1 $((CORES_PER_NODE - 1))); do
            sed -i '/^  dataWorkerMultiaddrs:/a\    - /ip4/127.0.0.1/tcp/'"$((START_PORT + j))" $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml
        done
    done

    # Step 2: Update bootstrap peers
    for i in $(seq 1 $NODE_COUNT); do
        if [[ $i -eq 1 ]]; then
            CONFIG_SUFFIX=""
        else
            CONFIG_SUFFIX="$i"
        fi
        
        # Add all other nodes as bootstrap peers
        for j in $(seq 1 $NODE_COUNT); do
            if [ $i -ne $j ]; then
                sed -i '/bootstrapPeers:/a\  - /ip4/127.0.0.1/tcp/833'"$j"'/p2p/'"${peer_ids[$j]}" $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml
            fi
        done

        # Set log file for each node
        if [[ $i -eq 1 ]]; then
            sed -i 's|logFile:.*|logFile: "output.log"|' $PROJECT_DIR/node/.config/config.yml
        else
            sed -i 's|logFile:.*|logFile: "output'"$i"'.log"|' $PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml
        fi
    done

    # Expose REST and gRPC ports on main node to access RPC services
    sed -i 's|listenRESTMultiaddr:.*|listenRESTMultiaddr: /ip4/127.0.0.1/tcp/8335|' $PROJECT_DIR/node/.config/config.yml
    sed -i 's|listenGrpcMultiaddr:.*|listenGrpcMultiaddr: /ip4/127.0.0.1/tcp/8337|' $PROJECT_DIR/node/.config/config.yml
    

    echo "Configuration setup complete."
}

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to start nodes
start_nodes() {
    cd $PROJECT_DIR/node
    
    for i in $(seq 1 $NODE_COUNT); do
        core_index=0

        if [[ $i -eq 1 ]]; then
            CONFIG_SUFFIX=""
        else
            CONFIG_SUFFIX="$i"
        fi

        # Start the main process
        echo -e "${YELLOW}Starting main process for node $i${NC}"
        MAIN_CMD="$PROJECT_DIR/node/node --signature-check=false --network=1 --config=.config$CONFIG_SUFFIX --core=$core_index"
        echo -e "${YELLOW}Command: $MAIN_CMD${NC}"
        if [ "$DRY_RUN" = false ]; then
            $MAIN_CMD 2>&1 | sed "s/^/[NODE $i] /" &
            node_pid=$!
            echo -e "${GREEN}Node $i started with PID $node_pid${NC}"
            core_index=$((core_index + 1))
        else
            echo -e "${YELLOW}[DRY RUN] Would execute: $MAIN_CMD${NC}"
            core_index=$((core_index + 1))
        fi
        
        # Start worker processes
        for j in $(seq 1 $((CORES_PER_NODE - 1))); do
            echo -e "${YELLOW}Starting worker process $j for node $i${NC}"
            WORKER_CMD="$PROJECT_DIR/node/node --signature-check=false --network=1 --config=.config$CONFIG_SUFFIX --parent-process=$node_pid --core=$core_index"
            echo -e "${YELLOW}Command: $WORKER_CMD${NC}"
            if [ "$DRY_RUN" = false ]; then
                $WORKER_CMD 2>&1 | sed "s/^/[NODE $i WORKER $j] /" &
                worker_pid=$!
                echo -e "${GREEN}Node $i Worker $j started with PID $worker_pid${NC}"
                core_index=$((core_index + 1))
            else
                echo -e "${YELLOW}[DRY RUN] Would execute: $WORKER_CMD${NC}"
                core_index=$((core_index + 1))
            fi
        done

        # Apply CPU limit to the entire process group
        if [ "$DRY_RUN" = false ]; then
            cpulimit -p $node_pid -l $CPU_LIMIT_PERCENT &
            echo -e "${GREEN}CPU limit applied to Node $i (PID $node_pid)${NC}"
        else
            echo -e "${YELLOW}[DRY RUN] Would execute: cpulimit -p $node_pid -l $CPU_LIMIT_PERCENT${NC}"
        fi
    done
    if [ "$DRY_RUN" = false ]; then
        echo -e "${GREEN}Local testnet started. $NODE_COUNT nodes are running in the background, each with $CORES_PER_NODE cores (1 main + $((CORES_PER_NODE - 1)) workers) and limited to $CPU_LIMIT_PERCENT% CPU usage.${NC}"
    else
        echo -e "${YELLOW}Dry run completed. No nodes were started.${NC}"
    fi
}

# Function to stop nodes
stop_nodes() {
    echo "Stopping all nodes..."
    pkill -f "$PROJECT_DIR/node/node"
    echo "All nodes stopped."
}

# Function to handle timeout
handle_timeout() {
    echo "Timeout reached. Stopping all nodes..."
    cleanup
    exit 0
}

# Function to clean up on exit
cleanup() {
    # Cancel timeout if it's still active
    if [ -n "$TIMEOUT_PID" ]; then
        kill $TIMEOUT_PID 2>/dev/null
    fi
    stop_nodes
    exit
}

# Parse command line arguments
RECOMPILE_LIBS=false
REINSTALL_DEPS=false
REDO_CONFIG=false
NODE_COUNT_SET=false
CORES_PER_NODE_SET=false
CPU_LIMIT_SET=false
TIMEOUT=""
DRY_RUN=false
parse_arguments "$@"

# If no parameters are set, inform about defaults and ask for confirmation
if [ "$NODE_COUNT_SET" = false ] && [ "$CORES_PER_NODE_SET" = false ] && [ "$CPU_LIMIT_SET" = false ]; then
    echo "Default configuration:"
    echo "  Number of nodes: $NODE_COUNT"
    echo "  Cores per node: $CORES_PER_NODE"
    echo "  CPU limit per node: ${CPU_LIMIT_PERCENT}%"
    echo ""
    read -p "Do you want to use these default values? (y/n) [y]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        recommend_resources
    fi
else
    # If any parameter is set, use recommend_resources to fill in the blanks
    if [ "$NODE_COUNT_SET" = false ] || [ "$CPU_LIMIT_SET" = false ] || [ "$CORES_PER_NODE_SET" = false ]; then
        echo "Using default values for unspecified parameters:"
        [ "$NODE_COUNT_SET" = false ] && echo "  Number of nodes: $NODE_COUNT"
        [ "$CORES_PER_NODE_SET" = false ] && echo "  Cores per node: $CORES_PER_NODE"
        [ "$CPU_LIMIT_SET" = false ] && echo "  CPU limit per node: ${CPU_LIMIT_PERCENT}%"
        echo ""
        read -p "Do you want to continue with these values? (y/n) [y]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            recommend_resources
        fi
    fi
fi

# Check available resources
check_resources

# Check if dependencies are installed or if reinstallation is requested
if ! command -v rustc &> /dev/null || ! command -v go &> /dev/null || $REINSTALL_DEPS; then
    echo "Installing dependencies..."
    ./install_dependencies.sh
else
    echo "Dependencies already installed. Skipping installation."
fi

# Check if the node binary exists or if recompilation is requested
if [[ ! -f "$PROJECT_DIR/node/node" ]] || $RECOMPILE_LIBS; then
    echo "Node binary not found or recompilation requested. Compiling libraries..."
    compile_libs
else
    echo "Node binary found. Skipping library compilation."
fi

# Check if config files exist, if recompilation is requested, or if redo config is requested
config_files_exist=true
for i in $(seq 1 $NODE_COUNT); do
    if [[ $i -eq 1 ]]; then
        CONFIG_SUFFIX=""
    else
        CONFIG_SUFFIX="$i"
    fi
    if [[ ! -f "$PROJECT_DIR/node/.config$CONFIG_SUFFIX/config.yml" ]]; then
        config_files_exist=false
        break
    fi
done

if [[ $config_files_exist == false ]] || $REDO_CONFIG; then
    echo "Setting up configuration..."
    setup_config
else
    echo "All config files found and no redo requested. Skipping configuration setup."
fi

echo "Setup complete. You can now run the start_nodes function to start the testnet."

# Set up trap to catch termination signals
trap cleanup SIGINT SIGTERM SIGHUP

# Start nodes
start_nodes

echo "Press Ctrl+C to stop all nodes..."

# Set up timeout if specified
if [ -n "$TIMEOUT" ]; then
    echo "Testnet will automatically stop after $TIMEOUT seconds."
    (sleep $TIMEOUT && handle_timeout) &
    TIMEOUT_PID=$!
fi

# Set up trap to catch termination signals and cancel timeout
trap 'cleanup; [ -n "$TIMEOUT_PID" ] && kill $TIMEOUT_PID 2>/dev/null' SIGINT SIGTERM SIGHUP

# Wait indefinitely
while true; do
    sleep 1
done