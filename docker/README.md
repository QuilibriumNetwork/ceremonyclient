# Quilibrium Docker Instructions

## WARNING

> [!WARNING]
> The Quilibrium docker container requires host configuration changes.

There are extreme buffering requirements, especially during sync, and these in turn require `sysctl`
configuration changes that unfortunately are not supported by Docker. But if these changes are made on
the host machine, then luckily containers seem to automatically have the larger buffers.

The buffer related `sysctl` settings are `net.core.rmem_max` and `net.core.wmem_max` and they both
should be set to `600,000,000` bytes. This value allows pre-buffering of the entire maximum payload
for sync.

You can tell that the buffer size is not large enough by noticing this log entry at beginning when 
Quilibrium starts, a few lines below the large logo:
> failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 2048 kiB, got: 416 kiB).
> See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.

To read the currently set values:
```shell
sysctl -n net.core.rmem_max
sysctl -n net.core.wmem_max
```

To set new values, this is not a persistent change:
```shell
sudo sysctl -w net.core.rmem_max=600000000
sudo sysctl -w net.core.wmem_max=600000000
```

To persistently set the new values add a configuration file named `20-quilibrium.conf` to
`/etc/sysctl.d/`. The file content should be:
```
# Quilibrium buffering requirements, especially during sync.
# The value could be as low as 26214400, but everything would be slower.

net.core.rmem_max = 600000000
net.core.wmem_max = 600000000
```

## Run

Copy [docker-compose.yml](docker-compose.yml) to a new folder on a server. The official
Docker image provided by Quilibrium Network will be pulled.

A `.config/` subfolder will be created in this folder, this will hold both configuration
and the node storage.

### New Instance

If you are starting a brand new node then simply run Quilibrium in a container:
```shell
docker compose up -d
```

> [!TIP]
> You can alternatively use the `task up` command. See the [Task](#task-1) section above.

A `.config/` subfolder will be created under the current folder, this is mapped inside the container.

> [!IMPORTANT]
> Once the node is running make sure you backup `config.yml` and `keys.yml`.

### Restore Previous Instance

If you have both `config.yml` and `keys.yml` backed up from a previous instance then follow these steps to
restore them:

1. Create an empty `.config/` subfolder.
2. Copy `config.yml` and `keys.yml` to `.config/`. 
3. Start the node:
   ```shell
   docker compose up -d
   ```

### Task

Similarly to building the image you can also use `Task`.

Start the container through docker compose:
```shell
task up
```

Show the logs through docker compose:
```shell
task logs
```

Drop into a shell inside the running container:
```shell
task shell
```

Stop the running container(s):
```shell
task down
```

Backup the critical configuration:
```shell
task backup
```

The above command will create a `backup.tar.gz` archive in the current folder, you still have to copy this
file from the server into a safe location. The command adds the `config.yml` and `keys.yml` files from
the `.config/` subfolder to the archive, with the ownership of the current user.

### Resource management
To ensure that your client performs optimally within a specific resource configuration, you can specify
resource limits and reservations in the node configuration as illustrated below. 

This configuration helps in deploying the client with controlled resource usage, such as CPU and memory,
to avoid overconsumption of resources in your environment.

The [docker-compose.yml](docker-compose.yml) file already specifies resources following the currently
recommended hardware requirements.

```yaml
services:
  node:
    # Some other configuration sections here
    deploy:
      resources:
        limits:
          cpus: '4'  # Maximum CPU count that the container can use
          memory: '16G'  # Maximum memory that the container can use
        reservations:
          cpus: '2'  # CPU count that the container initially requests
          memory: '8G'  # Memory that the container initially request
```


### Customizing docker-compose.yml

If you want to change certain parameters in [docker-compose.yml](docker-compose.yml) it is better not
to edit the file directly as new versions pushed through git would overwrite your changes. A more
flexible solution is to create another file called `docker-compose.override.yml` right next to it
and specifying the necessary overriding changes there.

For example:
```yaml
services:
  node:
    image: ghcr.io/mscurtescu/ceremonyclient
    restart: on-failure:7
```

The above will override the image name and also the restart policy.

To check if your overrides are being picked up run the following command:
```shell
docker compose config
```

This will output the merged and canonical compose file that will be used to run the container(s).


## Interact with a running container

Drop into a shell inside a running container:
```shell
docker compose exec -it node sh
```

Watch the logs:
```shell
docker compose logs -f
```

Get the node related info (peer id, version, max frame and balance):
```shell
docker compose exec node node -node-info
```

Run the DB console:
```shell
docker compose exec node node -db-console
```

Run the Quilibrium client:
```shell
docker compose exec node qclient help
docker compose exec node qclient token help
docker compose exec node qclient token balance
```