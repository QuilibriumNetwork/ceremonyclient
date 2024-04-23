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


## Build

The only requirements are `git` (to checkout the repository) and docker (to build the image and run the container).
Golang does not have to be installed, the docker image build process uses a build stage that provides the
correct Go environment and compiles the node down to one command.

In the repository root folder, where the [Dockerfile](Dockerfile) file is, build the docker image:
```shell
docker build --build-arg GIT_COMMIT=$(git log -1 --format=%h) -t quilibrium -t quilibrium:1.4.2 .
```

Use latest version instead of `1.4.2`.

> [!TIP]
> You can use the `task build` command instead. See the [Task](#task) section below.

The image that is built is light and safe. It is based on Alpine Linux with the Quilibrium node binary, not the
source code, nor the Go development environment. The image also has the `grpcurl` tool that can be used to
query the gRPC interface.

### Task

You can also use the [Task](https://taskfile.dev/) tool, it a simple build tool that takes care of extracting
parameters, building the image and running the container. The tasks are all defined in [Taskfile.yaml](Taskfile.yaml).

You can optionally create an `.env` file, in the same repository root folder to override specific parameters. Right now
only one optional env var is supported and that is `QUILIBRIUM_IMAGE_NAME`, if you want to change the default
image name from `quilibrium` to something else. If you are pushing your images to Github then you have to follow the
Github naming convention and use a name like `ghcr.io/mscurtescu/ceremonyclient`.

Bellow there are example interaction with `Task`.

The node version is extracted from [node/main.go](node/main.go). This version string is used to tag the image. The git
repo, branch and commit are read throught the `git` command and depend on the current state of your working
directory (one what branch and at what commit you are). These last three values are used to label the image.

List tasks:
```shell
task -l
```

Show what parameters, like image name, version etc, will be used:
```shell
task status
```

Build the image (aka run the `build` task):
```shell
task build
```

## Run

You can run Quilibrium on the same machine where you built the image, from the same repository root
folder where [docker-compose.yml](docker-compose.yml) is.

You can also copy `docker-compose.yml` to a new folder on a server and run it there. In this case you
have to have a way to push your image to a Docker image repo and then pull that image on the server.
Github offers such an image repo and a way to push and pull images using special authentication
tokens. See
[Working with the Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

Run Quilibrium in a container:
```shell
docker compose up -d
```

> [!TIP]
> You can alternatively use the `task up` command. See the [Task](#task-1) section above.

A `.config/` subfolder will be created under the current folder, this is mapped inside the container.
Make sure you backup `config.yml` and `keys.yml`.

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