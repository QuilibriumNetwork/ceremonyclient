# Quilibrium Docker Instructions

## Install Docker on a Server

> [!IMPORTANT]
> You have to install Docker Engine on your server, you don't want to install Docker Desktop.

The official Linux installation instructions start here:  
https://docs.docker.com/engine/install/

For Ubuntu you can start here:  
https://docs.docker.com/engine/install/ubuntu/

While there are several installation methods, you really want to use the apt repository, this way you get
automatic updates.

Make sure you also follow the Linux post-installation steps:  
https://docs.docker.com/engine/install/linux-postinstall/

## Install Docker on a Desktop

For a Linux desktop follow the server installation steps above, do not install Docker Desktop for Linux unless
you know what you are doing.

For Mac and Windows follow the corresponding Docker Desktop installation links from the top of:  
https://docs.docker.com/engine/install/

## Running a Node

Copy [docker-compose.yml](docker-compose.yml) to a new folder on a server. The official
Docker image provided by Quilibrium Network will be pulled.

A `.config/` subfolder will be created in this folder, this will hold both configuration
and the node storage.

Optionally you can also copy [Taskfile.yaml](Taskfile.yaml) and [.env.example](.env.example) to the
server, if you are planning to use them. See below.

### New Instance

If you are starting a brand new node then simply run Quilibrium in a container with:
```shell
docker compose up -d
```

A `.config/` subfolder will be created under the current folder, this is mapped inside the container.

> [!IMPORTANT]
> Once the node is running (the `-node-info` command shows a balance) make sure you backup
> `config.yml` and `keys.yml`.

### Restore Previous Instance

If you have both `config.yml` and `keys.yml` backed up from a previous instance then follow these
steps to restore them:

1. Create an empty `.config/` subfolder.
2. Copy `config.yml` and `keys.yml` to `.config/`. 
3. Start the node with:
   ```shell
   docker compose up -d
   ```

### Task

You can also use the [Task](https://taskfile.dev/) tool, it is a simple build tool that takes care of running
complex commands and intereacting with the container. The tasks are all defined in
[Taskfile.yaml](Taskfile.yaml).

You can optionally create an `.env` file, in the same folder to override specific parameters. Right now
only one optional env var is supported with `Task` and that is `QUILIBRIUM_IMAGE_NAME`, if you want to change the
default image name from `quilibrium` to something else. If you are pushing your images to GitHub, for example, then you
have to follow the GitHub naming convention and use a name like `ghcr.io/mscurtescu/ceremonyclient`. See the
[.env.example](.env.example) sample file, and keep in mind that `.env` is shared with
[docker-compose.yml](docker-compose.yml).

Bellow there are example interactions with `Task`.

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


## Customizing docker-compose.yml

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

You can optionally create an `.env` file, in the same folder to override specific parameters. See the
[.env.example](.env.example) sample file, and keep in mind that `.env` is shared with
[Taskfile.yaml](Taskfile.yaml). You can customize the image name and port mappings.

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
