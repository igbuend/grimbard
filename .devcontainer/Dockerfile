FROM mcr.microsoft.com/devcontainers/base:ubuntu
# It is relatively straightforward to change to Debian/Kali. Been there, done that, got the T-Shirt.
# Not going back, most 3rd party apps only support Ubuntu out of the box and my time is valuable.
ENV USER_UID=1689
ENV USER_GID=$USER_UID
# docker uses "sh" by default, we want bash, since we need some buildin commands which might not not be buildin with lesser shells.
SHELL ["/bin/bash", "-c"]
# Please refer to the README.md. Grimbard is the badger in the medieval fable of Reynard the Fox.
ENV USER_NAME=grimbard

# TODO move this to separate file and use awk/xargs (standard install for Ubuntu and others ??)
# xargs -a <(awk '! /^ *(#|$)/' "$packagelist") -r -- sudo apt-get -y install --no-install-recommends
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update && apt-get -y install --no-install-recommends \
      7zip \
      asciinema \
      bats \
      bc \
      build-essential \
      ca-certificates \
      cloc \
      coreutils \
      cron \
      curl \
      dialog \
      dirmngr \
      dnsutils \
      dos2unix \
      dotnet-sdk-8.0 \
      fuse-overlayfs \
      gawk \
      git \
      gnupg2 \
      golang \
      jq \
      just \
      lsb-release \
      locales \
      make \
      nano \
      net-tools \
      passt \
      pipx \
      pkg-config \
      pre-commit \
      python3 \
      python3-pip \
      python3-setuptools \
      python3-venv \
      ripgrep \
      slirp4netns \
      tar \
      shellcheck \
      sudo \
      tree \
      uidmap \
      unzip \
      wget \
      yq \
      zip

# Fixing locales. Do not remove, you will run into problems with certain distros/images.
RUN command -v locale-gen &>/dev/null && \
    locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8 \
    && export LANGUAGE=en_US.UTF-8 \
    && export LANG=en_US.UTF-8 \
    && export LC_ALL=en_US.UTF-8

# Install nodejs/npm/pnpm
RUN curl -fsSL https://deb.nodesource.com/setup_24.x -o nodesource_setup.sh \
    && bash ./nodesource_setup.sh \
    && rm -rf ./nodesource_setup.sh \
    && export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get -y install --no-install-recommends nodejs \
    && npm install -g pnpm

# Install gh
RUN (type -p wget >/dev/null || (sudo apt update && sudo apt install wget -y)) \
	&& sudo mkdir -p -m 755 /etc/apt/keyrings \
	&& out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
	&& cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& sudo mkdir -p -m 755 /etc/apt/sources.list.d \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
	&& sudo apt update \
	&& sudo apt install gh -y

# Create the user, add to docker group
RUN groupadd --non-unique --gid $USER_GID $USER_NAME \
    && useradd --uid $USER_UID --gid $USER_GID -c "Account created by grimbard" -s /usr/bin/bash -m $USER_NAME \
    && echo $USER_NAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USER_NAME \
    && chmod 0440 /etc/sudoers.d/$USER_NAME \
    && getent group docker &>/dev/null|| groupadd docker \
    && usermod -aG docker $USER_NAME

# Cleanup -> not really needed, since we install more apps in postCreateCommand.sh
# RUN rm -rf /var/lib/apt/lists/*

# Set the default user. Run whatever you need to install as non-root user after this line.
ENV HOME /home/$USER_NAME
USER $USER_NAME
WORKDIR $HOME
