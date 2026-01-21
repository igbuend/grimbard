#!/usr/bin/env bash
export SHELL="/bin/bash"
export DOTNET_CLI_TELEMETRY_OPTOUT="1"
export HOMEBREW_NO_ANALYTICS=1
export GRIMBARD_HOME="$PWD"
export USERNAME=grimbard
export USER_UID=""
USER_UID=$(id -u)
export USER_GID=""
USER_GID=$(id -g)

echo "" | sudo tee -a /etc/hosts > /dev/null
echo "127.0.1.1 malpertus" | sudo tee -a /etc/hosts > /dev/null

sudo chown -R "$(whoami)":"$(whoami)" "$GRIMBARD_HOME"

# start docker
sudo service docker start

sudo apt update

touch "$HOME"/.bashrc
mkdir -p "$HOME"/.npm-global
#shellcheck disable=SC2016
npm config set prefix '$HOME/.npm-global'
#shellcheck disable=SC2016
echo 'export PATH=$HOME/.npm-global/bin:$PATH' >> ~/.bashrc
pnpm setup
export PNPM_HOME="$HOME/.local/share/pnpm"

#shellcheck disable=SC1090,SC1091
source "$HOME"/.bashrc
case ":$PATH:" in
  *":$PNPM_HOME:"*) ;;
  *) export PATH="$PNPM_HOME:$PATH" ;;
esac

npm install -g @anthropic-ai/claude-code

# sarif-tools and strix-agent
pipx install sarif-tools -qq && pipx ensurepath

# gemini-cli
# pnpm add -g @google/gemini-cli

sudo chown -R "$(whoami)":"$(whoami)" "$HOME"/.local

if [[ -d ".git" ]]; then
  git config --global --add safe.directory .
  pre-commit install
fi

exit 0