FROM mcr.microsoft.com/devcontainers/go:1-1.25-bookworm

# Node 20 for Wails frontend
ARG NODE_VERSION=20
RUN su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} && nvm alias default ${NODE_VERSION}" 2>/dev/null || (curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs)

# Wails v2 Linux deps (WebKitGTK) + common tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    pkg-config \
    upx-ucl \
    nsis \
    && rm -rf /var/lib/apt/lists/*

# Wails CLI
RUN su vscode -c "go install github.com/wailsapp/wails/v2/cmd/wails@latest" || go install github.com/wailsapp/wails/v2/cmd/wails@latest
ENV PATH="${PATH}:/go/bin:/home/vscode/go/bin"
