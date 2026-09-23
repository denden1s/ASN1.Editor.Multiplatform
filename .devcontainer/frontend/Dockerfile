FROM mcr.microsoft.com/devcontainers/javascript-node:1-20-bookworm

# Frontend tooling for the Wails React UI (tree / hex / tabs / cert-view).
# System Chrome is intentionally NOT installed: Wails renders via the host
# WebView (WebView2/WKWebView/WebKitGTK), so `wails dev`/`wails build`
# for desktop targets still run on the host or in the backend container.
RUN npm i -g typescript@5
