# Sublime Text Packages

This repository contains custom Sublime Text packages.

## Available Packages

### Kubeseal
Encrypt/decrypt strings with kubeseal for Kubernetes sealed secrets.

### Kubeapply
Apply the open Kubernetes YAML via `kubectl`, with context quick-panel, namespace prompts, dry-run, diff, and overwrite confirmations.

## Installation

### Using Package Control (Recommended)

1. **Install Package Control** (if not already installed):
   - Open Sublime Text
   - Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
   - Type "Install Package Control" and press Enter

2. **Add this repository**:
   - Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
   - Type "Package Control: Add Repository" and press Enter
   - Enter: `https://raw.githubusercontent.com/dspasic12/sublime-text-packages/main/repository.json`

3. **Install the package**:
   - Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
   - Type "Package Control: Install Package" and press Enter
   - Search for "Kubeseal" or "Kubeapply" and select it

### Manual Installation

1. Download the latest release from the [Releases page](https://github.com/dspasic12/sublime-text-packages/releases)
2. Extract the ZIP file
3. Copy the package folder (`Kubeseal` or `kubeapply`) to your Sublime Text `Packages` directory:

   | Platform | Path |
   |----------|------|
   | **Windows** | `%APPDATA%\Sublime Text\Packages\` |
   | **Mac** | `~/Library/Application Support/Sublime Text/Packages/` |
   | **Linux** | `~/.config/sublime-text/Packages/` |

4. Restart Sublime Text

**Dev symlink (optional)** — point Packages at a local checkout:

```bash
ln -s "/path/to/sublime-text-packages/kubeapply" \
  "$HOME/Library/Application Support/Sublime Text/Packages/kubeapply"
```

## Usage

### Kubeseal Package

After installation, you can access Kubeseal commands via:

#### Command Palette
Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac), then type:
- `Kubeseal: Encrypt String`
- `Kubeseal: Decrypt String`

#### Menu
Go to **Tools → Kubeseal** and select your desired action

### Kubeapply Package

1. Open a Kubernetes YAML file
2. `Cmd+Shift+P` → **Kubeapply: Apply Open File**
3. Pick a **context** from the quick panel
4. If a namespaced kind has no `metadata.namespace`, pick a namespace
5. Review dry-run / diff / CREATE-vs-UPDATE confirmations before apply

Also available: **Dry-Run Open File**, **Diff Open File**.

## Requirements

- Sublime Text 3 or higher (Kubeapply targets Sublime Text 4)
- `kubeseal` binary on PATH (Kubeseal package)
- `kubectl` binary on PATH (Kubeapply package)

## Issues

Report issues at: [GitHub Issues](https://github.com/dspasic12/sublime-text-packages/issues)

## License

[Add your license information here]
