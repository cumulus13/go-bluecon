# BlueCon - Bluetooth Connection Manager

Bluetooth connection manager written in Go, designed to manage Bluetooth devices both locally and remotely via SSH.

## Features

- 🔌 **Local Bluetooth Management** - Connect to Bluetooth devices on your local machine
- 🌐 **Remote SSH Control** - Manage Bluetooth devices on remote Linux hosts via SSH
- 🔐 **SSH Key Authentication** - Secure key-based authentication for remote connections
- 📊 **Structured Logging** - Clean, timestamped logs with different verbosity levels
- 🔔 **Audio Notifications** - Optional sound notification on successful connection
- 🎯 **Device Information Parsing** - Parse and display detailed Bluetooth device information
- ⚡ **Cross-Platform** - Works on Windows, Linux, and macOS

## Prerequisites

### For Local Use
- `bluetoothctl` installed (part of BlueZ package on Linux)
- Bluetooth hardware enabled

### For Remote Use
- SSH access to remote host
- RSA private key for authentication
- `bluetoothctl` installed on remote host

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/cumulus13/go-bluecon
cd go-bluecon

# Install dependencies
go get github.com/sirupsen/logrus
go get golang.org/x/crypto/ssh
go get github.com/faiface/beep
go get github.com/faiface/beep/mp3
go get github.com/faiface/beep/speaker

# Build
go build -o bluecon

# Optional: Build with optimizations
go build -ldflags="-s -w" -o bluecon
```

### Binary Release

Download the pre-built binary for your platform from the releases page.

## Usage

### Basic Commands

```bash
# Show help
bluecon -h

# Show version
bluecon -version

# Run local Bluetooth connection
bluecon

# Connect to remote device
bluecon -remote

# List remote devices
bluecon -remote -list

# Enable debug mode
bluecon -remote -debug
```

### Command Line Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-remote` | bool | false | Execute remotely via SSH |
| `-list` | bool | false | List devices instead of connecting |
| `-hostname` | string | 222.222.222.5 | Remote SSH hostname |
| `-username` | string | root | Remote SSH username |
| `-port` | int | 22 | Remote SSH port |
| `-key` | string | (auto-detected) | SSH private key file path |
| `-debug` | bool | false | Enable debug logging |
| `-version` | bool | false | Show version information |

### Examples

#### Remote Connection with Custom Settings

```bash
bluecon -remote \
  -hostname 192.168.1.100 \
  -username pi \
  -port 22 \
  -key ~/.ssh/id_rsa
```

#### List Remote Devices

```bash
bluecon -remote -list -debug
```

#### Windows with Custom Key Path

```bash
bluecon.exe -remote -key "C:\Users\YourUser\.ssh\id_rsa"
```

## Configuration

### Default Device Settings

The program is pre-configured with default Bluetooth adapter and device addresses. To modify these, edit the following in the source code:

```go
commands := []string{
    "select 10:08:B1:B3:29:A2",  // Bluetooth adapter MAC
    "power on",
    "pairable on",
    "agent on",
    "default-agent",
    "connect F4:4E:FD:20:4C:A6", // Device MAC to connect
    "info F4:4E:FD:20:4C:A6",
    "exit",
}
```

### SSH Key Path Detection

On Windows, the program attempts to find your SSH key in this order:

1. `%MSYS2_HOME%\home\%USERNAME%\.ssh\id_rsa`
2. `%USERPROFILE%\.ssh\id_rsa`
3. `C:\msys64\home\LICFACE\.ssh\id_rsa` (fallback)

On Linux/macOS:
- `~/.ssh/id_rsa`

You can always override with the `-key` flag.

## Audio Notifications

Place an MP3 file named `connected.mp3` in the same directory as the executable to enable audio notifications on successful connection.

## Architecture

### Key Components

- **SSHClient** - Manages SSH connections and remote command execution
- **Parser** - Parses bluetoothctl output into structured data
- **Remote** - Handles remote Bluetooth operations
- **BlueCon** - Handles local Bluetooth operations

### Data Structures

```go
type DeviceInfo struct {
    MAC         string
    AddressType string
    Name        string
    Alias       string
    Paired      bool
    Trusted     bool
    Blocked     bool
    Connected   bool
    UUIDs       []UUID
    Properties  map[string]string
}
```

## Troubleshooting

### "bluetoothctl not found"

Ensure BlueZ is installed:

```bash
# Debian/Ubuntu
sudo apt-get install bluez

# Fedora/RHEL
sudo dnf install bluez

# Arch Linux
sudo pacman -S bluez
```

### "unable to read private key"

Check that your SSH key exists and has correct permissions:

```bash
# Linux/macOS
ls -la ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa

# Windows
dir %USERPROFILE%\.ssh\id_rsa
```

### Connection Times Out

- Verify the remote host is reachable: `ping <hostname>`
- Check SSH access: `ssh -i <key> user@hostname`
- Ensure bluetoothctl is in PATH on remote host: `which bluetoothctl`

### Commands Not Executing

Enable debug mode to see detailed command execution:

```bash
bluecon -remote -debug
```

## Development

### Building for Different Platforms

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o bluecon-linux

# macOS
GOOS=darwin GOARCH=amd64 go build -o bluecon-macos

# Windows
GOOS=windows GOARCH=amd64 go build -o bluecon.exe

# ARM (e.g., Raspberry Pi)
GOOS=linux GOARCH=arm GOARM=7 go build -o bluecon-arm
```

## Security Considerations

- The current implementation uses `ssh.InsecureIgnoreHostKey()` for host key verification
- For production use, implement proper host key verification
- Keep your SSH private keys secure and never commit them to version control
- Use SSH key passphrases for additional security

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

---

**Note**: This tool directly interfaces with BlueZ's bluetoothctl. Ensure you have appropriate permissions to manage Bluetooth devices on your system.