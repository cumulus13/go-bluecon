// File: main.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-01-17
// Description: Bluetooth connection manager written in Go, designed to manage Bluetooth devices both locally and remotely via SSH.
// License: MIT

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/faiface/beep"
	"github.com/faiface/beep/mp3"
	"github.com/faiface/beep/speaker"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	log     *logrus.Logger
	version string
	author  = "Hadi Cahyadi <cumulus13@gmail.com>"
)

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
	
	// Read version from VERSION file
	version = readVersionFile()
}

// readVersionFile reads version from VERSION file
func readVersionFile() string {
	defaultVersion := "1.0.0"
	
	// Get executable directory
	exePath, err := os.Executable()
	var versionFile string
	
	if err == nil {
		exeDir := filepath.Dir(exePath)
		versionFile = filepath.Join(exeDir, "VERSION")
	}
	
	// Try reading from executable directory
	data, err := os.ReadFile(versionFile)
	if err != nil {
		// Try reading from current directory
		data, err = os.ReadFile("VERSION")
		if err != nil {
			log.Debug("VERSION file not found, using default")
			return defaultVersion
		}
	}
	
	// Parse file content
	content := string(data)
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(parts[1], "\"' \n\r\t")
				
				if strings.ToLower(key) == "version" {
					return value
				}
			}
		}
	}
	
	return defaultVersion
}

// DeviceInfo represents parsed Bluetooth device information
type DeviceInfo struct {
	MAC         string            `json:"mac"`
	AddressType string            `json:"address_type,omitempty"`
	Name        string            `json:"name,omitempty"`
	Alias       string            `json:"alias,omitempty"`
	Paired      bool              `json:"paired"`
	Trusted     bool              `json:"trusted"`
	Blocked     bool              `json:"blocked"`
	Connected   bool              `json:"connected"`
	UUIDs       []UUID            `json:"uuids,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// UUID represents a Bluetooth service UUID
type UUID struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SSHConfig holds SSH connection configuration
type SSHConfig struct {
	Hostname string
	Username string
	KeyFile  string
	Port     int
	Timeout  time.Duration
}

// SSHClient manages SSH connections
type SSHClient struct {
	config *SSHConfig
	client *ssh.Client
}

// NewSSHClient creates a new SSH client instance
func NewSSHClient(config *SSHConfig) *SSHClient {
	return &SSHClient{
		config: config,
	}
}

// ConnectWithKeyFile establishes SSH connection using private key file
func (s *SSHClient) ConnectWithKeyFile() error {
	log.WithFields(logrus.Fields{
		"hostname": s.config.Hostname,
		"port":     s.config.Port,
		"username": s.config.Username,
		"key_file": s.config.KeyFile,
	}).Debug("Attempting SSH connection")

	// Read private key
	key, err := os.ReadFile(s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %w", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: s.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.config.Timeout,
	}

	// Connect
	addr := fmt.Sprintf("%s:%d", s.config.Hostname, s.config.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	s.client = client
	log.Infof("✓ Connected to %s:%d", s.config.Hostname, s.config.Port)
	return nil
}

// RunCommand executes a single command on the remote host
func (s *SSHClient) RunCommand(command string) (string, string, error) {
	if s.client == nil {
		return "", "", fmt.Errorf("SSH client not connected")
	}

	session, err := s.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	log.Debugf("Executing command: %s", command)
	err = session.Run(command)

	return stdout.String(), stderr.String(), err
}

// Close closes the SSH connection
func (s *SSHClient) Close() error {
	if s.client != nil {
		log.Debug("Closing SSH connection")
		return s.client.Close()
	}
	return nil
}

// Parser handles bluetoothctl output parsing
type Parser struct{}

// ParseBluetoothctlOutput parses bluetoothctl device info output
func (p *Parser) ParseBluetoothctlOutput(output string) *DeviceInfo {
	if strings.TrimSpace(output) == "" {
		return &DeviceInfo{Properties: make(map[string]string)}
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	info := &DeviceInfo{
		Properties: make(map[string]string),
	}

	// Parse first line for device MAC and address type
	deviceRegex := regexp.MustCompile(`^\s*Device\s+([\w:]+)\s*(?:\((\w+)\))?`)
	if match := deviceRegex.FindStringSubmatch(lines[0]); match != nil {
		info.MAC = match[1]
		if len(match) > 2 && match[2] != "" {
			info.AddressType = match[2]
		}
	}

	var uuids []UUID

	// Parse remaining lines
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse UUIDs
		if strings.HasPrefix(line, "UUID:") {
			uuidRegex := regexp.MustCompile(`UUID:\s+(.+?)\s+\(([\w-]+)\)`)
			if match := uuidRegex.FindStringSubmatch(line); match != nil {
				uuids = append(uuids, UUID{
					Name:  strings.TrimSpace(match[1]),
					Value: match[2],
				})
			}
			continue
		}

		// Parse key-value pairs
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Handle specific known fields
				switch key {
				case "Name":
					info.Name = value
				case "Alias":
					info.Alias = value
				case "Paired":
					info.Paired = strings.ToLower(value) == "yes"
				case "Trusted":
					info.Trusted = strings.ToLower(value) == "yes"
				case "Blocked":
					info.Blocked = strings.ToLower(value) == "yes"
				case "Connected":
					info.Connected = strings.ToLower(value) == "yes"
				default:
					info.Properties[key] = value
				}
			}
		}
	}

	if len(uuids) > 0 {
		info.UUIDs = uuids
	}

	return info
}

// Remote handles remote Bluetooth operations
type Remote struct {
	sshConfig *SSHConfig
}

// NewRemote creates a new Remote instance
func NewRemote(hostname, username, keyFile string, port int) *Remote {
	return &Remote{
		sshConfig: &SSHConfig{
			Hostname: hostname,
			Username: username,
			KeyFile:  keyFile,
			Port:     port,
			Timeout:  10 * time.Second,
		},
	}
}

// List lists Bluetooth devices on remote host
func (r *Remote) List() error {
	client := NewSSHClient(r.sshConfig)
	if err := client.ConnectWithKeyFile(); err != nil {
		return err
	}
	defer client.Close()

	commands := []string{
		"select 10:08:B1:B3:29:A2",
		"devices",
	}

	parser := &Parser{}
	success := false

	// Execute each command separately like Python version
	for _, cmd := range commands {
		fullCmd := fmt.Sprintf("bluetoothctl %s", cmd)
		log.Debugf("Executing: %s", fullCmd)
		
		stdout, stderr, err := client.RunCommand(fullCmd)
		
		if stdout != "" {
			fmt.Printf("bluecon: %s", stdout)
			
			// Try to parse if it contains device info
			if strings.Contains(stdout, "Device") {
				deviceInfo := parser.ParseBluetoothctlOutput(stdout)
				if deviceInfo.MAC != "" {
					log.WithField("device_info", deviceInfo).Info("Device information")
					success = true
				}
			}
		}
		
		if stderr != "" {
			log.Error(stderr)
		}
		
		if err != nil {
			log.Debugf("Command error: %v", err)
		}
		
		// Small delay between commands
		time.Sleep(100 * time.Millisecond)
	}

	if success {
		playSound()
	}

	return nil
}

// Connect connects to Bluetooth device on remote host
func (r *Remote) Connect() error {
	client := NewSSHClient(r.sshConfig)
	if err := client.ConnectWithKeyFile(); err != nil {
		return err
	}
	defer client.Close()

	commands := []string{
		"select 10:08:B1:B3:29:A2",
		"power on",
		"pairable on",
		"agent on",
		"default-agent",
		"connect F4:4E:FD:20:4C:A6",
		"info F4:4E:FD:20:4C:A6",
		"exit",
	}

	parser := &Parser{}
	success := false

	// Execute each command separately like Python version
	for _, cmd := range commands {
		fullCmd := fmt.Sprintf("bluetoothctl %s", cmd)
		log.Debugf("Executing: %s", fullCmd)
		
		stdout, stderr, err := client.RunCommand(fullCmd)
		
		// Check for success indicators
		if strings.Contains(stdout, "Connected: yes") || 
		   strings.Contains(stdout, "Connection successful") {
			success = true
			log.Info("✓ Device connected successfully")
		}
		
		if stdout != "" {
			fmt.Printf("bluecon: %s", stdout)
			
			// Try to parse device info from info command
			if cmd == "info F4:4E:FD:20:4C:A6" {
				deviceInfo := parser.ParseBluetoothctlOutput(stdout)
				if deviceInfo.MAC != "" {
					log.WithField("device_info", deviceInfo).Debug("Device information")
				}
			}
		}
		
		if stderr != "" {
			log.Error(stderr)
		}
		
		if err != nil {
			log.Debugf("Command error: %v", err)
		}
		
		// Small delay between commands
		time.Sleep(100 * time.Millisecond)
	}

	if success {
		playSound()
	}

	return nil
}

// BlueCon handles local Bluetooth operations
type BlueCon struct{}

// RunLocal executes local bluetoothctl commands
func (b *BlueCon) RunLocal() error {
	commands := []string{
		"select 10:08:B1:B3:29:A2",
		"power on",
		"pairable on",
		"agent on",
		"default-agent",
		"connect F4:4E:FD:20:4C:A6",
		"info F4:4E:FD:20:4C:A6",
		"exit",
	}

	var cmd *exec.Cmd

	// Detect OS and use appropriate method
	if runtime.GOOS == "windows" {
		// Windows: Direct bluetoothctl with stdin
		cmd = exec.Command("bluetoothctl")
	} else {
		// Linux/Unix/macOS: use sh with echo pipe
		commandStr := strings.Join(commands, "\\n")
		cmdStr := fmt.Sprintf("echo -e '%s' | bluetoothctl", commandStr)
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start bluetoothctl: %w", err)
	}

	// Send commands via stdin (for Windows and as fallback)
	go func() {
		defer stdin.Close()
		for _, command := range commands {
			fmt.Printf("→ %s\n", command)
			fmt.Fprintf(stdin, "%s\n", command)
			time.Sleep(300 * time.Millisecond)
		}
	}()

	// Read stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	// Read stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Error(scanner.Text())
		}
	}()

	return cmd.Wait()
}

// playSound plays notification sound if available
func playSound() {
	soundFile := filepath.Join(filepath.Dir(os.Args[0]), "connected.mp3")

	if _, err := os.Stat(soundFile); os.IsNotExist(err) {
		log.Debug("Sound file not found, skipping notification")
		return
	}

	go func() {
		f, err := os.Open(soundFile)
		if err != nil {
			log.Debugf("Could not open sound file: %v", err)
			return
		}
		defer f.Close()

		streamer, format, err := mp3.Decode(f)
		if err != nil {
			log.Debugf("Could not decode mp3: %v", err)
			return
		}
		defer streamer.Close()

		speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))
		done := make(chan bool)
		speaker.Play(beep.Seq(streamer, beep.Callback(func() {
			done <- true
		})))

		<-done
		log.Debug("Played notification sound")
	}()
}

func main() {
	// Get default SSH key path based on OS
	var defaultKeyPath string
	if runtime.GOOS == "windows" {
		// Windows: Check common locations
		if msysHome := os.Getenv("MSYS2_HOME"); msysHome != "" {
			defaultKeyPath = filepath.Join(msysHome, "home", os.Getenv("USERNAME"), ".ssh", "id_rsa")
		} else if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
			defaultKeyPath = filepath.Join(userProfile, ".ssh", "id_rsa")
		} else {
			defaultKeyPath = `C:\msys64\home\LICFACE\.ssh\id_rsa`
		}
	} else {
		defaultKeyPath = filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
	}

	// Command line flags
	var (
		remote   = flag.Bool("remote", false, "Execute remotely via SSH")
		listOnly = flag.Bool("list", false, "List devices instead of connecting")
		hostname = flag.String("hostname", "222.222.222.5", "Remote SSH hostname")
		username = flag.String("username", "root", "Remote SSH username")
		port     = flag.Int("port", 22, "Remote SSH port")
		keyFile  = flag.String("key", defaultKeyPath, "SSH key file full path")
		debug    = flag.Bool("debug", false, "Enable debug mode")
		showVer  = flag.Bool("version", false, "Show version")
	)

	flag.Parse()

	// Show version
	if *showVer {
		fmt.Printf("BlueCon v%s by %s\n", version, author)
		os.Exit(0)
	}

	// Set log level
	if *debug {
		log.SetLevel(logrus.DebugLevel)
		log.Debug("🐞 Debug mode enabled")
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\nOperation cancelled by user")
		os.Exit(130)
	}()

	// Execute based on flags
	var err error

	if *remote {
		r := NewRemote(*hostname, *username, *keyFile, *port)
		if *listOnly {
			err = r.List()
		} else {
			err = r.Connect()
		}
	} else {
		if *listOnly {
			fmt.Println("Local list not implemented. Use: bluetoothctl devices")
		} else {
			// If no arguments, show help and run local
			if len(os.Args) == 1 {
				flag.PrintDefaults()
				fmt.Println("\n[Running local Bluetooth connection...]")
			}
			bc := &BlueCon{}
			err = bc.RunLocal()
		}
	}

	if err != nil {
		log.Errorf("Error: %v", err)
		os.Exit(1)
	}
}