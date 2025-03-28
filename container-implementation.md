# Container Implementation on Ubuntu 24.04

This document details the implementation of a basic container system using Go on Ubuntu 24.04. It covers process isolation, filesystem isolation, resource control, and networking, aligning with a task to create an isolated environment with security and resource management. Each section includes the relevant code from `main.go`.

## Prerequisites
- **Ubuntu 24.04**: Tested on this version.
- **Go**: Install with `sudo apt install golang-go`.
- **Root Privileges**: Required for namespace and network operations (`sudo`).
- **Minimal Root Filesystem**: A directory like `./alpine_fs` with a basic Alpine Linux filesystem (e.g., extracted from an Alpine minirootfs tarball).

## Setup
1. **Install Go**:
   ```bash
   sudo apt update
   sudo apt install golang-go
   go version  # Should show go1.22 or later
   ```
2. **Create Project**:
   ```bash
   mkdir ~/containers
   cd ~/containers
   touch main.go
   ```
3. **Prepare Root Filesystem**:
   - Download Alpine minirootfs: `wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.1-x86_64.tar.gz`
   - Extract: `tar -xzf alpine-minirootfs-3.19.1-x86_64.tar.gz -C ./alpine_fs`

## Implementation Breakdown

### Part 1: Isolated Environment

#### Process Isolation with Namespaces
- **PID Namespace**: Isolates process IDs so the container has its own PID 1.
- **User Namespace**: Maps container root (UID 0) to a non-root user on the host.
- **Network Namespace**: Provides a separate network stack.
- **Mount Namespace**: Isolates mount points.

**Code**:
```go
// In run() function
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | 
                syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
    Unshareflags: syscall.CLONE_NEWNS,
    UidMappings: []syscall.SysProcIDMap{
        {ContainerID: 0, HostID: os.Getuid(), Size: 1},
    },
    GidMappings: []syscall.SysProcIDMap{
        {ContainerID: 0, HostID: os.Getgid(), Size: 1},
    },
}
```

**Implementation**:
- Configured in `run()` to set up all necessary namespaces and user mappings when forking the child process.

#### Filesystem Isolation with Chroot
- **Minimal Root Filesystem**: Uses `./alpine_fs` as the container’s root.
- **Chroot**: Restricts filesystem access to `alpine_fs`.
- **Mount /proc**: Provides process information inside the container.

**Code**:
```go
// In child() function
must(syscall.Sethostname([]byte("container")))
must(syscall.Chroot(RootFS))
must(os.Chdir("/"))
must(os.MkdirAll("/etc", 0755))
must(setupDNS())
must(syscall.Mount("proc", "proc", "proc", 0, ""))
defer syscall.Unmount("proc", 0)
```

**Implementation**:
- In `child()`, sets a unique hostname, chroots to `alpine_fs`, changes to root directory, mounts `/proc`, and prepares `/etc` for DNS setup.

### Part 2: Resource & Security Management

#### Control Resource Usage with Cgroups
- **Process Limit**: Restricts the container to 10 processes.

**Code**:
```go
func cgPids() {
    cgroups := "/sys/fs/cgroup/"
    containerDir := filepath.Join(cgroups, "go_container/")
    os.Mkdir(containerDir, 0755)
    must(os.WriteFile(filepath.Join(containerDir, "pids.max"), []byte("10"), 0700))
    must(os.WriteFile(filepath.Join(containerDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0700))
}
```

**Implementation**:
- `cgPids()` creates a cgroup directory, limits processes to 10 via `pids.max`, and adds the current process to the cgroup.

#### Networking Isolation
- **Virtual Network Interface**: Creates a veth pair (`veth0` on host, `veth1` in container).
- **Host Network Isolation**: Ensures the container can’t access host interfaces.
- **Outbound Connectivity**: Configured via NAT.

**Code**:
```go
// In setupHostNetwork()
func setupHostNetwork(pid int) error {
    cmd := exec.Command("ip", "link", "add", VethHost, "type", "veth", "peer", "name", VethContainer)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to create veth pair: %v\nOutput: %s", err, output)
    }
    cmd = exec.Command("ip", "link", "set", VethContainer, "netns", fmt.Sprintf("%d", pid))
    output, err = cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to move veth to container: %v\nOutput: %s", err, output)
    }
    cmd = exec.Command("ip", "link", "set", VethHost, "up")
    output, err = cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to bring up host interface: %v\nOutput: %s", err, output)
    }
    cmd = exec.Command("ip", "addr", "add", HostIP, "dev", VethHost)
    output, err = cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to assign IP to host interface: %v\nOutput: %s", err, output)
    }
    cmds := [][]string{
        {"sysctl", "-w", "net.ipv4.ip_forward=1"},
        {"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE"},
        {"iptables", "-A", "FORWARD", "-o", VethHost, "-j", "ACCEPT"},
        {"iptables", "-A", "FORWARD", "-i", VethHost, "-j", "ACCEPT"},
    }
    for _, args := range cmds {
        cmd = exec.Command(args[0], args[1:]...)
        output, err = cmd.CombinedOutput()
        if err != nil {
            return fmt.Errorf("failed %v: %v\nOutput: %s", args, err, output)
        }
    }
    return nil
}

// In setupContainerNetwork()
func setupContainerNetwork() error {
    if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
        return fmt.Errorf("failed to bring up lo: %v", err)
    }
    if err := exec.Command("ip", "link", "set", VethContainer, "up").Run(); err != nil {
        return fmt.Errorf("failed to bring up veth: %v", err)
    }
    if err := exec.Command("ip", "addr", "add", ContainerIP, "dev", VethContainer).Run(); err != nil {
        return fmt.Errorf("failed to assign IP to veth: %v", err)
    }
    if err := exec.Command("ip", "route", "add", "default", "via", Gateway).Run(); err != nil {
        return fmt.Errorf("failed to add default route: %v", err)
    }
    return nil
}
```

**Implementation**:
- `setupHostNetwork()` creates and configures the host side of the veth pair with NAT.
- `setupContainerNetwork()` configures the container’s network stack with IP and routing.

#### Security Hardening
- **Filesystem Isolation**: Achieved via chroot and mount namespace.
- **Pending**: Non-root execution, seccomp/AppArmor.

**Code**:
```go
// In child() (partial overlap with Filesystem Isolation)
must(syscall.Chroot(RootFS))
must(os.Chdir("/"))
must(syscall.Mount("proc", "proc", "proc", 0, ""))
```

**Implementation**:
- Chroot and mount namespace in `child()` ensure filesystem isolation from the host.

#### DNS Setup
- **DNS Resolution**: Mounts host’s `resolv.conf` or creates a fallback.

**Code**:
```go
func setupDNS() error {
    resolvContainer := "/etc/resolv.conf"
    possibleHostPaths := []string{
        "/etc/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
    }
    var resolvHost string
    for _, path := range possibleHostPaths {
        if info, err := os.Stat(path); err == nil {
            if info.Mode().IsRegular() || (info.Mode()&os.ModeSymlink != 0) {
                resolvHost = path
                break
            }
        } else {
            log.Printf("Checked %s: %v", path, err)
        }
    }
    if resolvHost != "" {
        err := syscall.Mount(resolvHost, resolvContainer, "bind", syscall.MS_BIND|syscall.MS_RDONLY, "")
        if err != nil {
            return fmt.Errorf("failed to bind mount %s to %s: %v", resolvHost, resolvContainer, err)
        }
        log.Printf("Mounted %s to container's %s", resolvHost, resolvContainer)
        return nil
    }
    log.Printf("No host resolv.conf found; creating fallback with Google's DNS")
    resolvContent := []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    if err := os.WriteFile(resolvContainer, resolvContent, 0644); err != nil {
        if err := syscall.Mount("tmpfs", "/etc", "tmpfs", 0, "size=65536"); err != nil {
            return fmt.Errorf("failed to mount tmpfs on /etc: %v", err)
        }
        if err := os.WriteFile(resolvContainer, resolvContent, 0644); err != nil {
            return fmt.Errorf("failed to create fallback resolv.conf after tmpfs: %v", err)
        }
        log.Printf("Created fallback resolv.conf on tmpfs")
    }
    return nil
}
```

**Implementation**:
- `setupDNS()` attempts to bind-mount a host `resolv.conf` or creates a fallback with Google DNS, using tmpfs if needed.

### Cleanup
- **Resource Cleanup**: Removes network and namespace artifacts.

**Code**:
```go
func (rm *ResourceManager) cleanup() error {
    var errors []error
    cmds := [][]string{
        {"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE"},
        {"iptables", "-D", "FORWARD", "-o", VethHost, "-j", "ACCEPT"},
        {"iptables", "-D", "FORWARD", "-i", VethHost, "-j", "ACCEPT"},
    }
    for _, args := range cmds {
        if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
            log.Printf("Warning: failed to clean %v: %v", args, err)
            errors = append(errors, err)
        }
    }
    if err := exec.Command("ip", "link", "delete", rm.vethHost).Run(); err != nil {
        log.Printf("Warning: failed to delete veth interface: %v", err)
        errors = append(errors, err)
    }
    nsPath := "/var/run/netns/" + rm.containerName
    if err := syscall.Unmount(nsPath, 0); err != nil {
        log.Printf("Warning: failed to unmount namespace file %s: %v", nsPath, err)
        errors = append(errors, err)
    }
    if err := os.Remove(nsPath); err != nil {
        log.Printf("Warning: failed to remove namespace file %s: %v", nsPath, err)
        errors = append(errors, err)
    }
    if len(errors) > 0 {
        return fmt.Errorf("encountered %d cleanup errors", len(errors))
    }
    return nil
}
```

**Implementation**:
- `cleanup()` removes iptables rules, deletes the veth interface, and cleans up the namespace file.

## Building and Running
1. **Compile**:
   ```bash
   go build -o container
   ```
2. **Run**:
   ```bash
   sudo ./container run /bin/sh
   ```
3. **Test**:
   - Check isolation: `ps aux` (should show only container processes).
   - Test network: `ping 8.8.8.8` and `ping google.com`.

## Debugging
- **Logs**: Check output for errors (e.g., `failed to create veth pair`).
- **Permissions**: Ensure `sudo` is used and `alpine_fs` is writable where needed.
- **DNS**: Verify `/run/systemd/resolve/stub-resolv.conf` exists on the host.

## Current Status
- **Completed**:
  - PID, User, Network, Mount namespaces
  - Chroot with `/proc` mount
  - Process limit via cgroups
  - Network isolation with veth
  - Basic DNS setup
- **Pending**:
  - Memory and I/O limits (cgroups)
  - Non-root execution inside container
  - Seccomp/AppArmor
  - Specific outbound connection filtering
  - Mounting `/sys` and `/dev`

## Notes
- Runs as root on the host (via `sudo`) but maps to a non-root UID outside the container.
- Requires `alpine_fs` to be pre-populated with a minimal filesystem.
- Tested on Ubuntu 24.04 with Go 1.22.