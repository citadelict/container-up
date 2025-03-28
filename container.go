package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	ContainerName  = "mycontainer"
	VethHost       = "veth0"
	VethContainer  = "veth1"
	ContainerIP    = "10.0.0.2/24"
	HostIP         = "10.0.0.1/24"
	Gateway        = "10.0.0.1"
	RootFS         = "./alpine_fs"
)

type ResourceManager struct {
	containerName string
	vethHost      string
	mounts        []string
	namespaces    []string
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Expected at least one argument: run or child")
	}

	switch os.Args[1] {
	case "run":
		run(os.Args[2:]...)
	case "child":
		child(os.Args[2:]...)
	default:
		log.Fatal("Unknown command. Use run <command_name>, like `run /bin/sh` or `run /bin/echo hello`")
	}
}

func run(command ...string) {
	log.Println("Executing", command, "from run")
	log.Printf("Running %v as user %d in process %d\n", os.Args[2:], os.Geteuid(), os.Getpid())

	pid := os.Getpid()
	setupCgroups(pid)

	cmd := exec.Command("/proc/self/exe", append([]string{"child"}, command...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		Unshareflags: syscall.CLONE_NEWNS,
		UidMappings:  []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:  []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		AmbientCaps:  []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN},
	}

	must(createNetworkNamespace(ContainerName))
	must(cmd.Start())
	must(setupHostNetwork(cmd.Process.Pid))

	rm := &ResourceManager{
		containerName: ContainerName,
		vethHost:      VethHost,
		mounts:        []string{"/var/run/netns/" + ContainerName},
		namespaces:    []string{"net"},
	}

	must(cmd.Wait())
	if err := rm.cleanup(); err != nil {
		log.Printf("Cleanup failed: %v", err)
	}
}

func child(command ...string) {
	log.Println("Executing", command, "from child")
	log.Printf("Running %v as user %d in process %d\n", os.Args[2:], os.Geteuid(), os.Getpid())

	// Setup network before chroot
	must(setupContainerNetwork())

	// Set hostname
	must(syscall.Sethostname([]byte("container")))

	// Chroot and change directory after network setup
	must(syscall.Chroot(RootFS))
	must(os.Chdir("/"))

	// Create essential directories
	must(os.MkdirAll("/etc/apk", 0755))
	must(os.MkdirAll("/sys", 0755))
	must(os.MkdirAll("/dev", 0755))
	must(os.MkdirAll("/proc", 0755))

	// Setup APK repositories if not present
	reposFile := "/etc/apk/repositories"
	if _, err := os.Stat(reposFile); os.IsNotExist(err) {
		reposContent := []byte("http://dl-cdn.alpinelinux.org/alpine/v3.19/main\nhttp://dl-cdn.alpinelinux.org/alpine/v3.19/community\n")
		must(os.WriteFile(reposFile, reposContent, 0644))
		log.Println("Created /etc/apk/repositories with default Alpine mirrors")
	}

	// Setup DNS
	must(setupDNS())

	// Mount /proc
	must(syscall.Mount("proc", "/proc", "proc", 0, ""))
	defer func() {
		if err := syscall.Unmount("/proc", 0); err != nil {
			log.Printf("Failed to unmount /proc: %v", err)
		}
	}()

	// Mount /sys as read-only
	must(syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_RDONLY, ""))
	defer func() {
		if err := syscall.Unmount("/sys", 0); err != nil {
			log.Printf("Failed to unmount /sys: %v", err)
		}
	}()

	// Execute the command
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to run command: %v", err)
	}
}

func createNetworkNamespace(name string) error {
	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		return err
	}
	nsFile := filepath.Join("/var/run/netns", name)
	fd, err := os.Create(nsFile)
	if err != nil {
		return err
	}
	fd.Close()
	return syscall.Mount("/proc/self/ns/net", nsFile, "bind", syscall.MS_BIND, "")
}

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

func setupContainerNetwork() error {
	if err := exec.Command("/usr/sbin/ip", "link", "set", "lo", "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up lo: %v", err)
	}

	if err := exec.Command("/usr/sbin/ip", "link", "set", VethContainer, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up veth: %v", err)
	}

	if err := exec.Command("/usr/sbin/ip", "addr", "add", ContainerIP, "dev", VethContainer).Run(); err != nil {
		return fmt.Errorf("failed to assign IP to veth: %v", err)
	}

	if err := exec.Command("/usr/sbin/ip", "route", "add", "default", "via", Gateway).Run(); err != nil {
		return fmt.Errorf("failed to add default route: %v", err)
	}

	return nil
}

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

func setupCgroups(pid int) {
	cgroups := "/sys/fs/cgroup/"
	containerDir := filepath.Join(cgroups, "go_container/")
	
	if err := os.MkdirAll(containerDir, 0755); err != nil {
		log.Printf("Failed to create cgroup directory: %v", err)
		panic(err)
	}

	if err := os.WriteFile(filepath.Join(cgroups, "cgroup.subtree_control"), []byte("+cpu +pids"), 0700); err != nil {
		log.Printf("Failed to enable cpu and pids controllers: %v", err)
	}

	must(os.WriteFile(filepath.Join(containerDir, "pids.max"), []byte("20"), 0700))
	must(os.WriteFile(filepath.Join(containerDir, "cpu.max"), []byte("50000 100000"), 0700))
	must(os.WriteFile(filepath.Join(containerDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0700))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
