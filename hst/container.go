package hst

import (
	"encoding/json"
	"errors"
	"path"
	"strings"
	"syscall"
	"time"

	"hakurei.app/container/check"
)

// PrivateTmp is a private writable path in a hakurei container.
const PrivateTmp = "/.hakurei"

// AbsPrivateTmp is a [check.Absolute] representation of [PrivateTmp].
var AbsPrivateTmp = check.MustAbs(PrivateTmp)

// ErrCgroupPath is returned when a cgroup slice resolves outside of the filesystem root.
var ErrCgroupPath = errors.New("invalid cgroup slice path")

const (
	// WaitDelayDefault is used when WaitDelay has its zero value.
	WaitDelayDefault = 5 * time.Second
	// WaitDelayMax is used if WaitDelay exceeds its value.
	WaitDelayMax = 30 * time.Second
)

const (
	// ExitFailure is returned if the container fails to start.
	ExitFailure = iota + 1
	// ExitCancel is returned if the container is terminated by a shim-directed signal which cancels its context.
	ExitCancel
	// ExitOrphan is returned when the shim is orphaned before priv side delivers a signal.
	ExitOrphan

	// ExitRequest is returned when the priv side process requests shim exit.
	ExitRequest = 254
)

// Flags are options held by [ContainerConfig].
type Flags uintptr

const (
	// FMultiarch unblocks syscalls required for multiarch to work on applicable targets.
	FMultiarch Flags = 1 << iota

	// FSeccompCompat changes emitted seccomp filter programs to be identical to that of Flatpak.
	FSeccompCompat
	// FDevel unblocks ptrace and friends.
	FDevel
	// FUserns unblocks userns creation and container setup syscalls.
	FUserns
	// FHostNet skips net namespace creation.
	FHostNet
	// FHostAbstract skips setting up abstract unix socket scope.
	FHostAbstract
	// FTty unblocks dangerous terminal I/O (faking input).
	FTty

	// FMapRealUID maps the target user uid to the privileged user uid in the container user namespace.
	//	Some programs fail to connect to dbus session running as a different uid,
	//	this option works around it by mapping priv-side caller uid in container.
	FMapRealUID

	// FDevice mount /dev/ from the init mount namespace as-is in the container mount namespace.
	FDevice

	// FShareRuntime shares XDG_RUNTIME_DIR between containers under the same identity.
	FShareRuntime
	// FShareTmpdir shares TMPDIR between containers under the same identity.
	FShareTmpdir

	fMax

	// FAll is [ContainerConfig.Flags] with all currently defined bits set.
	FAll = fMax - 1
)

func (flags Flags) String() string {
	switch flags {
	case FMultiarch:
		return "multiarch"
	case FSeccompCompat:
		return "compat"
	case FDevel:
		return "devel"
	case FUserns:
		return "userns"
	case FHostNet:
		return "net"
	case FHostAbstract:
		return "abstract"
	case FTty:
		return "tty"
	case FMapRealUID:
		return "mapuid"
	case FDevice:
		return "device"
	case FShareRuntime:
		return "runtime"
	case FShareTmpdir:
		return "tmpdir"

	default:
		s := make([]string, 0, 1<<4)
		for f := Flags(1); f < fMax; f <<= 1 {
			if flags&f != 0 {
				s = append(s, f.String())
			}
		}
		if len(s) == 0 {
			return "none"
		}
		return strings.Join(s, ", ")
	}
}

// ContainerConfig describes the container configuration to be applied to an underlying [container].
type ContainerConfig struct {
	// Container UTS namespace hostname.
	Hostname string `json:"hostname,omitempty"`

	// Duration in nanoseconds to wait for after interrupting the initial process.
	// Defaults to [WaitDelayDefault] if zero, or [WaitDelayMax] if greater than [WaitDelayMax].
	// Values lesser than zero is equivalent to zero, bypassing [WaitDelayDefault].
	WaitDelay time.Duration `json:"wait_delay,omitempty"`

	// Initial process environment variables.
	Env map[string]string `json:"env"`

	/* Container mount points.

	If the first element targets /, it is inserted early and excluded from path hiding. */
	Filesystem []FilesystemConfigJSON `json:"filesystem"`

	// String used as the username of the emulated user, validated against the default NAME_REGEX from adduser.
	// Defaults to passwd name of target uid or chronos.
	Username string `json:"username,omitempty"`
	// Pathname of shell in the container filesystem to use for the emulated user.
	Shell *check.Absolute `json:"shell"`
	// Directory in the container filesystem to enter and use as the home directory of the emulated user.
	Home *check.Absolute `json:"home"`

	// Pathname to executable file in the container filesystem.
	Path *check.Absolute `json:"path,omitempty"`
	// Final args passed to the initial program.
	Args []string `json:"args"`

	// Flags holds boolean options of [ContainerConfig].
	Flags Flags `json:"-"`

	// Optional cgroup configuration applied prior to starting the container.
	Cgroup *CgroupConfig `json:"cgroup,omitempty"`
}

const (
	// CgroupRoot is the default root for the unified cgroup hierarchy.
	CgroupRoot = "/sys/fs/cgroup"
	// defaultCgroupSlice is used when Slice is left unspecified.
	defaultCgroupSlice = CgroupRoot + "/hakurei.slice"
)

// CgroupConfig configures a cgroup v2 subtree for the container.
type CgroupConfig struct {
	// Slice denotes the delegated cgroup slice that instances are created under.
	// Relative values are resolved against CgroupRoot.
	Slice string `json:"slice,omitempty"`
	// LimitCPU specifies the microsecond quota applied to the default 100000µs period.
	// A zero value leaves cpu.max untouched.
	LimitCPU uint64 `json:"limit_cpu,omitempty"`
	// LimitMemory caps memory.max in bytes. A zero value keeps the current limit.
	LimitMemory uint64 `json:"limit_memory,omitempty"`
	// LimitPids caps pids.max. Zero disables the limit.
	LimitPids int `json:"limit_pids,omitempty"`
}

func (config *ContainerConfig) validateCgroup() error {
	if config.Cgroup == nil {
		return nil
	}
	return config.Cgroup.Validate()
}

// Validate ensures cgroup constraints are sane.
func (c *CgroupConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.LimitPids < 0 {
		return &AppError{Step: "validate configuration", Err: syscall.EINVAL,
			Msg: "cgroup limit pids cannot be negative"}
	}
	if _, err := c.slicePath(); err != nil {
		return &AppError{Step: "validate configuration", Err: err, Msg: "invalid cgroup slice"}
	}
	return nil
}

// SlicePath returns the absolute slice root path.
func (c *CgroupConfig) SlicePath() (*check.Absolute, error) {
	if c == nil {
		return nil, syscall.EINVAL
	}
	return c.slicePath()
}

// InstancePath returns the per-instance cgroup directory path.
func (c *CgroupConfig) InstancePath(identity string, id *ID) (*check.Absolute, error) {
	if c == nil || id == nil {
		return nil, syscall.EINVAL
	}
	root, err := c.instanceRoot(identity)
	if err != nil {
		return nil, err
	}
	return root.Append(id.String()), nil
}

func (c *CgroupConfig) instanceRoot(identity string) (*check.Absolute, error) {
	slice, err := c.slicePath()
	if err != nil {
		return nil, err
	}
	return slice.Append("hakurei-" + identity), nil
}

func (c *CgroupConfig) slicePath() (*check.Absolute, error) {
	base := c.Slice
	if base == "" {
		base = defaultCgroupSlice
	}
	if !path.IsAbs(base) {
		base = path.Join(CgroupRoot, base)
	}
	cleaned := path.Clean(base)
	abs, err := check.NewAbs(cleaned)
	if err != nil {
		return nil, ErrCgroupPath
	}
	return abs, nil
}

// ContainerConfigF is [ContainerConfig] stripped of its methods.
// The [ContainerConfig.Flags] field does not survive a [json] round trip.
type ContainerConfigF ContainerConfig

// containerConfigJSON is the [json] representation of [ContainerConfig].
type containerConfigJSON = struct {
	*ContainerConfigF

	// Corresponds to [FSeccompCompat].
	SeccompCompat bool `json:"seccomp_compat,omitempty"`
	// Corresponds to [FDevel].
	Devel bool `json:"devel,omitempty"`
	// Corresponds to [FUserns].
	Userns bool `json:"userns,omitempty"`
	// Corresponds to [FHostNet].
	HostNet bool `json:"host_net,omitempty"`
	// Corresponds to [FHostAbstract].
	HostAbstract bool `json:"host_abstract,omitempty"`
	// Corresponds to [FTty].
	Tty bool `json:"tty,omitempty"`

	// Corresponds to [FMultiarch].
	Multiarch bool `json:"multiarch,omitempty"`

	// Corresponds to [FMapRealUID].
	MapRealUID bool `json:"map_real_uid"`

	// Corresponds to [FDevice].
	Device bool `json:"device,omitempty"`

	// Corresponds to [FShareRuntime].
	ShareRuntime bool `json:"share_runtime,omitempty"`
	// Corresponds to [FShareTmpdir]
	ShareTmpdir bool `json:"share_tmpdir,omitempty"`
}

func (c *ContainerConfig) MarshalJSON() ([]byte, error) {
	if c == nil {
		return nil, syscall.EINVAL
	}
	return json.Marshal(&containerConfigJSON{
		ContainerConfigF: (*ContainerConfigF)(c),

		SeccompCompat: c.Flags&FSeccompCompat != 0,
		Devel:         c.Flags&FDevel != 0,
		Userns:        c.Flags&FUserns != 0,
		HostNet:       c.Flags&FHostNet != 0,
		HostAbstract:  c.Flags&FHostAbstract != 0,
		Tty:           c.Flags&FTty != 0,
		Multiarch:     c.Flags&FMultiarch != 0,
		MapRealUID:    c.Flags&FMapRealUID != 0,
		Device:        c.Flags&FDevice != 0,
		ShareRuntime:  c.Flags&FShareRuntime != 0,
		ShareTmpdir:   c.Flags&FShareTmpdir != 0,
	})
}

func (c *ContainerConfig) UnmarshalJSON(data []byte) error {
	if c == nil {
		return syscall.EINVAL
	}

	v := new(containerConfigJSON)
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*c = *(*ContainerConfig)(v.ContainerConfigF)
	if v.SeccompCompat {
		c.Flags |= FSeccompCompat
	}
	if v.Devel {
		c.Flags |= FDevel
	}
	if v.Userns {
		c.Flags |= FUserns
	}
	if v.HostNet {
		c.Flags |= FHostNet
	}
	if v.HostAbstract {
		c.Flags |= FHostAbstract
	}
	if v.Tty {
		c.Flags |= FTty
	}
	if v.Multiarch {
		c.Flags |= FMultiarch
	}
	if v.MapRealUID {
		c.Flags |= FMapRealUID
	}
	if v.Device {
		c.Flags |= FDevice
	}
	if v.ShareRuntime {
		c.Flags |= FShareRuntime
	}
	if v.ShareTmpdir {
		c.Flags |= FShareTmpdir
	}
	return nil
}
