package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"hakurei.app/container/check"
	"hakurei.app/hst"
)

// CgroupLimits configures basic cgroup v2 resource controllers.
type CgroupLimits struct {
	CPU    uint64
	Memory uint64
	Pids   int
}

// Cgroup registers a process-scoped cgroup operation rooted at base and applied to target.
func (sys *I) Cgroup(base, target *check.Absolute, limits CgroupLimits) *I {
	if sys == nil || base == nil || target == nil {
		panic("invalid cgroup specification")
	}
	sys.ops = append(sys.ops, &cgroupOp{
		base:   base.String(),
		path:   target.String(),
		limits: limits,
	})
	return sys
}

type cgroupOp struct {
	base    string
	path    string
	limits  CgroupLimits
	created []string
	files   []string
}

func (c *cgroupOp) Type() hst.Enablement { return Process }

func (c *cgroupOp) apply(sys *I) error {
	sys.msg.Verbosef("configuring cgroup %q", c.path)

	if !strings.HasPrefix(c.path, c.base) {
		return newOpErrorMessage("cgroup", syscall.EINVAL, "cgroup path escapes slice", false)
	}

	if _, err := sys.stat(c.base); err != nil {
		return newOpError("cgroup", err, false)
	}

	if err := c.ensurePath(sys); err != nil {
		return err
	}

	if err := c.applyLimits(); err != nil {
		return err
	}

	return nil
}

func (c *cgroupOp) ensurePath(sys *I) error {
	rel := strings.TrimPrefix(c.path, c.base)
	rel = strings.TrimPrefix(rel, string(os.PathSeparator))
	if rel == "" {
		return newOpErrorMessage("cgroup", syscall.EINVAL, "cgroup path cannot equal slice", false)
	}

	cur := c.base
	parts := strings.Split(rel, string(os.PathSeparator))
	for i, part := range parts {
		if part == "" {
			continue
		}

		cur = filepath.Join(cur, part)
		err := sys.mkdir(cur, 0755)
		switch {
		case err == nil:
			c.created = append(c.created, cur)
		case errors.Is(err, os.ErrExist):
			if i == len(parts)-1 {
				return newOpErrorMessage("cgroup", err, fmt.Sprintf("cgroup %q already exists", cur), false)
			}
			continue
		default:
			return newOpError("cgroup", err, false)
		}
	}
	return nil
}

func (c *cgroupOp) applyLimits() error {
	if c.limits.CPU > 0 {
		if err := c.writeControllerFile("cpu.max", fmt.Sprintf("%d 100000", c.limits.CPU)); err != nil {
			return err
		}
	}
	if c.limits.Memory > 0 {
		if err := c.writeControllerFile("memory.max", fmt.Sprintf("%d", c.limits.Memory)); err != nil {
			return err
		}
	}
	if c.limits.Pids > 0 {
		if err := c.writeControllerFile("pids.max", fmt.Sprintf("%d", c.limits.Pids)); err != nil {
			return err
		}
	}
	return nil
}

func (c *cgroupOp) writeControllerFile(name, value string) error {
	file := filepath.Join(c.path, name)
	if err := os.WriteFile(file, []byte(value), 0644); err != nil {
		return newOpError("cgroup", err, false)
	}
	c.files = append(c.files, file)
	return nil
}

func (c *cgroupOp) revert(sys *I, ec *Criteria) error {
	if ec != nil && !ec.hasType(Process) {
		sys.msg.Verbosef("skipping revert for cgroup %q", c.path)
		return nil
	}

	for i := len(c.files) - 1; i >= 0; i-- {
		file := c.files[i]
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			sys.msg.Verbosef("cannot remove cgroup file %q: %v", file, err)
		}
	}

	var errs []error
	for i := len(c.created) - 1; i >= 0; i-- {
		dir := c.created[i]
		if err := sys.remove(dir); err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				continue
			case errors.Is(err, syscall.ENOTEMPTY):
				sys.msg.Verbosef("skipping busy cgroup path %q", dir)
			default:
				errs = append(errs, newOpError("cgroup", err, true))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *cgroupOp) Is(o Op) bool {
	target, ok := o.(*cgroupOp)
	if !ok || target == nil || c == nil {
		return false
	}
	return c.base == target.base &&
		c.path == target.path &&
		c.limits == target.limits
}

func (c *cgroupOp) Path() string { return c.path }

func (c *cgroupOp) String() string {
	return fmt.Sprintf("base: %q path: %q cpu: %d memory: %d pids: %d",
		c.base, c.path, c.limits.CPU, c.limits.Memory, c.limits.Pids)
}
