package outcome

import (
	"encoding/gob"

	"hakurei.app/container/check"
	"hakurei.app/hst"
	"hakurei.app/internal/system"
)

func init() { gob.Register(new(spCgroupOp)) }

type spCgroupOp struct {
	Path string
}

func (s *spCgroupOp) toSystem(state *outcomeStateSys) error {
	if state.Container.Cgroup == nil {
		return errNotEnabled
	}

	slicePath, err := state.Container.Cgroup.SlicePath()
	if err != nil {
		return err
	}
	instancePath, err := state.Container.Cgroup.InstancePath(state.identity.String(), state.id.String())
	if err != nil {
		return err
	}

	state.sys.Cgroup(slicePath, instancePath, system.CgroupLimits{
		CPU:    state.Container.Cgroup.LimitCPU,
		Memory: state.Container.Cgroup.LimitMemory,
		Pids:   state.Container.Cgroup.LimitPids,
	})

	s.Path = instancePath.String()
	return nil
}

func (s *spCgroupOp) toContainer(state *outcomeStateParams) error {
	if s.Path == "" {
		return newWithMessage("invalid cgroup state")
	}
	pathname, err := check.NewAbs(s.Path)
	if err != nil {
		return &hst.AppError{Step: "parse cgroup path", Err: err}
	}
	state.params.CgroupPath = pathname
	return nil
}
