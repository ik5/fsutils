package fsutils

import (
	"errors"
	"os"
	"syscall"
)

// SystemPath represents a struct with private members that stores information about a path
type SystemPath struct {
	stat os.FileInfo
	err  error
}

const (
	// IRUSR Read by owner
	IRUSR = 00400
	// IREAD Read by owner
	IREAD = 00400
	// IWUSR Write by owner
	IWUSR = 00200
	// IWRITE Write by Owner
	IWRITE = 00200
	// IXUSR Execute/search by owner
	IXUSR = 00100
	// IEXEC Execute/search by owner
	IEXEC = 00100
	// IRGRP Read by group
	IRGRP = 00040
	// IWGRP Write by group
	IWGRP = 00020
	// IXGRP Execute/search by group
	IXGRP = 00010
	// IROTH Read by others
	IROTH = 00004
	// IWOTH Write by others
	IWOTH = 00002
	// IXOTH Execute/search by others
	IXOTH = 00001
)

// SystemInit get a path and create a SystemPath with it
func SystemInit(path string) SystemPath {
	stat, err := os.Stat(path)
	return SystemPath{stat, err}
}

// HaveError check to see if an error was returned
func (s SystemPath) HaveError() bool {
	return s.err != nil
}

func (s SystemPath) Error() error {
	return s.err
}

// IsStat validate if a stat exists in the path
func (s SystemPath) IsStat(istat os.FileMode) bool {
	if s.err != nil {
		return false
	}
	return (s.stat.Mode() & istat) == istat
}

// IsDir check if a path is actually a directory
func (s SystemPath) IsDir() bool {
	return s.IsStat(os.ModeDir)
}

// IsExist validate if a path actually exists
func (s SystemPath) IsExist() bool {
	return os.IsNotExist(s.err) == false
}

// IsSymlink validate if a path is a symbolic link
func (s SystemPath) IsSymlink() bool {
	return s.IsStat(os.ModeSymlink)
}

// IsAppend check if the path is opened for appending text
func (s SystemPath) IsAppend() bool {
	return s.IsStat(os.ModeAppend)
}

// IsExclusive validate if the path is opened exclusivly or not
func (s SystemPath) IsExclusive() bool {
	return s.IsStat(os.ModeExclusive)
}

// IsTemporary validate if the path is set temporarly
func (s SystemPath) IsTemporary() bool {
	return s.IsStat(os.ModeTemporary)
}

// IsDevice validate if the path is a type of device file
func (s SystemPath) IsDevice() bool {
	return s.IsStat(os.ModeDevice)
}

// IsNamedPipe validate if the path is a pipe file
func (s SystemPath) IsNamedPipe() bool {
	return s.IsStat(os.ModeNamedPipe)
}

// IsSocket validate if the path is a socket file
func (s SystemPath) IsSocket() bool {
	return s.IsStat(os.ModeSocket)
}

// IsCharDevice validate if the path is a char file
func (s SystemPath) IsCharDevice() bool {
	return s.IsStat(os.ModeCharDevice)
}

// HasSetUID valiate if a path contain a suid property
func (s SystemPath) HasSetUID() bool {
	return s.IsStat(os.ModeSetuid)
}

// HasSetGid validate if a path contain a set gid property
func (s SystemPath) HasSetGid() bool {
	return s.IsStat(os.ModeSetgid)
}

// IsSticky validate if a path has a sticky property
func (s SystemPath) IsSticky() bool {
	return s.IsStat(os.ModeSticky)
}

// IsRegularFile validate if the path is not something special
func (s SystemPath) IsRegularFile() bool {
	if s.err != nil {
		return false
	}
	return s.stat.Mode().IsRegular()
}

// HavePerm check to see if a permission exists in the path
func (s SystemPath) HavePerm(perm os.FileMode) bool {
	if s.err != nil {
		return false
	}
	return (s.stat.Mode().Perm() & perm) == perm
}

// IsOwnerReadable validate if a path is readable by the owner
func (s SystemPath) IsOwnerReadable() bool {
	return s.HavePerm(IRUSR)
}

// IsOwnerWriteable validate if a path is writeable by the owner
func (s SystemPath) IsOwnerWriteable() bool {
	return s.HavePerm(IWUSR)
}

// IsOwnerExecutable validate if a path is executable by the owner
func (s SystemPath) IsOwnerExecutable() bool {
	return s.HavePerm(IXUSR)
}

// IsGroupReadable validate if a path is readable by the group
func (s SystemPath) IsGroupReadable() bool {
	return s.HavePerm(IRGRP)
}

// IsGroupWriteable validate if the path is writeable by the group
func (s SystemPath) IsGroupWriteable() bool {
	return s.HavePerm(IWGRP)
}

// IsGroupExecutable validate if the path is executable by the group
func (s SystemPath) IsGroupExecutable() bool {
	return s.HavePerm(IXGRP)
}

// IsOtherReadable validate if the path is readable by others
func (s SystemPath) IsOtherReadable() bool {
	return s.HavePerm(IROTH)
}

// IsOtherWriteable validate if the path is writeable by others
func (s SystemPath) IsOtherWriteable() bool {
	return s.HavePerm(IWOTH)
}

// IsOtherExecutable validate if the path is executable by others
func (s SystemPath) IsOtherExecutable() bool {
	return s.HavePerm(IXOTH)
}

// GetUID returns the path user id or an error
func (s SystemPath) GetUID() (uint32, error) {
	uid := s.stat.Sys().(*syscall.Stat_t).Uid
	if uid >= 0 {
		return uid, nil
	}

	return 0, errors.New("Invalid value for uid")
}

// GetGID returns the path group id or an error
func (s SystemPath) GetGID() (uint32, error) {
	gid := s.stat.Sys().(*syscall.Stat_t).Uid
	if gid >= 0 {
		return gid, nil
	}

	return 0, errors.New("Invalid value for gid")
}

// IsReadable check if the current user has read permission to a path
func (s SystemPath) IsReadable() bool {
	user := InitUser()

	useruid := user.GetUID()
	usergid := user.GetGID()
	fileuid, _ := s.GetUID()
	filegid, _ := s.GetGID()

	if fileuid == uint32(useruid) {
		return s.IsOwnerReadable()
	}

	if filegid == uint32(usergid) {
		return s.IsGroupReadable()
	}

	return s.IsOtherReadable()
}

// IsWriteable check if the current user have write permission to a path
func (s SystemPath) IsWriteable() bool {
	user := InitUser()

	useruid := user.GetUID()
	usergid := user.GetGID()
	fileuid, _ := s.GetUID()
	filegid, _ := s.GetGID()

	if fileuid == uint32(useruid) {
		return s.IsOwnerWriteable()
	}

	if filegid == uint32(usergid) {
		return s.IsGroupWriteable()
	}

	return s.IsOtherWriteable()
}

// IsExecutible check if a path have execution permission for the user
func (s SystemPath) IsExecutible() bool {
	user := InitUser()

	useruid := user.GetUID()
	usergid := user.GetGID()
	fileuid, _ := s.GetUID()
	filegid, _ := s.GetGID()

	if fileuid == uint32(useruid) {
		return s.IsOwnerExecutable()
	}

	if filegid == uint32(usergid) {
		return s.IsGroupExecutable()
	}

	return s.IsOtherExecutable()
}

// Size return length in bytes for regular files; system-dependent for others
func (s SystemPath) Size() int64 {
	return s.stat.Size()
}

// GetCurrentDir returns the working directory that the executable points to
func GetCurrentDir(endseperator bool) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	if endseperator {
		dir = dir + string(os.PathSeparator)
	}
	return dir
}
