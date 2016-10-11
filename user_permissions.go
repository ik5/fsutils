package fsutil

import (
	"syscall"
)

// UserDetails contains private members regarding the current user in the system
type UserDetails struct {
	uid  int
	gid  int
	euid int
	egid int
}

/*InitUser get The current active user

* If the user was not found, or something went wrong, we will return error
  and empty UserDetails.
*/
func InitUser() UserDetails {
	var user UserDetails
	user.uid = syscall.Getuid()
	user.gid = syscall.Getgid()
	user.euid = syscall.Geteuid()
	user.egid = syscall.Getegid()

	return user
}

// GetUID retrive the user's id
func (u UserDetails) GetUID() int {
	return u.uid
}

// GetGID retrive the user's goup id
func (u UserDetails) GetGID() int {
	return u.gid
}

// GetEUid retrive the effective user id
func (u UserDetails) GetEUid() int {
	return u.euid
}

// GetEGid retrive the effective group id
func (u UserDetails) GetEGid() int {
	return u.egid
}
