package fot

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Password   string `json:"password" required:"true" confidential:"true" help:"The password used to encrypt the fnOS backup (.fot) files. It must match the one set when the backup was created."`
	RemotePath string `json:"remote_path" required:"true" help:"The mount path of the underlying storage which contains the encrypted .fot files, e.g. /local or /webdav"`
	ShowHidden bool   `json:"show_hidden" required:"false" default:"true" help:"show hidden directories and files"`
}

// GetRootPath implements driver.IRootPath, mapping the driver root to the underlying storage mount path
func (a Addition) GetRootPath() string {
	return a.RemotePath
}

var config = driver.Config{
	Name:        "FotCrypt",
	LocalSort:   true,
	OnlyProxy:   true,
	NoCache:     false,
	NoUpload:    false,
	DefaultRoot: "/",
	NoLinkURL:   true,
	CheckStatus: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &Fot{}
	})
}
