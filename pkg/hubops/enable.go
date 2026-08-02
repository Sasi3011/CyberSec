package hubops

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// EnableCommand installs a hub item and its dependencies.
// In case this command is called during an upgrade, the sub-items list it taken from the
// latest version in the index, otherwise from the version that is currently installed.
type EnableCommand struct {
	Item       *cwhub.Item
	Force      bool
	FromLatest bool
}

func NewEnableCommand(item *cwhub.Item, force bool) *EnableCommand {
	return &EnableCommand{Item: item, Force: force}
}

func (c *EnableCommand) Prepare(plan *ActionPlan) (bool, error) {
	var dependencies cwhub.Dependencies

	i := c.Item

	if c.FromLatest {
		// we are upgrading
		dependencies = i.LatestDependencies()
	} else {
		dependencies = i.CurrentDependencies()
	}

	for sub := range dependencies.SubItems(plan.hub) {
		if err := plan.AddCommand(NewEnableCommand(sub, c.Force)); err != nil {
			return false, err
		}
	}

	if i.State.IsInstalled() {
		return false, nil
	}

	return true, nil
}

// CreateInstallLink creates a symlink between the actual config file at hub.HubDir and hub.ConfigDir.
func CreateInstallLink(i *cwhub.Item) error {
	dest, err := i.PathForInstall()
	if err != nil {
		return err
	}

	destDir := filepath.Dir(dest)
	if err = os.MkdirAll(destDir, os.ModePerm); err != nil {
		return fmt.Errorf("while creating %s: %w", destDir, err)
	}

	if _, err = os.Lstat(dest); err == nil {
		// already exists
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat %s: %w", dest, err)
	}

	src := i.State.DownloadPath

	if err = createInstallLink(src, dest); err != nil {
		return fmt.Errorf("while creating symlink from %s to %s: %w", src, dest, err)
	}

	i.State.LocalPath = dest

	return nil
}

func createInstallLink(src, dest string) error {
	symlinkErr := os.Symlink(src, dest)
	if symlinkErr == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return symlinkErr
	}

	srcInfo, statErr := os.Stat(src)
	if statErr != nil {
		return symlinkErr
	}

	if srcInfo.IsDir() {
		return copyInstallTree(src, dest)
	}

	return copyInstallFile(src, dest)
}

func copyInstallFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfoMode(src))
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func copyInstallTree(src, dest string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, os.ModePerm)
		}

		return copyInstallFile(path, target)
	})
}

func srcInfoMode(src string) os.FileMode {
	info, err := os.Stat(src)
	if err != nil {
		return 0o644
	}

	return info.Mode().Perm()
}

func (c *EnableCommand) Run(_ context.Context, plan *ActionPlan) error {
	i := c.Item

	fmt.Fprintln(os.Stdout, "enabling " + colorizeItemName(i.FQName()))

	if !i.State.IsDownloaded() {
		// XXX: this a warning?
		return fmt.Errorf("can't enable %s: not downloaded", i.FQName())
	}

	if err := CreateInstallLink(i); err != nil {
		return fmt.Errorf("while enabling %s: %w", i.FQName(), err)
	}

	plan.ReloadNeeded = true

	i.State.Tainted = false

	return nil
}

func (*EnableCommand) OperationType() string {
	return "enable"
}

func (c *EnableCommand) ItemType() string {
	return c.Item.Type
}

func (c *EnableCommand) Detail() string {
	return colorizeItemName(c.Item.Name)
}
