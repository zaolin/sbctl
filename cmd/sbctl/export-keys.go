package main

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	dir string
)

var exportKeysCmd = &cobra.Command{
	Use:   "export-keys",
	Short: "Export PK, KEKs and DB/DBX certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		if dir == "" {
			dir, _ = ioutil.TempDir("", "sbctl")
		} else {
			path, _ := filepath.Abs(dir)
			err := os.MkdirAll(path, 0755)
			if err != nil {
				return err
			}
		}

		err := sbctl.ExportKeys(dir)
		if err != nil {
			return err
		} else {
			logging.Ok("Exported keys successful to %s", dir)
		}
		return nil
	},
}

func exportKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&dir, "output", "o", "", "output directory. Default creates the directory")
}

func init() {
	exportKeysCmdFlags(exportKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: exportKeysCmd,
	})
}
