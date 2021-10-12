package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	dbxFilePath string
)

const (
	uefiDBXURL    = "https://uefi.org/sites/default/files/resources/dbxupdate_"
	uefiDBXSuffix = ".bin"
)

func download(filepath string, url string) error {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

var updateDBXCmd = &cobra.Command{
	Use:   "update-dbx",
	Short: "Update dbx efi variable",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := CheckImmutable(); err != nil {
			return err
		}
		uuid, err := sbctl.GetGUID()
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Join(sbctl.KeysPath, "dbx"), 0755)
		_, err = os.Stat(dbxFilePath)
		if os.IsNotExist(err) {
			dbxFile := filepath.Join(sbctl.KeysPath, "dbx", "dbx.pem")
			if runtime.GOARCH == "amd64" {
				url := uefiDBXURL + "x64" + uefiDBXSuffix
				if err := download(dbxFile, url); err != nil {
					return err
				}
			} else if runtime.GOARCH == "i386" {
				url := uefiDBXURL + "x86" + uefiDBXSuffix
				if err := download(dbxFile, url); err != nil {
					return err
				}
			} else if runtime.GOARCH == "arm64" {
				url := uefiDBXURL + "arm64" + uefiDBXSuffix
				if err := download(dbxFile, url); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("architecture not supported")
			}
		}
		guid := util.StringToGUID(uuid.String())
		logging.Print("Updating dbx to EFI variable...")
		if err := sbctl.UpdateDBX(*guid, sbctl.KeysPath); err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't update dbx: %w", err)
		}
		logging.Ok("\nUpdated dbx to the EFI variable!")
		return nil
	},
}

func updateDBXCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&dbxFilePath, "dbx", "f", "", "dbx file to update efi variable")
}

func init() {
	updateDBXCmdFlags(updateDBXCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: updateDBXCmd,
	})
}
