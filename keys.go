package sbctl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"golang.org/x/sys/unix"
)

var (
	MicrosoftKEKHash = []byte{0xa1, 0x11, 0x7f, 0x51, 0x6a, 0x32, 0xce, 0xfc, 0xba, 0x3f, 0x2d,
		0x1a, 0xce, 0x10, 0xa8, 0x79, 0x72, 0xfd, 0x6b, 0xbe, 0x8f, 0xe0, 0xd0,
		0xb9, 0x96, 0xe0, 0x9e, 0x65, 0xd8, 0x02, 0xa5, 0x03}
	MicrosoftDBProduction = []byte{0xe8, 0xe9, 0x5f, 0x07, 0x33, 0xa5, 0x5e, 0x8b, 0xad, 0x7b, 0xe0, 0xa1,
		0x41, 0x3e, 0xe2, 0x3c, 0x51, 0xfc, 0xea, 0x64, 0xb3, 0xc8, 0xfa,
		0x6a, 0x78, 0x69, 0x35, 0xfd, 0xdc, 0xc7, 0x19, 0x61}
	MicrosoftDBUEFI = []byte{0x48, 0xe9, 0x9b, 0x99, 0x1f, 0x57, 0xfc, 0x52, 0xf7, 0x61, 0x49, 0x59,
		0x9b, 0xff, 0x0a, 0x58, 0xc4, 0x71, 0x54, 0x22, 0x9b, 0x9f, 0x8d,
		0x60, 0x3a, 0xc4, 0x0d, 0x35, 0x00, 0x24, 0x85, 0x07}
)

var RSAKeySize = 4096

var (
	DatabasePath = "/usr/share/secureboot/"
	KeysPath     = filepath.Join(DatabasePath, "keys")
	PKKey        = filepath.Join(KeysPath, "PK", "PK.key")
	PKCert       = filepath.Join(KeysPath, "PK", "PK.pem")
	KEKKey       = filepath.Join(KeysPath, "KEK", "KEK.key")
	KEKCert      = filepath.Join(KeysPath, "KEK", "KEK.pem")
	DBKey        = filepath.Join(KeysPath, "db", "db.key")
	DBCert       = filepath.Join(KeysPath, "db", "db.pem")
	DBXKey       = filepath.Join(KeysPath, "dbx", "dbx.key")
	DBXCert      = filepath.Join(KeysPath, "dbx", "dbx.pem")

	DBPath  = filepath.Join(DatabasePath, "files.db")
	DBXPath = filepath.Join(DatabasePath, "files.dbx")

	GUIDPath = filepath.Join(DatabasePath, "GUID")
)

// Check if we can access the db certificate to verify files
func CanVerifyFiles() error {
	if err := unix.Access(DBCert, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", DBCert, err)
	}
	if err := unix.Access(DBXCert, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", DBXCert, err)
	}
	return nil
}

func CreateKey(name string) ([]byte, []byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			Country:    []string{name},
			CommonName: name,
		},
	}
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to key: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to certificate: %v", err)
	}
	return keyOut.Bytes(), certOut.Bytes(), nil
}

func SaveKey(k []byte, file string) error {
	os.MkdirAll(filepath.Dir(file), os.ModePerm)
	err := os.WriteFile(file, k, 0400)
	if err != nil {
		return err
	}
	return nil
}

func ExportKeys(outputDir string) error {
	pkList, err := efi.GetPK()
	if err != nil {
		return err
	}
	for it, e := range pkList {
		if e.SignatureType == signature.CERT_X509_GUID {
			path := filepath.Join(outputDir, "PK_"+fmt.Sprintf("%d", it)+".pem")
			ioutil.WriteFile(path, e.Signatures[0].Data, 0644)
		}
	}
	kekList, err := efi.GetKEK()
	if err != nil {
		return err
	}
	for it, e := range kekList {
		if e.SignatureType == signature.CERT_X509_GUID {
			path := filepath.Join(outputDir, "KEK_"+fmt.Sprintf("%d", it)+".pem")
			ioutil.WriteFile(path, e.Signatures[0].Data, 0644)
		}
	}
	dbList, err := efi.Getdb()
	if err != nil {
		return err
	}
	for it, e := range dbList {
		if e.SignatureType == signature.CERT_X509_GUID {
			path := filepath.Join(outputDir, "DB_"+fmt.Sprintf("%d", it)+".pem")
			ioutil.WriteFile(path, e.Signatures[0].Data, 0644)
		}
	}
	return nil
}

func Enroll(uuid util.EFIGUID, cert, signerKey, signerPem []byte, efivar string) error {
	c := signature.NewSignatureList(signature.CERT_X509_GUID)
	c.AppendBytes(uuid, cert)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	key, err := util.ReadKey(signerKey)
	if err != nil {
		return nil
	}
	crt, err := util.ReadCert(signerPem)
	if err != nil {
		return nil
	}
	signedBuf, err := efi.SignEFIVariable(key, crt, efivar, buf.Bytes())
	if err != nil {
		return err
	}
	return efi.WriteEFIVariable(efivar, signedBuf)
}

func EnrollDatabase(list []*signature.SignatureList, signerKey, signerPem []byte, efivar string) error {
	d := signature.SignatureDatabase{}
	for _, e := range list {
		d.AppendList(e)
	}
	buf := new(bytes.Buffer)
	signature.WriteSignatureDatabase(buf, d)
	key, err := util.ReadKey(signerKey)
	if err != nil {
		return nil
	}
	crt, err := util.ReadCert(signerPem)
	if err != nil {
		return nil
	}
	signedBuf, err := efi.SignEFIVariable(key, crt, efivar, buf.Bytes())
	if err != nil {
		return err
	}
	return efi.WriteEFIVariable(efivar, signedBuf)
}

func UpdateDBX(guid util.EFIGUID, keydir string) error {
	KEKKey, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.key"))
	KEKPem, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.pem"))
	dbxPem, err := os.ReadFile(filepath.Join(keydir, "dbx", "dbx.pem"))
	if err != nil {
		return err
	}
	if err := Enroll(guid, dbxPem, KEKKey, KEKPem, "dbx"); err != nil {
		return err
	}
	return nil
}

func KeySync(guid util.EFIGUID, keydir string, msKEK bool) error {
	PKKey, _ := os.ReadFile(filepath.Join(keydir, "PK", "PK.key"))
	PKPem, _ := os.ReadFile(filepath.Join(keydir, "PK", "PK.pem"))
	KEKKey, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.key"))
	KEKPem, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.pem"))
	MSKEKPem, _ := os.ReadFile(filepath.Join(keydir, "MSKEK", "KEK.pem"))
	MSDB1Pem, _ := os.ReadFile(filepath.Join(keydir, "MSDB", "DB1.pem"))
	MSDB2Pem, _ := os.ReadFile(filepath.Join(keydir, "MSDB", "DB2.pem"))
	dbPem, _ := os.ReadFile(filepath.Join(keydir, "db", "db.pem"))
	dbxPem, _ := os.ReadFile(filepath.Join(keydir, "dbx", "dbx.pem"))
	if msKEK {
		dbList := make([]*signature.SignatureList, 3)
		dbList[0] = signature.NewSignatureList(signature.CERT_X509_GUID)
		dbList[1] = signature.NewSignatureList(signature.CERT_X509_GUID)
		dbList[2] = signature.NewSignatureList(signature.CERT_X509_GUID)
		dbList[0].AppendBytes(guid, dbPem)
		dbList[1].AppendBytes(guid, MSDB1Pem)
		dbList[2].AppendBytes(guid, MSDB2Pem)
		if err := EnrollDatabase(dbList, KEKKey, KEKPem, "db"); err != nil {
			return err
		}
		kekList := make([]*signature.SignatureList, 2)
		kekList[0] = signature.NewSignatureList(signature.CERT_X509_GUID)
		kekList[1] = signature.NewSignatureList(signature.CERT_X509_GUID)
		kekList[0].AppendBytes(guid, KEKPem)
		kekList[1].AppendBytes(guid, MSKEKPem)
		if err := EnrollDatabase(kekList, PKKey, PKPem, "KEK"); err != nil {
			return err
		}
	} else {
		if err := Enroll(guid, dbPem, KEKKey, KEKPem, "db"); err != nil {
			return err
		}
		if err := Enroll(guid, KEKPem, PKKey, PKPem, "KEK"); err != nil {
			return err
		}
	}
	if err := Enroll(guid, dbxPem, KEKKey, KEKPem, "dbx"); err != nil {
		return err
	}
	if err := Enroll(guid, PKPem, PKKey, PKPem, "PK"); err != nil {
		return err
	}
	return nil
}

func VerifyFile(cert, file string) (bool, error) {
	if err := unix.Access(cert, unix.R_OK); err != nil {
		return false, fmt.Errorf("couldn't access %s: %w", cert, err)
	}

	peFile, err := os.ReadFile(file)
	if err != nil {
		return false, err
	}

	x509Cert, err := util.ReadCertFromFile(cert)
	if err != nil {
		return false, err
	}
	sigs, err := pecoff.GetSignatures(peFile)
	if err != nil {
		return false, err
	}
	if len(sigs) == 0 {
		return false, nil
	}
	for _, signature := range sigs {
		ok, err := pkcs7.VerifySignature(x509Cert, signature.Certificate)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	// If we come this far we haven't found a signature that matches the cert
	return false, nil
}

var ErrAlreadySigned = errors.New("already signed file")

func SignFile(key, cert, file, output, checksum string) error {

	// Check file exists before we do anything
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", file)
	}

	// Let's check if we have signed it already AND the original file hasn't changed
	ok, err := VerifyFile(cert, output)
	if errors.Is(err, os.ErrNotExist) && (file != output) {
		// if the file does not exist and file is not the same as output
		// then we just catch the error and continue. This is expected
		// behaviour
	} else if err != nil {
		return err
	}

	chk, err := ChecksumFile(file)
	if err != nil {
		return err
	}
	if ok && chk == checksum {
		return ErrAlreadySigned
	}

	// Let's also check if we can access the key
	if err := unix.Access(key, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", key, err)
	}

	// We want to write the file back with correct permissions
	si, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("failed signing file: %w", err)
	}

	peFile, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	Cert, err := util.ReadCertFromFile(cert)
	if err != nil {
		return err
	}
	Key, err := util.ReadKeyFromFile(key)
	if err != nil {
		return err
	}

	ctx := pecoff.PECOFFChecksum(peFile)

	sig, err := pecoff.CreateSignature(ctx, Cert, Key)
	if err != nil {
		return err
	}

	b, err := pecoff.AppendToBinary(ctx, sig)
	if err != nil {
		return err
	}
	if err = os.WriteFile(output, b, si.Mode()); err != nil {
		return err
	}

	return nil
}

// Map up our default keys in a struct
var SecureBootKeys = []struct {
	Key         string
	Description string
}{
	{
		Key:         "PK",
		Description: "Platform Key",
	},
	{
		Key:         "KEK",
		Description: "Key Exchange Key",
	},
	{
		Key:         "db",
		Description: "Database Key",
	},
	{
		Key:         "dbx",
		Description: "Forbidden Database Key",
	},
}

// Check if we have already intialized keys in the given output directory
func CheckIfKeysInitialized(output string) bool {
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, key.Key)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// Initialize the secure boot keys needed to setup secure boot.
// It creates the following keys:
//	* Platform Key (PK)
//	* Key Exchange Key (KEK)
//	* db (database)
//	* dbx (database)
func InitializeSecureBootKeys(output string) error {
	if CheckIfKeysInitialized(output) {
		return nil
	}
	for _, key := range SecureBootKeys {
		keyfile, cert, err := CreateKey(key.Description)
		if err != nil {
			return err
		}
		path := filepath.Join(output, key.Key)
		SaveKey(keyfile, filepath.Join(path, fmt.Sprintf("%s.key", key.Key)))
		SaveKey(cert, filepath.Join(path, fmt.Sprintf("%s.pem", key.Key)))
	}
	return nil
}
