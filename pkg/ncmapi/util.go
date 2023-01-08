package ncmapi

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"os"
)

// Generates a random UUID according to RFC 4122
func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// Writes PEM to temp file (dirprefix is dir prefix)
func WritePemToTempFile(dirprefix string, pem []byte) (string, error) {
	myuuid, err := newUUID()
	if err != nil {
		return "", err
	}

	// path := "/tmp/ncm_new.pem"
	path := dirprefix + myuuid + ".pem"

	// write CSRPEM into csrfile
	csrfile, err := os.Create(path)
	if err != nil {
		// return nil, err, "no such file"
		return path, err
	}
	_, err = csrfile.Write(pem)
	if err != nil {
		// return nil, err, "err to write file"
		return path, err
	}
	csrfile.Sync()
	csrfile.Close()

	return path, err
}

func GetPathFromCertURL(certURL string) (string, error) {
	parsedURL, err := url.Parse(certURL)
	if err != nil {
		return "", fmt.Errorf("cannot parsed given URL: url=%s", certURL)
	}

	return parsedURL.Path, nil
}
