package util

import (
	"os"
)

// WritePEMToTempFile writes PEM to temporary file.
func WritePEMToTempFile(pem []byte) (string, error) {
	csrFile, err := os.CreateTemp("", "*.pem")
	if err != nil {
		return "", err
	}

	defer csrFile.Close()
	path := csrFile.Name()

	if _, err = csrFile.Write(pem); err != nil {
		return path, err
	}

	if err = csrFile.Sync(); err != nil {
		return path, err
	}

	return path, err
}
