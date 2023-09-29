/*
Copyright 2023 Nokia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
