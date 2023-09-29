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

package ncmapi

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExternalClient interface {
	GetCAs() (*CAsResponse, error)
	GetCA(path string) (*CAResponse, error)
	SendCSR(pem []byte, CA *CAResponse, profileID string) (*CSRResponse, error)
	CheckCSRStatus(path string) (*CSRStatusResponse, error)
	DownloadCertificate(path string) (*CertificateDownloadResponse, error)
	DownloadCertificateInPEM(path string) ([]byte, error)
	RenewCertificate(path string, duration *metav1.Duration, profileID string) (*RenewCertificateResponse, error)
	StartHealthChecker(interval time.Duration)
	StopHealthChecker()
}
