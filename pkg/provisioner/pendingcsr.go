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

package provisioner

import (
	"sync"
)

// PendingCSR stores pending CSR href and "checked" which means
// how many times CSRStatusPending was encountered when checking
// CSR status in NCM.
type PendingCSR struct {
	href    string
	checked int
}

// PendingCSRsMap stores pending CSRs which have not yet been accepted by NCM
// as key-value pair where key is composed of namespace + certificate name
// (e.g. ncm-issuer-ns.example-certificate) and value is PendingCSR.
type PendingCSRsMap struct {
	pendingCSRs map[string]*PendingCSR
	mu          sync.RWMutex
}

func (cm *PendingCSRsMap) Add(namespace, certName, href string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if _, ok := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]; !ok {
		cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)] = &PendingCSR{href: href, checked: 1}
	}
}

func (cm *PendingCSRsMap) Has(namespace, certName string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	_, ok := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]
	return ok
}

func (cm *PendingCSRsMap) Get(namespace, certName string) *PendingCSR {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	pendingCSR := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]
	return pendingCSR
}

// Load seeds a pending CSR from externally persisted state, keeping any fresher in-memory entry so a rehydration never lowers the check counter.
func (cm *PendingCSRsMap) Load(namespace, certName, href string, checked int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	key := prepareCSRsMapKey(namespace, certName)
	if _, ok := cm.pendingCSRs[key]; ok {
		return
	}
	if checked < 1 {
		checked = 1
	}
	cm.pendingCSRs[key] = &PendingCSR{href: href, checked: checked}
}

// GetState returns the stored href and check counter for a pending CSR together with whether an entry exists.
func (cm *PendingCSRsMap) GetState(namespace, certName string) (string, int, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if pendingCSR, ok := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]; ok {
		return pendingCSR.href, pendingCSR.checked, true
	}
	return "", 0, false
}

func (cm *PendingCSRsMap) Increment(namespace, certName string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	pendingCSR := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]
	pendingCSR.checked++
}

func (cm *PendingCSRsMap) ResetCheckCounter(namespace, certName string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	pendingCSR := cm.pendingCSRs[prepareCSRsMapKey(namespace, certName)]
	pendingCSR.checked = 1
}

func (cm *PendingCSRsMap) Delete(namespace, certName string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.pendingCSRs, prepareCSRsMapKey(namespace, certName))
}
