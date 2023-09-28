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
