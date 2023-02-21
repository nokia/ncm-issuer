/*
Copyright 2022.

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

package main

import (
	"flag"
	"k8s.io/utils/clock"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	certmanagerv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/controllers"
	//+kubebuilder:scaffold:imports
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

var (
	scheme           = runtime.NewScheme()
	setupLog         = ctrl.Log.WithName("setup")
	NCMIssuerVersion = "1.0.3"
)

const setupErrMsg = "unable to create controller"

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(certmanagerv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
	utilruntime.Must(cmapi.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info(
		"starting",
		"version", NCMIssuerVersion,
		"enable-leader-election", enableLeaderElection,
		"metrics-addr", metricsAddr,
	)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b84bc1d2.ncm.nokia.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.IssuerReconciler{
		Kind:     "ClusterIssuer",
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Clock:    clock.RealClock{},
		Recorder: mgr.GetEventRecorderFor("external-clusterIssuer-controller"),
		Log:      ctrl.Log.WithName("controllers").WithName("ClusterIssuer"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "ClusterIssuer")
		os.Exit(1)
	} else {
		setupLog.Info("Successfully for clusterissuer")
	}

	if err = (&controllers.IssuerReconciler{
		Kind:     "Issuer",
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Clock:    clock.RealClock{},
		Recorder: mgr.GetEventRecorderFor("external-issuer-controller"),
		Log:      ctrl.Log.WithName("controllers").WithName("Issuer"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "Issuer")
		os.Exit(1)
	}

	if err = (&controllers.CertificateRequestReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		Clock:    clock.RealClock{},
		Recorder: mgr.GetEventRecorderFor("certificateRequests-controller"),
		Scheme:   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "CertificateRequest")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
