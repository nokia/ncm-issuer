/*
Copyright 2025 Nokia

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
	"os"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/controllers"
	"github.com/nokia/ncm-issuer/pkg/provisioner"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme       = runtime.NewScheme()
	setupLog     = ctrl.Log.WithName("setup")
	chartVersion = "1.1.4"
	imageVersion = "1.1.4"
)

const (
	webhookPort = 9443
	setupErrMsg = "unable to create controller"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ncmv1.AddToScheme(scheme))
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

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info(
		"starting",
		"chart-version", chartVersion,
		"image-version", imageVersion,
		"replica-count", os.Getenv("REP_COUNT"),
		"enable-leader-election", enableLeaderElection,
		"metrics-addr", metricsAddr,
	)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr, // ":8080"
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b84bc1d2.ncm.nokia.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	provisioners := provisioner.NewProvisionersMap()
	if err = (&controllers.IssuerReconciler{
		Kind:         "ClusterIssuer",
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Clock:        clock.RealClock{},
		Recorder:     mgr.GetEventRecorderFor("clusterissuer-controller"),
		Provisioners: provisioners,
		Log:          ctrl.Log.WithName("controllers").WithName("ClusterIssuer"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "ClusterIssuer")
		os.Exit(1)
	}

	if err = (&controllers.IssuerReconciler{
		Kind:         "Issuer",
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Clock:        clock.RealClock{},
		Recorder:     mgr.GetEventRecorderFor("issuer-controller"),
		Provisioners: provisioners,
		Log:          ctrl.Log.WithName("controllers").WithName("Issuer"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "Issuer")
		os.Exit(1)
	}

	if err = (&controllers.CertificateRequestReconciler{
		Client:       mgr.GetClient(),
		Log:          ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		Clock:        clock.RealClock{},
		Recorder:     mgr.GetEventRecorderFor("certificaterequest-controller"),
		Provisioners: provisioners,
		Scheme:       mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, setupErrMsg, "controller", "CertificateRequest")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
