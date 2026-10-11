package cluster

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func int32ptr(v int32) *int32 { return &v }

func TestServiceSelectorExposesDifferentNamedService(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "frontend",
				Namespace: "default",
				Labels:    map[string]string{"blastguard.io/critical": "true"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32ptr(2),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "frontend"}},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					},
				},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 2},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "internal-worker", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32ptr(1),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "internal-worker"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "internal-worker"}},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "nginx:1.27"}},
					},
				},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
		// Service name intentionally differs from deployment name.
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "public-edge", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeLoadBalancer,
				Selector: map[string]string{"app": "frontend"},
				Ports:    []corev1.ServicePort{{Port: 80}},
			},
		},
	)

	sc := NewScannerWithClient(cs, "blastguard.io/critical")
	wls, err := sc.ScanCluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var frontend, worker *struct {
		exposed, reachable, critical bool
	}
	for _, w := range wls {
		switch w.Name {
		case "frontend":
			frontend = &struct {
				exposed, reachable, critical bool
			}{w.InternetExposed, w.ReachablePath, w.Critical}
		case "internal-worker":
			worker = &struct {
				exposed, reachable, critical bool
			}{w.InternetExposed, w.ReachablePath, w.Critical}
		}
	}
	if frontend == nil || !frontend.exposed {
		t.Fatalf("frontend should be exposed via selector-matched Service, got %+v workloads=%v", frontend, wls)
	}
	if !frontend.reachable {
		t.Fatal("without NetworkPolicy, exposed frontend should be reachable")
	}
	if !frontend.critical {
		t.Fatal("frontend should be critical via label")
	}
	if worker == nil || worker.exposed {
		t.Fatalf("internal-worker must not be exposed, got %+v", worker)
	}
}

func TestDefaultDenyNetworkPolicySeparatesReachability(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "locked"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32ptr(1),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1"}}},
				},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "api-svc", Namespace: "locked"},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeLoadBalancer,
				Selector: map[string]string{"app": "api"},
				Ports:    []corev1.ServicePort{{Port: 80}},
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "locked"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     nil, // deny all ingress
			},
		},
	)

	sc := NewScannerWithClient(cs, "")
	wls, err := sc.ScanCluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(wls) != 1 {
		t.Fatalf("want 1 workload, got %d", len(wls))
	}
	if !wls[0].InternetExposed {
		t.Fatal("expected internet exposed")
	}
	if wls[0].ReachablePath {
		t.Fatal("default-deny namespace must set ReachablePath=false")
	}
}

func TestIngressBackendMarksServiceExposed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32ptr(1),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "web:1"}}},
				},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web-svc", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: map[string]string{"app": "web"},
				Ports:    []corev1.ServicePort{{Port: 80}},
			},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "web-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{Name: "web-svc"},
								},
							}},
						},
					},
				}},
			},
		},
	)

	sc := NewScannerWithClient(cs, "")
	wls, err := sc.ScanCluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(wls) != 1 || !wls[0].InternetExposed {
		t.Fatalf("Ingress backend should expose web, got %+v", wls)
	}
}
