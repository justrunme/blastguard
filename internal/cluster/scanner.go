package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Exposure vs reachability
//
// InternetExposed means a Service that selects the workload is reachable from
// outside the cluster path (LoadBalancer, NodePort, or Ingress/Gateway backend).
//
// ReachablePath is separate: in a namespace with a default-deny NetworkPolicy
// (policyTypes includes Ingress and no rule selects the pods), internet exposure
// does not imply a live path — ReachablePath stays false unless an allow policy
// selects the pod template. Namespaces without NetworkPolicies treat exposure
// as reachable (cluster default-allow).

type Scanner struct {
	clientset     kubernetes.Interface
	criticalLabel string
}

func NewScanner(kubeconfig string) (*Scanner, error) {
	var config *rest.Config
	var err error

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}

	configOverrides := &clientcmd.ConfigOverrides{}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err = clientConfig.ClientConfig()
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig or in-cluster: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return NewScannerWithClient(clientset, "blastguard.io/critical"), nil
}

// NewScannerWithClient builds a Scanner for tests (fake clientset).
func NewScannerWithClient(cs kubernetes.Interface, criticalLabel string) *Scanner {
	if criticalLabel == "" {
		criticalLabel = "blastguard.io/critical"
	}
	return &Scanner{clientset: cs, criticalLabel: criticalLabel}
}

func (s *Scanner) ScanCluster(ctx context.Context) ([]graph.Workload, error) {
	services, err := s.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	ingresses, err := s.clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ingresses: %w", err)
	}
	netpols, err := s.clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list networkpolicies: %w", err)
	}

	exposed := s.findExposedServiceKeys(services.Items, ingresses.Items)
	npByNS := indexNetworkPolicies(netpols.Items)

	var workloads []graph.Workload

	deployments, err := s.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}
	for _, dep := range deployments.Items {
		workloads = append(workloads, s.workloadsFromPodTemplate(
			dep.Name, dep.Namespace, dep.Labels,
			dep.Spec.Template.Labels, dep.Spec.Template.Spec,
			replicasOr(dep.Spec.Replicas, 1), int(dep.Status.ReadyReplicas),
			services.Items, exposed, npByNS[dep.Namespace],
		)...)
	}

	statefulSets, err := s.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}
	for _, ss := range statefulSets.Items {
		workloads = append(workloads, s.workloadsFromPodTemplate(
			ss.Name, ss.Namespace, ss.Labels,
			ss.Spec.Template.Labels, ss.Spec.Template.Spec,
			replicasOr(ss.Spec.Replicas, 1), int(ss.Status.ReadyReplicas),
			services.Items, exposed, npByNS[ss.Namespace],
		)...)
	}

	daemonSets, err := s.clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}
	for _, ds := range daemonSets.Items {
		workloads = append(workloads, s.workloadsFromPodTemplate(
			ds.Name, ds.Namespace, ds.Labels,
			ds.Spec.Template.Labels, ds.Spec.Template.Spec,
			int32(ds.Status.DesiredNumberScheduled), int(ds.Status.NumberReady),
			services.Items, exposed, npByNS[ds.Namespace],
		)...)
	}

	cronJobs, err := s.clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cronjobs: %w", err)
	}
	for _, cj := range cronJobs.Items {
		tpl := cj.Spec.JobTemplate.Spec.Template
		workloads = append(workloads, s.workloadsFromPodTemplate(
			cj.Name, cj.Namespace, cj.Labels,
			tpl.Labels, tpl.Spec,
			1, 0,
			services.Items, exposed, npByNS[cj.Namespace],
		)...)
	}

	// Attach image digests from running pods when available.
	s.attachImageIDs(ctx, workloads)

	return workloads, nil
}

func (s *Scanner) workloadsFromPodTemplate(
	name, namespace string,
	objLabels, podLabels map[string]string,
	podSpec corev1.PodSpec,
	replicas int32, ready int,
	services []corev1.Service,
	exposed map[string]bool,
	netpols []networkingv1.NetworkPolicy,
) []graph.Workload {
	images := containerImages(podSpec)
	if len(images) == 0 {
		images = []string{""}
	}
	internet := s.isExposedBySelector(namespace, podLabels, services, exposed)
	reachable := computeReachable(internet, podLabels, netpols)
	critical := s.isCritical(objLabels, podLabels, name, namespace)
	running := replicas > 0 && ready > 0

	out := make([]graph.Workload, 0, len(images))
	for i, img := range images {
		wlName := name
		if i > 0 {
			wlName = fmt.Sprintf("%s:%s", name, imageShort(img))
		}
		out = append(out, graph.Workload{
			Name:            wlName,
			Namespace:       namespace,
			Image:           img,
			Replicas:        int(replicas),
			Critical:        critical,
			InternetExposed: internet,
			ReachablePath:   reachable,
			Running:         running,
		})
	}
	return out
}

func containerImages(spec corev1.PodSpec) []string {
	var imgs []string
	seen := map[string]bool{}
	add := func(list []corev1.Container) {
		for _, c := range list {
			if c.Image == "" || seen[c.Image] {
				continue
			}
			seen[c.Image] = true
			imgs = append(imgs, c.Image)
		}
	}
	add(spec.InitContainers)
	add(spec.Containers)
	return imgs
}

func imageShort(ref string) string {
	n := graph.ImageName(ref)
	if n == "" {
		return "container"
	}
	return n
}

func replicasOr(p *int32, def int32) int32 {
	if p == nil {
		return def
	}
	return *p
}

// findExposedServiceKeys marks namespace/name for Services that are externally
// reachable (LB/NodePort) or referenced by an Ingress backend.
func (s *Scanner) findExposedServiceKeys(services []corev1.Service, ingresses []networkingv1.Ingress) map[string]bool {
	exposed := make(map[string]bool)

	for _, svc := range services {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
			exposed[svc.Namespace+"/"+svc.Name] = true
		}
	}

	for _, ing := range ingresses {
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			exposed[ing.Namespace+"/"+ing.Spec.DefaultBackend.Service.Name] = true
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					exposed[ing.Namespace+"/"+path.Backend.Service.Name] = true
				}
			}
		}
	}
	return exposed
}

// isExposedBySelector returns true when an exposed Service's selector matches
// the workload pod template labels (not by Service name == Deployment name).
func (s *Scanner) isExposedBySelector(namespace string, podLabels map[string]string, services []corev1.Service, exposed map[string]bool) bool {
	for _, svc := range services {
		if svc.Namespace != namespace {
			continue
		}
		if !exposed[svc.Namespace+"/"+svc.Name] {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		sel := labels.Set(svc.Spec.Selector).AsSelector()
		if sel.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}

func indexNetworkPolicies(items []networkingv1.NetworkPolicy) map[string][]networkingv1.NetworkPolicy {
	out := make(map[string][]networkingv1.NetworkPolicy)
	for _, np := range items {
		out[np.Namespace] = append(out[np.Namespace], np)
	}
	return out
}

// computeReachable separates exposure from path liveness under NetworkPolicy.
func computeReachable(internetExposed bool, podLabels map[string]string, netpols []networkingv1.NetworkPolicy) bool {
	if !internetExposed {
		return false
	}
	if len(netpols) == 0 {
		// Cluster default-allow: exposure implies reachable.
		return true
	}

	defaultDeny := false
	allowed := false
	for _, np := range netpols {
		if !appliesIngress(np) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		matchesAll := len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0
		matchesPod := matchesAll || sel.Matches(labels.Set(podLabels))
		if !matchesPod {
			continue
		}
		if len(np.Spec.Ingress) == 0 {
			// Empty ingress list on an Ingress-typed policy = deny all to selected pods.
			defaultDeny = true
			continue
		}
		allowed = true
	}
	if defaultDeny && !allowed {
		return false
	}
	return true
}

func appliesIngress(np networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		// Per Kubernetes: if ingress rules present (or neither), Ingress is implied.
		return true
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func (s *Scanner) isCritical(objLabels, podLabels map[string]string, name, namespace string) bool {
	if objLabels != nil && objLabels[s.criticalLabel] == "true" {
		return true
	}
	if podLabels != nil && podLabels[s.criticalLabel] == "true" {
		return true
	}
	// Optional annotation on the object.
	_ = name
	_ = namespace
	return false
}

func (s *Scanner) attachImageIDs(ctx context.Context, workloads []graph.Workload) {
	pods, err := s.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for _, pod := range pods.Items {
		app := pod.Labels["app"]
		if app == "" {
			app = pod.Labels["app.kubernetes.io/name"]
		}
		for i := range workloads {
			w := &workloads[i]
			if w.Namespace != pod.Namespace {
				continue
			}
			base := strings.Split(w.Name, ":")[0]
			if base != app && !strings.HasPrefix(pod.Name, base+"-") {
				continue
			}
			for _, cs := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
				if cs.ImageID == "" {
					continue
				}
				if cs.Image == w.Image || graph.ImagesMatch(cs.Image, w.Image) {
					w.ImageID = cs.ImageID
				}
			}
		}
	}
}
