package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Scanner struct {
	clientset *kubernetes.Clientset
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
	
	return &Scanner{clientset: clientset}, nil
}

func (s *Scanner) ScanCluster(ctx context.Context) ([]graph.Workload, error) {
	deployments, err := s.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}
	
	services, err := s.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	
	ingresses, err := s.clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ingresses: %w", err)
	}
	
	exposedServices := s.findExposedServices(services.Items, ingresses.Items)
	
	var workloads []graph.Workload
	for _, dep := range deployments.Items {
		image := ""
		if len(dep.Spec.Template.Spec.Containers) > 0 {
			image = dep.Spec.Template.Spec.Containers[0].Image
		}
		
		replicas := int32(1)
		if dep.Spec.Replicas != nil {
			replicas = *dep.Spec.Replicas
		}
		
		running := replicas > 0 && dep.Status.ReadyReplicas > 0
		internetExposed := s.isDeploymentExposed(dep, exposedServices)
		critical := s.isCritical(dep)
		
		workloads = append(workloads, graph.Workload{
			Name:            dep.Name,
			Namespace:       dep.Namespace,
			Image:           image,
			Replicas:        int(replicas),
			Critical:        critical,
			InternetExposed: internetExposed,
			ReachablePath:   internetExposed,
			Running:         running,
		})
	}
	
	return workloads, nil
}

func (s *Scanner) findExposedServices(services []corev1.Service, ingresses []networkingv1.Ingress) map[string]bool {
	exposed := make(map[string]bool)
	
	for _, svc := range services {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
			key := svc.Namespace + "/" + svc.Name
			exposed[key] = true
		}
	}
	
	for _, ing := range ingresses {
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil {
						key := ing.Namespace + "/" + path.Backend.Service.Name
						exposed[key] = true
					}
				}
			}
		}
	}
	
	return exposed
}

func (s *Scanner) isDeploymentExposed(dep appsv1.Deployment, exposedServices map[string]bool) bool {
	key := dep.Namespace + "/" + dep.Name
	return exposedServices[key]
}

func (s *Scanner) isCritical(dep appsv1.Deployment) bool {
	criticalKeywords := []string{"payment", "auth", "api", "prod", "production"}
	
	name := strings.ToLower(dep.Name)
	namespace := strings.ToLower(dep.Namespace)
	
	for _, keyword := range criticalKeywords {
		if strings.Contains(name, keyword) || strings.Contains(namespace, keyword) {
			return true
		}
	}
	
	if dep.Labels != nil {
		if critical, ok := dep.Labels["blastguard.io/critical"]; ok && critical == "true" {
			return true
		}
	}
	
	return false
}
