// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package render

import (
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	TyphaServiceName              = "calico-typha"
	TyphaPortName                 = "calico-typha"
	TyphaK8sAppName               = "calico-typha"
	TyphaServiceAccountName       = "calico-typha"
	AppLabelName                  = "k8s-app"
	TyphaPort               int32 = 5473
	TyphaMetricsName              = "calico-typha-metrics"

	TyphaContainerName = "calico-typha"

	TyphaNonClusterHostSuffix            = "-noncluster-host"
	TyphaNonClusterHostNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "typha-noncluster-host-access"

	defaultTyphaTerminationGracePeriod = 300
	shutdownTimeoutEnvVar              = "TYPHA_SHUTDOWNTIMEOUTSECS"

	// TyphaLeaderServiceName is the headless Service that the elected leader Typha pod
	// exposes so that follower Typhas can discover their upstream. The leader applies the
	// label projectcalico.org/typha-role: leader to itself, and this Service selects on
	// that label. Only rendered when hierarchical mode is enabled.
	TyphaLeaderServiceName     = "calico-typha-leader"
	TyphaLeaderServicePortName = "calico-typha"

	// TyphaRoleLabelKey is the pod label the elected leader applies to itself to be
	// discoverable via TyphaLeaderServiceName.
	TyphaRoleLabelKey   = "projectcalico.org/typha-role"
	TyphaRoleLabelValue = "leader"

	// TyphaTierLabelKey is the pod label applied to all Typha pods to indicate which
	// tier they belong to in hierarchical mode.
	TyphaTierLabelKey = "projectcalico.org/typha-tier"

	// TyphaTier1ServiceName is the headless Service that exposes Tier-1 Typha pods.
	// Tier-2 followers DNS-resolve this Service to discover their upstream Typhas.
	// Only rendered when hierarchical mode is enabled.
	TyphaTier1ServiceName = "calico-typha-tier1"

	// TyphaHierarchyRoleName is the namespaced Role granting hierarchy-specific RBAC
	// (leases + pod self-labelling). Rendered only when HierarchyEnabled is true.
	TyphaHierarchyRoleName = "calico-typha-hierarchy"

	// TyphaTLSClientSecretName is the Secret holding the typha-client keypair.  Typha
	// uses this when it dials an upstream Typha in hierarchical mode.  It is a
	// distinct Secret from node-certs (same CN is fine; sharing the private key
	// between components is not).
	TyphaTLSClientSecretName = "typha-client-certs"
)

var (
	TyphaTLSSecretName               = "typha-certs"
	TyphaTLSSecretNameNonClusterHost = TyphaTLSSecretName + TyphaNonClusterHostSuffix

	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
)

// TyphaConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/typha on a cluster.
type TyphaConfiguration struct {
	K8sServiceEp k8sapi.ServiceEndpoint

	// K8sServiceEpPodNetwork is used for pod-networked Typha (i.e. the non-cluster-host
	// deployment), where K8sServiceEp may be unreachable from pods.
	K8sServiceEpPodNetwork k8sapi.ServiceEndpoint

	Installation      *operatorv1.InstallationSpec
	TLS               *TyphaNodeTLS
	MigrateNamespaces bool
	ClusterDomain     string
	NonClusterHost    *operatorv1.NonClusterHost

	// The health port that Felix is bound to. We configure Typha to bind to the port
	// that is one less.
	FelixHealthPort int

	// HierarchyEnabled gates all hierarchical-Typha rendering.  When false (the
	// default), the rendered objects are byte-identical to the pre-hierarchy output so
	// that existing clusters are unaffected.  Sourced from
	// Installation.Spec.TyphaHierarchy.Enabled via core_controller.go.
	HierarchyEnabled bool

	// Tier1Count is the number of Tier-1 Typha replicas.  Only meaningful when
	// HierarchyEnabled is true.  Sourced from
	// Installation.Spec.TyphaHierarchy.Tier1Count.
	Tier1Count int32
}

// Typha creates the typha daemonset and other resources for the daemonset to operate normally.
func Typha(cfg *TyphaConfiguration) Component {
	return &typhaComponent{cfg: cfg}
}

type typhaComponent struct {
	// Given configuration.
	cfg *TyphaConfiguration

	// Generated internal config, built from the given configuration.
	calicoImage string
}

func (c *typhaComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *typhaComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *typhaComponent) Objects() ([]client.Object, []client.Object) {
	pdb := c.typhaPodDisruptionBudget()
	if overrides := c.cfg.Installation.TyphaPodDisruptionBudget; overrides != nil {
		rcomp.ApplyPodDisruptionBudgetOverrides(pdb, overrides)
	}
	objs := []client.Object{
		c.typhaServiceAccount(),
		c.typhaRole(),
		c.typhaRoleBinding(),
		pdb,
	}

	// When hierarchical mode is enabled, add the namespaced Role + RoleBinding for
	// leases/pod-patch RBAC, and the tier-discovery Services.
	if c.cfg.HierarchyEnabled {
		objs = append(objs,
			c.typhaHierarchyRole(),
			c.typhaHierarchyRoleBinding(),
		)
	}

	objs = append(objs, c.typhaServices()...)

	// Add deployment last, as it may depend on the creation of previous objects in the list.
	objs = append(objs, c.typhaDeployment()...)
	if c.cfg.Installation.TyphaMetricsPort != nil {
		objs = append(objs, c.typhaPrometheusService())
	}

	return objs, nil
}

func NewTyphaNonClusterHostPolicy(cfg *TyphaConfiguration) Component {
	return NewPassthrough(
		[]client.Object{typhaNonClusterHostCalicoSystemPolicy(cfg)},
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("typha-noncluster-host-access", common.CalicoNamespace),
		},
	)
}

func (c *typhaComponent) typhaPodDisruptionBudget() *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					AppLabelName: TyphaK8sAppName,
				},
			},
		},
	}
}

func (c *typhaComponent) Ready() bool {
	return true
}

// typhaServiceAccount creates the typha's service account.
func (c *typhaComponent) typhaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceAccountName,
			Namespace: common.CalicoNamespace,
		},
	}
}

// typhaRoleBinding creates a clusterrolebinding giving the typha service account the required permissions to operate.
func (c *typhaComponent) typhaRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-typha",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TyphaServiceAccountName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

// typhaRole creates the clusterrole containing policy rules that allow the typha deployment to operate normally.
func (c *typhaComponent) typhaRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Calico uses endpoint slices for service-based network policy rules.
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Some information is stored on the node status.
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				// For enforcing network policies.
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// For enforcing k8s cluster network policies.
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"watch", "list"},
			},
			{
				// Metadata from these are used in conjunction with network policy.
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// For monitoring Calico-specific configuration.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
					"bgpfilters",
					"blockaffinities",
					"caliconodestatuses",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"stagedglobalnetworkpolicies",
					"networkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"ipreservations",
					"networksets",
					"tiers",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// For migration code in calico/node startup only. Remove when the migration
				// code is removed from node.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Calico creates some configuration on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				// Calico creates some tiers on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"create"},
			},
			{
				// Calico monitors nodes for some networking configuration.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// But, we only need to be able to query for IPAM config.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"ipamconfigurations"},
				Verbs:     []string{"get"},
			},
			{
				// confd (and in some cases, felix) watches block affinities for route aggregation.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
			{
				// For monitoring KubeVirt live migration.
				APIGroups: []string{"kubevirt.io"},
				Resources: []string{"virtualmachineinstancemigrations"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		extraRules := []rbacv1.PolicyRule{
			{
				// Tigera Secure needs to be able to read licenses, and config.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bfdconfigurations",
					"deeppacketinspections",
					"egressgatewaypolicies",
					"externalnetworks",
					"licensekeys",
					"networks",
					"packetcaptures",
					"remoteclusterconfigurations",
				},
				Verbs: []string{"get", "list", "watch"},
			},
		}
		role.Rules = append(role.Rules, extraRules...)
	}
	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}
	return role
}

// typhaLeaseResourceNames returns the names of all Kubernetes Lease objects that Typha
// creates and manages in hierarchical mode: one for leader election plus one per Tier-1
// pod for tier assignment.  These are used to tighten the RBAC get/update rule.
func (c *typhaComponent) typhaLeaseResourceNames() []string {
	names := []string{"calico-typha-leader"}
	for i := int32(0); i < c.cfg.Tier1Count; i++ {
		names = append(names, fmt.Sprintf("calico-typha-tier1-%d", i))
	}
	return names
}

// typhaHierarchyRole creates a namespaced Role in calico-system granting typha the
// additional permissions required for hierarchical mode:
//   - coordination.k8s.io leases: leader election and tier assignment (get/create/update;
//     create cannot be scoped to a resource name, so it is left unscoped).
//   - core pods patch: self-labelling so the leader and tier-1 pods are discoverable via
//     their headless Services (cannot be name-scoped by the API).
//
// Using a namespaced Role rather than widening the ClusterRole follows the principle
// of least privilege: these permissions are only needed within calico-system.
func (c *typhaComponent) typhaHierarchyRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaHierarchyRoleName,
			Namespace: common.CalicoNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Leader election and tier assignment: get and update can be scoped to
				// the known lease names; create cannot be resource-name-scoped (API
				// limitation).
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups:     []string{"coordination.k8s.io"},
				Resources:     []string{"leases"},
				Verbs:         []string{"get", "update"},
				ResourceNames: c.typhaLeaseResourceNames(),
			},
			{
				// Self-labelling: the elected leader patches its own pod with
				// projectcalico.org/typha-role: leader and tier-1 pods with
				// projectcalico.org/typha-tier: "1" so that the headless Services
				// can select them.  Pod patch cannot be resource-name-scoped.
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"patch"},
			},
		},
	}
}

// typhaHierarchyRoleBinding binds the namespaced hierarchy Role to the typha SA.
func (c *typhaComponent) typhaHierarchyRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaHierarchyRoleName,
			Namespace: common.CalicoNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     TyphaHierarchyRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TyphaServiceAccountName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

// typhaDeployment creates the typha deployment.
func (c *typhaComponent) typhaDeployment() []client.Object {
	// We set a fairly long grace period by default. Typha sheds load during the grace period rather than
	// disconnecting all clients at once.
	var terminationGracePeriod int64 = defaultTyphaTerminationGracePeriod
	var revisionHistoryLimit int32 = 2
	// Allowing 1 unavailable Typha by default ensures that we make progress in a cluster with constrained scheduling.
	maxUnavailable := intstr.FromInt(1)
	// Allowing 100% surge allows a complete replacement fleet of Typha instances to start during an upgrade. When
	// combined with Typha's graceful shutdown, we get nice emergent behavior:
	// - All up-level Typhas start if there's room available.
	// - Back-level Typhas shed load slowly over the termination grace period.
	// - Clients that are shed end up connecting to up-level Typhas (because all the back-level Typhas are marked
	//   as terminating once all the up-level Typhas are ready).  This tends to avoid bouncing a client multiple
	//   times during an upgrade.
	// - If there's any sort of version skew issue where a back-level client can't understand an up-level Typha,
	//   it'll go non-ready and Kubernetes will upgrade it.  This is rate limited by Typha's load-shedding rate,
	//   so we shouldn't get a "thundering herd".
	maxSurge := intstr.FromString("100%")

	typhaContainer := c.typhaContainer()

	annotations := c.cfg.TLS.TrustedBundle.HashAnnotations()
	annotations[c.cfg.TLS.TyphaSecret.HashAnnotationKey()] = c.cfg.TLS.TyphaSecret.HashAnnotationValue()
	var initContainers []corev1.Container
	if c.cfg.TLS.TyphaSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLS.TyphaSecret.InitContainer(common.CalicoNamespace, typhaContainer.SecurityContext))
	}
	if c.cfg.HierarchyEnabled && c.cfg.TLS.TyphaClientSecret != nil {
		annotations[c.cfg.TLS.TyphaClientSecret.HashAnnotationKey()] = c.cfg.TLS.TyphaClientSecret.HashAnnotationValue()
		if c.cfg.TLS.TyphaClientSecret.UseCertificateManagement() {
			initContainers = append(initContainers, c.cfg.TLS.TyphaClientSecret.InitContainer(common.CalicoNamespace, typhaContainer.SecurityContext))
		}
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.TyphaMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)
	}

	// Allow tolerations to be overwritten by the end-user. By default Typha uses
	// the bootstrap toleration set: broad enough to schedule on otherwise tainted
	// nodes during install (before the CNI / cloud provider are ready), but narrow
	// enough that cordoned nodes are still avoided.
	tolerations := rmeta.TolerateBootstrap
	if len(c.cfg.Installation.ControlPlaneTolerations) != 0 {
		tolerations = c.cfg.Installation.ControlPlaneTolerations
	}
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	// In hierarchical mode, mark pods as tier-2 so that the tier-1 Service selector
	// does NOT match them.  The label is only metadata — the Deployment Selector stays
	// pinned to k8s-app=calico-typha so that existing PDBs and Services are unaffected.
	var podTemplateLabels map[string]string
	if c.cfg.HierarchyEnabled {
		podTemplateLabels = map[string]string{
			TyphaTierLabelKey: "2",
		}
	}

	deploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      podTemplateLabels,
				},
				Spec: corev1.PodSpec{
					Tolerations:                   tolerations,
					Affinity:                      c.affinity(),
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					ServiceAccountName:            TyphaServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []corev1.Container{typhaContainer},
					Volumes:                       c.volumes(),
				},
			},
		},
	}
	SetClusterCriticalPod(&deploy.Spec.Template)
	if c.cfg.MigrateNamespaces {
		migration.SetTyphaAntiAffinity(deploy)
	}

	if overrides := c.cfg.Installation.TyphaDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deploy, overrides)
	}

	// ApplyDeploymentOverrides patches some fields that have consistency requirements elsewhere in the spec.
	// fix up the other places.
	c.applyPostOverrideFixUps(deploy)

	if c.cfg.NonClusterHost != nil {
		// Create a separate deployment to handle non-cluster host requests.
		deployNonClusterHost := deploy.DeepCopy()
		deployNonClusterHost.Name += TyphaNonClusterHostSuffix
		// Replace Typha secret annotation for NonClusterHost deployment.
		delete(deployNonClusterHost.Spec.Template.Annotations, c.cfg.TLS.TyphaSecret.HashAnnotationKey())
		deployNonClusterHost.Spec.Template.Annotations[c.cfg.TLS.TyphaSecretNonClusterHost.HashAnnotationKey()] = c.cfg.TLS.TyphaSecretNonClusterHost.HashAnnotationValue()
		// Remove the affinity and use pod network
		deployNonClusterHost.Spec.Template.Spec.Affinity = nil
		deployNonClusterHost.Spec.Template.Spec.HostNetwork = false
		// Strip the hierarchy tier label: NCH Typha does not participate in the
		// two-tier topology, so the tier-1 Service must not select it.
		delete(deployNonClusterHost.Spec.Template.Labels, TyphaTierLabelKey)
		if len(deployNonClusterHost.Spec.Template.Labels) == 0 {
			deployNonClusterHost.Spec.Template.Labels = nil
		}
		// Tune Typha container and volumes for NonClusterHost deployment.
		deployNonClusterHost.Spec.Template.Spec.Containers = []corev1.Container{c.typhaContainerNonClusterHost()}
		deployNonClusterHost.Spec.Template.Spec.Volumes = c.volumeNonClusterHost()
		return []client.Object{deploy, deployNonClusterHost}
	}

	return []client.Object{deploy}
}

func (c *typhaComponent) applyPostOverrideFixUps(d *appsv1.Deployment) {
	// The deployment overrides may update the termination grace period and typha needs to know what the grace
	// period is in order to calculate its shutdown disconnection rate.  Copy that over to an env var.
	terminationGracePeriod := *d.Spec.Template.Spec.TerminationGracePeriodSeconds
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name != TyphaContainerName {
			continue
		}
		for i, e := range c.Env {
			if e.Name != shutdownTimeoutEnvVar {
				continue
			}
			c.Env[i].Value = fmt.Sprint(terminationGracePeriod)
			break
		}
		break
	}

	// If the termination grace period has been set to a very high value, make sure the Deployment's progress
	// deadline takes account of that.
	minProgressDeadline := int32(terminationGracePeriod * 120 / 100)
	if minProgressDeadline < 600 {
		// 600 is the Kubernetes default so let's not go below that.
		minProgressDeadline = 600
	}
	if d.Spec.ProgressDeadlineSeconds == nil || *d.Spec.ProgressDeadlineSeconds < minProgressDeadline {
		d.Spec.ProgressDeadlineSeconds = &minProgressDeadline
	}
}

// volumes creates the typha's volumes.
func (c *typhaComponent) volumes() []corev1.Volume {
	vols := []corev1.Volume{
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.TyphaSecret.Volume(),
	}
	if c.cfg.HierarchyEnabled && c.cfg.TLS.TyphaClientSecret != nil {
		vols = append(vols, c.cfg.TLS.TyphaClientSecret.Volume())
	}
	return vols
}

func (c *typhaComponent) volumeNonClusterHost() []corev1.Volume {
	return []corev1.Volume{
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.TyphaSecretNonClusterHost.Volume(),
	}
}

// typhaVolumeMounts creates the typha's volume mounts.
func (c *typhaComponent) typhaVolumeMounts() []corev1.VolumeMount {
	mounts := append(
		c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.TLS.TyphaSecret.VolumeMount(c.SupportedOSType()),
	)
	if c.cfg.HierarchyEnabled && c.cfg.TLS.TyphaClientSecret != nil {
		mounts = append(mounts, c.cfg.TLS.TyphaClientSecret.VolumeMount(c.SupportedOSType()))
	}
	return mounts
}

func (c *typhaComponent) typhaVolumeMountsNonClusterHost() []corev1.VolumeMount {
	return append(
		c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.TLS.TyphaSecretNonClusterHost.VolumeMount(c.SupportedOSType()),
	)
}

func (c *typhaComponent) typhaPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{
			ContainerPort: TyphaPort,
			Name:          TyphaPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

// typhaContainer creates the main typha container.
func (c *typhaComponent) typhaContainer() corev1.Container {
	lp, rp := c.livenessReadinessProbes("localhost")
	return corev1.Container{
		Name:            TyphaContainerName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "typha"},
		Resources:       c.typhaResources(),
		Env:             c.typhaEnvVars(c.cfg.TLS.TyphaSecret),
		VolumeMounts:    c.typhaVolumeMounts(),
		Ports:           c.typhaPorts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

func (c *typhaComponent) typhaContainerNonClusterHost() corev1.Container {
	container := c.typhaContainer()
	container.Env = c.typhaEnvVarsNonClusterHost()
	container.VolumeMounts = c.typhaVolumeMountsNonClusterHost()
	container.LivenessProbe, container.ReadinessProbe = c.livenessReadinessProbes("")
	return container
}

// typhaResources creates the typha's resource requirements.
func (c *typhaComponent) typhaResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameTypha)
}

// typhaEnvVars creates the typha's envvars.
func (c *typhaComponent) typhaEnvVars(typhaSecret certificatemanagement.KeyPairInterface) []corev1.EnvVar {
	typhaEnv := []corev1.EnvVar{
		{Name: "TYPHA_LOGSEVERITYSCREEN", Value: "info"},
		{Name: "TYPHA_LOGFILEPATH", Value: "none"},
		{Name: "TYPHA_LOGSEVERITYSYS", Value: "none"},
		{Name: "TYPHA_CONNECTIONREBALANCINGMODE", Value: "kubernetes"},
		{Name: "TYPHA_DATASTORETYPE", Value: "kubernetes"},
		{Name: "TYPHA_HEALTHENABLED", Value: "true"},
		{Name: "TYPHA_HEALTHPORT", Value: fmt.Sprintf("%d", typhaHealthPort(c.cfg))},
		{Name: "TYPHA_K8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "TYPHA_CAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
		{Name: "TYPHA_SERVERCERTFILE", Value: typhaSecret.VolumeMountCertificateFilePath()},
		{Name: "TYPHA_SERVERKEYFILE", Value: typhaSecret.VolumeMountKeyFilePath()},
		{Name: shutdownTimeoutEnvVar, Value: fmt.Sprint(defaultTyphaTerminationGracePeriod)}, // May get overridden later.
	}
	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TLS.TyphaCommonName != "" {
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "TYPHA_CLIENTCN", Value: c.cfg.TLS.NodeCommonName})
	}
	if c.cfg.TLS.TyphaURISAN != "" {
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "TYPHA_CLIENTURISAN", Value: c.cfg.TLS.NodeURISAN})
	}

	// Downward-API pod identity vars.  Required for leader election (PodName, PodNamespace)
	// and node-affinity routing (NodeName); injected unconditionally so that any future
	// feature relying on them is already available without a rolling restart.
	typhaEnv = append(typhaEnv,
		corev1.EnvVar{
			Name: "TYPHA_PODNAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		corev1.EnvVar{
			Name: "TYPHA_PODNAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		corev1.EnvVar{
			Name: "TYPHA_NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
	)

	// Hierarchy and leader-election env vars.  Only rendered when HierarchyEnabled so
	// that the default deployment is byte-for-byte unchanged except for the downward-API
	// vars added above (which are always safe).  PR2 will replace HierarchyEnabled with
	// a first-class Installation API field (Installation.Spec.TyphaHierarchy.Enabled).
	if c.cfg.HierarchyEnabled {
		typhaEnv = append(typhaEnv,
			corev1.EnvVar{Name: "TYPHA_HIERARCHYENABLED", Value: "true"},
			corev1.EnvVar{Name: "TYPHA_LEADERELECTIONENABLED", Value: "true"},
			corev1.EnvVar{Name: "TYPHA_TIER1COUNT", Value: fmt.Sprintf("%d", c.cfg.Tier1Count)},
		)
		if c.cfg.TLS.TyphaClientSecret != nil {
			typhaEnv = append(typhaEnv,
				corev1.EnvVar{Name: "TYPHA_CLIENTCERTFILE", Value: c.cfg.TLS.TyphaClientSecret.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "TYPHA_CLIENTKEYFILE", Value: c.cfg.TLS.TyphaClientSecret.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "TYPHA_CLIENTCAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
				corev1.EnvVar{Name: "TYPHA_UPSTREAMSERVERCN", Value: TyphaCommonName},
			)
		}
	}

	switch c.cfg.Installation.CNI.Type {
	case operatorv1.PluginAmazonVPC:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
	case operatorv1.PluginGKE:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
	case operatorv1.PluginAzureVNET:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			typhaEnv = append(typhaEnv, corev1.EnvVar{
				Name:  "MULTI_INTERFACE_MODE",
				Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value(),
			})
		}
	}

	// If host-local IPAM is in use, we need to configure typha to use the Kubernetes pod CIDR.
	cni := c.cfg.Installation.CNI
	if cni != nil && cni.IPAM != nil && cni.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		typhaEnv = append(typhaEnv, corev1.EnvVar{
			Name:  "USE_POD_CIDR",
			Value: "true",
		})
	}

	typhaEnv = append(typhaEnv, c.cfg.K8sServiceEp.EnvVars()...)

	if c.cfg.Installation.TyphaMetricsPort != nil {
		// If a typha metrics port was given, then enable typha prometheus metrics and set the port.
		typhaEnv = append(typhaEnv,
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"},
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)},
		)
	}

	return typhaEnv
}

func replaceOrAppendEnvVar(envVars []corev1.EnvVar, key, value string) []corev1.EnvVar {
	found := false
	for i := range envVars {
		if envVars[i].Name == key {
			envVars[i].Value = value
			found = true
		}
	}

	if !found && value != "" {
		envVars = append(envVars, corev1.EnvVar{Name: key, Value: value})
	}
	return envVars
}

// hierarchyEnvVarNames are the env var names that relate to hierarchical Typha mode.
// The NCH Typha does not participate in hierarchy so these must be stripped from
// its env.
var hierarchyEnvVarNames = map[string]struct{}{
	"TYPHA_HIERARCHYENABLED":      {},
	"TYPHA_LEADERELECTIONENABLED": {},
	"TYPHA_TIER1COUNT":            {},
	"TYPHA_CLIENTCERTFILE":        {},
	"TYPHA_CLIENTKEYFILE":         {},
	"TYPHA_CLIENTCAFILE":          {},
	"TYPHA_UPSTREAMSERVERCN":      {},
	// Downward-API vars are also NCH-irrelevant (leader election / node-affinity
	// routing only apply to in-cluster Typhas).
	"TYPHA_PODNAME":      {},
	"TYPHA_PODNAMESPACE": {},
	"TYPHA_NODENAME":     {},
}

func (c *typhaComponent) typhaEnvVarsNonClusterHost() []corev1.EnvVar {
	// Update Typha client common name or URISAN for non-cluster hosts.
	// At least one of TYPHA_CLIENTCN or TYPHA_CLIENTURISAN must be set.
	envVars := c.typhaEnvVars(c.cfg.TLS.TyphaSecretNonClusterHost)
	envVars = replaceOrAppendEnvVar(envVars, "TYPHA_CLIENTCN", c.cfg.TLS.NodeNonClusterHostCommonName)
	envVars = replaceOrAppendEnvVar(envVars, "TYPHA_CLIENTURISAN", c.cfg.TLS.NodeNonClusterHostURISAN)

	// Strip hierarchy-related env vars: the NCH Typha does not participate in
	// leader election or hierarchical routing.
	envVars = slices.DeleteFunc(envVars, func(e corev1.EnvVar) bool {
		_, isHierarchy := hierarchyEnvVarNames[e.Name]
		return isHierarchy
	})

	// NCH Typha runs pod-networked, so the host-network apiserver endpoint
	// (e.g. MKE's proxy.local) may not be reachable. Strip the inherited env
	// vars so we fall back to the default kubernetes Service that kubelet
	// injects into every pod, then re-add a pod-network endpoint if one was
	// configured explicitly.
	envVars = slices.DeleteFunc(envVars, func(e corev1.EnvVar) bool {
		return e.Name == "KUBERNETES_SERVICE_HOST" || e.Name == "KUBERNETES_SERVICE_PORT"
	})
	envVars = append(envVars, c.cfg.K8sServiceEpPodNetwork.EnvVars()...)

	// Tell the health aggregator to listen on all interfaces.
	envVars = append(envVars, corev1.EnvVar{Name: "TYPHA_HEALTHHOST", Value: "0.0.0.0"})
	return envVars
}

// typhaHealthPort returns the liveness and readiness port to use for typha.
func typhaHealthPort(cfg *TyphaConfiguration) int {
	// We use the felix health port, minus one, to determine the port to use for Typha.
	// This isn't ideal, but allows for some control of the typha port.
	return cfg.FelixHealthPort - 1
}

// livenessReadinessProbes creates the typha's liveness and readiness probes.
func (c *typhaComponent) livenessReadinessProbes(host string) (*corev1.Probe, *corev1.Probe) {
	port := intstr.FromInt(typhaHealthPort(c.cfg))
	lp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: host,
				Path: "/liveness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	rp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: host,
				Path: "/readiness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	return lp, rp
}

func (c *typhaComponent) typhaServices() []client.Object {
	svc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       TyphaPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString(TyphaPortName),
					Name:       TyphaPortName,
				},
			},
			Selector: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
	}

	var svcs []client.Object
	svcs = append(svcs, svc)

	if c.cfg.NonClusterHost != nil {
		svcNonClusterHost := svc.DeepCopy()
		svcNonClusterHost.Name += TyphaNonClusterHostSuffix
		svcNonClusterHost.Labels[AppLabelName] += TyphaNonClusterHostSuffix
		svcNonClusterHost.Spec.Selector[AppLabelName] += TyphaNonClusterHostSuffix
		svcs = append(svcs, svcNonClusterHost)
	}

	if c.cfg.HierarchyEnabled {
		svcs = append(svcs, c.typhaLeaderService())
		svcs = append(svcs, c.typhaTier1Service())
	}

	return svcs
}

// typhaLeaderService returns the headless Service that exposes the elected leader Typha
// pod.  The leader applies the label projectcalico.org/typha-role: leader to itself;
// this Service selects on that label so follower Typhas can discover their upstream.
// Only rendered when HierarchyEnabled is true.
func (c *typhaComponent) typhaLeaderService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaLeaderServiceName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaLeaderServiceName,
			},
		},
		Spec: corev1.ServiceSpec{
			// Headless: follower Typhas DNS-resolve the pod IP directly rather
			// than going through kube-proxy.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Port:       TyphaPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString(TyphaLeaderServicePortName),
					Name:       TyphaLeaderServicePortName,
				},
			},
			Selector: map[string]string{
				TyphaRoleLabelKey: TyphaRoleLabelValue,
			},
		},
	}
}

// typhaTier1Service returns the headless Service that exposes Tier-1 Typha pods.
// Tier-2 followers DNS-resolve this Service to discover which Typhas are acting as
// their upstream tier-1 peers.  Only rendered when HierarchyEnabled is true.
func (c *typhaComponent) typhaTier1Service() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaTier1ServiceName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaTier1ServiceName,
			},
		},
		Spec: corev1.ServiceSpec{
			// Headless: tier-2 Typhas DNS-resolve pod IPs directly.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Port:       TyphaPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString(TyphaLeaderServicePortName),
					Name:       TyphaLeaderServicePortName,
				},
			},
			Selector: map[string]string{
				TyphaTierLabelKey: "1",
			},
		},
	}
}

// affinity sets the user-specified typha affinity if specified.
func (c *typhaComponent) affinity() (aff *corev1.Affinity) {
	if c.cfg.Installation.TyphaAffinity != nil && c.cfg.Installation.TyphaAffinity.NodeAffinity != nil {
		// this ensures we return nil if no affinity is specified.
		if c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil && len(c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
			return nil
		}
		aff = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution:  c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				PreferredDuringSchedulingIgnoredDuringExecution: c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			},
		}

	}
	if aff == nil {
		aff = &corev1.Affinity{}
	}
	aff.PodAntiAffinity = &corev1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
			{
				Weight: 1,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      AppLabelName,
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{TyphaK8sAppName},
							},
						},
					},
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}
	return aff
}

// typhaPrometheusService service for scraping typha metrics.
func (c *typhaComponent) typhaPrometheusService() *corev1.Service {
	port := c.cfg.Installation.TyphaMetricsPort
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaMetricsName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaMetricsName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       *port,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(int(*port)),
					Name:       TyphaMetricsName,
				},
			},
			Selector: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
	}
}

func typhaNonClusterHostCalicoSystemPolicy(cfg *TyphaConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}...)

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(TyphaPort), uint16(typhaHealthPort(cfg))),
			},
		},
	}

	if r, err := cfg.K8sServiceEp.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaNonClusterHostNetworkPolicyName,
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(common.TyphaDeploymentName + TyphaNonClusterHostSuffix),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}
