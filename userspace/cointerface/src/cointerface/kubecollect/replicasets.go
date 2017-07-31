package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"reflect"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/api/core/v1"
)

// make this a library function?
func replicaSetEvent(rs *v1beta1.ReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func replicaSetEquals(lhs *v1beta1.ReplicaSet, rhs *v1beta1.ReplicaSet) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	if in && len(lhs.GetLabels()) != len(rhs.GetLabels()) {
		in = false
	} else {
		for k,v := range lhs.GetLabels() {
			if rhs.GetLabels()[k] != v {
				in = false
			}
		}
	}

	if in && lhs.Status.Replicas != rhs.Status.Replicas {
		in = false
	}

	if in && ((lhs.Spec.Replicas == nil && rhs.Spec.Replicas != nil) ||
		(lhs.Spec.Replicas != nil && rhs.Spec.Replicas == nil)) {
		in = false
	}

	if in && (lhs.Spec.Replicas != nil && uint32(*lhs.Spec.Replicas) != uint32(*rhs.Spec.Replicas)) {
		in = false
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	} else if !reflect.DeepEqual(lhs.Spec.Selector.MatchLabels, rhs.Spec.Selector.MatchLabels) {
		out = false
	}

	return in, out
}

func newReplicaSetCongroup(replicaSet *v1beta1.ReplicaSet, setLinks bool) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range replicaSet.GetLabels() {
		tags["kubernetes.replicaSet.label." + k] = v
	}
	tags["kubernetes.replicaSet.name"] = replicaSet.GetName()

	desiredReplicas := uint32(0)
	if replicaSet.Spec.Replicas != nil {
		desiredReplicas = uint32(*replicaSet.Spec.Replicas)
	}
	metrics := map[string]uint32{"kubernetes.replicaSet.replicas.desired": desiredReplicas,
		"kubernetes.replicaSet.replicas.running": uint32(replicaSet.Status.Replicas),}

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
		Tags: tags,
		Metrics: metrics,
	}
	if setLinks {
		AddNSParents(&ret.Parents, replicaSet.GetNamespace())
		AddDeploymentParents(&ret.Parents, replicaSet)
		selector, _ := v1meta.LabelSelectorAsSelector(replicaSet.Spec.Selector)
		AddPodChildren(&ret.Children, selector, replicaSet.GetNamespace())
	}
	return ret
}

var replicaSetInf cache.SharedInformer

func AddReplicaSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(replicaSet.Spec.Selector)
		if pod.GetNamespace() == replicaSet.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}
func AddReplicaSetChildren(children *[]*draiosproto.CongroupUid, deployment *v1beta1.Deployment) {
	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(deployment.Spec.Selector)
		if replicaSet.GetNamespace() == deployment.GetNamespace() && selector.Matches(labels.Set(replicaSet.GetLabels())) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}

func AddReplicaSetChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		if replicaSet.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}

func WatchReplicaSets(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchReplicaSets()")

	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	replicaSetInf = cache.NewSharedInformer(lw, &v1beta1.ReplicaSet{}, resyncPeriod)

	replicaSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- replicaSetEvent(obj.(*v1beta1.ReplicaSet),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldReplicaSet := oldObj.(*v1beta1.ReplicaSet)
				newReplicaSet := newObj.(*v1beta1.ReplicaSet)
				if oldReplicaSet.GetResourceVersion() != newReplicaSet.GetResourceVersion() {
					sameEntity, sameLinks := replicaSetEquals(oldReplicaSet, newReplicaSet)
					if !sameEntity || !sameLinks {
						evtc <- replicaSetEvent(newReplicaSet,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldReplicaSet := obj.(*v1beta1.ReplicaSet)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_replicaset"),
							Id:proto.String(string(oldReplicaSet.GetUID()))},
					},
				}
			},
		},
	)

	go replicaSetInf.Run(ctx.Done())

	return replicaSetInf
}
