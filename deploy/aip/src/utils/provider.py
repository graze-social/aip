from pulumi import get_stack, log as logger, Config,StackReference
from pulumi_kubernetes import Provider
from typing import Optional


REF_NAME: str = "eks"
stack = get_stack()

def create_provider(namespace: str, cluster_name: Optional[str]=None) -> Provider:
    if cluster_name:
        ref = Config().require(REF_NAME)
        eks_ref = StackReference(ref)
        kubeconfig = eks_ref.require_output(f"{cluster_name}-kubeconfig")
        provider = Provider(f"{stack}-cluster", kubeconfig=kubeconfig, namespace=namespace)
    else:
        k8s_context = Config().require("k8s_context")
        provider = Provider(
            f"{stack}-cluster",
            context=k8s_context,
            namespace=namespace,
        )
    return provider
