import pulumi
from pulumi_kubernetes import Provider
from src.service.aip import AIPConfig, AIPService

stack = pulumi.get_stack()
config = pulumi.Config()
k8s_context = config.require("k8s_context")

# Lock deployments to 1 namespace
namespace = f"aip-{stack}"
provider = Provider(
    f"{stack}-cluster",
    context=k8s_context,
    namespace=namespace,
)
# TODO:
# Add custom timeout from flag
# eg
# ResourceOptions(custom_timeouts=CustomTimeouts(create='5m'))


aip_config: AIPConfig = config.require_object("aip_config")

aip = AIPService(
    "aip", namespace, aip_config, pulumi.ResourceOptions(provider=provider)
)
