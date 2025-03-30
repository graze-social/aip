import pulumi
from typing import Optional
from src.utils.provider import create_provider
from src.service.aip import AIPConfig, AIPService

stack = pulumi.get_stack()
config = pulumi.Config()

# Lock deployments to 1 namespace
namespace = f"aip-{stack}"
cluster_name: Optional[str] = config.get("import_kubeconfig")

# This will now import a kubeconfig that will delegate to your aws cli
# The default method requires setting a stack reference and a cluster name to import
# eg
# ...
#   aip:eks: organization/eks/main
#   aip:import_kubeconfig: graze-01
# ...
provider = create_provider(namespace, cluster_name)

# TODO:
# Add custom timeout from flag
# eg
# ResourceOptions(custom_timeouts=CustomTimeouts(create='5m'))

aip_config: AIPConfig = config.require_object("aip_config")

aip = AIPService(
    "aip", namespace, aip_config, pulumi.ResourceOptions(provider=provider)
)
