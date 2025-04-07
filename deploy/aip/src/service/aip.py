from typing import Mapping, Optional, Sequence, TypedDict
from pulumi import ComponentResource, get_stack, ResourceOptions, Input, log as logger
import pulumi_kubernetes as k8s


appsv1 = k8s.apps.v1
corev1 = k8s.core.v1

STACK = get_stack()
IMAGE_REPO = "715841359524.dkr.ecr.us-east-1.amazonaws.com/graze.social/aip"


class AIPRequiredEnv(TypedDict):
    """These are the known required env vars
    To be read from encrpyted pulumi state
    """

    # Postgres URL w/ scheme ex. postgresql+asyncpg://postgres:postgres@postgres/aip
    DATABASE_URL: Input[str]
    # Full Redis/Valkey url w/scheme ie `redis://user:pass@redis:6379/0`
    REDIS_DSN: Input[str]
    # Worker Identifier (Need more info)
    WORKER_ID: Input[str]
    # Path to webkeys json
    JSON_WEB_KEYS: Input[str]
    # String array of active `kid` from webkeys json
    ACTIVE_SIGNING_KEYS: Input[str]
    # Possible duplicate of ACTIVE_SIGNING_KEYS
    SERVICE_AUTH_KEYS: Input[str]
    # more...


class AIPConfig(TypedDict):
    """A convenience object for controlling key values of a given deployment"""

    # Toggle init containers
    enable_init_containers: bool
    # The entire image slug
    image_slug: str
    # The image tag to specify
    image_tag: str
    # The number of replicas
    replicas: int
    # The required env config
    required_env: AIPRequiredEnv
    # This is additional env you wanna specify, ie DEBUG=true etc
    extra_env: Mapping[str, Input[str]]
    # Signing keys json file. This is encrypted in pulumi state
    signing_keys_json_string: Input[str]
    # ARN for the public ACM cert used w/ service load balancer
    ssl_cert_arn: Input[str]


class AIPService(ComponentResource):
    cfg: AIPConfig
    deployment: appsv1.Deployment
    namespace: str
    svc: corev1.Service
    secrets: Mapping[str, corev1.Secret]

    def __init__(
        self,
        name: str,
        namespace: str,
        cfg: AIPConfig,
        opts: Optional[ResourceOptions] = None,
    ) -> None:
        super().__init__("aip:index:AIPService", name, None, opts)
        self.cfg = cfg
        self.namespace = namespace
        self.secrets = {
            "required": self.env_secret(),
            "extra": self.extra_env_secret(),
            "signing_keys": self.signing_key_secret(),
        }

        self.deployment = appsv1.Deployment(
            "aip",
            metadata={"name": "aip", "namespace": namespace},
            spec=self.spec(),
            opts=ResourceOptions(parent=self, depends_on=[*self.secrets.values()]),
        )

        self.service = corev1.Service(
            "aip-headless",
            metadata={
                "name": "aip-headless",
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/instance": "aip",
                    "app.kubernetes.io/name": "aip",
                },
            },
            spec={
                "cluster_ip": "None",
                "selector": {
                    "app.kubernetes.io/instance": "aip",
                    "app.kubernetes.io/name": "aip",
                },
                "ports": [
                    {
                        "name": "http-alt",
                        "port": 5100,
                        "protocol": "TCP",
                        "target_port": "http-alt",
                    },
                    {
                        "name": "http",
                        "port": 8080,
                        "protocol": "TCP",
                        "target_port": "http",
                    },
                ],
            },
            opts=ResourceOptions(parent=self),
        )

        self.load_balancer = corev1.Service(
            "aip-ingress",
            metadata={
                "name": "aip-ingress",
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/instance": "aip",
                    "app.kubernetes.io/name": "aip",
                },
                "annotations": {
                    # Note that the backend talks over HTTP.
                    "service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
                    # TODO: Fill in with the ARN of your certificate.
                    "service.beta.kubernetes.io/aws-load-balancer-ssl-cert": self.cfg[
                        "ssl_cert_arn"
                    ],
                    # Run TLS only on the port named "https" below.
                    "service.beta.kubernetes.io/aws-load-balancer-ssl-ports": "https",
                },
            },
            spec={
                "type": "LoadBalancer",
                "selector": {
                    "app.kubernetes.io/instance": "aip",
                    "app.kubernetes.io/name": "aip",
                },
                "ports": [
                    {
                        "name": "http",
                        "port": 80,
                        "protocol": "TCP",
                        "target_port": "http",
                    },
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "TCP",
                        "target_port": "http",
                    },
                ],
            },
            opts=ResourceOptions(parent=self),
        )

    def init_containers(self) -> Sequence[corev1.ContainerArgsDict]:
        """Run the migrations during initialization"""
        return [
            {
                "name": "aip-init-migrations",
                "image": self.image,
                "args": ["pdm", "run", "alembic", "upgrade", "head"],
                "env_from": self.env_from(),
                "image_pull_policy": "IfNotPresent",
            }
        ]

    def containers(self) -> Sequence[corev1.ContainerArgsDict]:
        # TODO:
        # 1. Affinity
        return [
            {
                "name": "aip",
                "image": self.image,
                "image_pull_policy": "Always",
                "ports": [
                    {"container_port": 8080, "name": "http", "protocol": "TCP"},
                    # TODO: I think this port is superfluous and can be removed
                    {"container_port": 5100, "name": "http-alt", "protocol": "TCP"},
                ],
                "env_from": self.env_from(),
                "args": ["pdm", "run", "aipserver"],
                "resources": {
                    # TODO: This is likely overkill
                    "limits": {"cpu": "1", "memory": "2Gi"},
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                },
                # Foregoing liveness probe here
                "readiness_probe": {
                    "http_get": {
                        "path": "/internal/ready",
                        "port": "http",
                        "scheme": "HTTP",
                    },
                    "initial_delay_seconds": 5,
                    "period_seconds": 3,
                    "success_threshold": 1,
                    "failure_threshold": 3,
                    "timeout_seconds": 1,
                },
                "volume_mounts": [
                    {
                        "mount_path": "/etc/signing_keys.json",
                        "name": "signing-keys-json",
                        "read_only": True,
                        "sub_path": "signing_keys.json",
                    }
                ],
                "lifecycle": {
                    "post_start": {
                        "exec_": {
                            "command": [
                                "/bin/sh",
                                "-c",
                                "cp /etc/signing_keys.json /app/signing_keys.json",
                            ]
                        }
                    }
                },
            }
        ]

    def spec(self) -> appsv1.DeploymentSpecArgsDict:
        return {
            "replicas": 3,
            "selector": {
                "match_labels": {
                    "app.kubernetes.io/instance": "aip",
                    "app.kubernetes.io/name": "aip",
                }
            },
            "strategy": {
                "rolling_update": {
                    "max_surge": "25%",
                    "max_unavailable": "25%",
                }
            },
            "template": {
                "metadata": {
                    "annotations": {},
                    "labels": {
                        "app.kubernetes.io/instance": "aip",
                        "app.kubernetes.io/name": "aip",
                    },
                },
                "spec": {
                    "containers": self.containers(),
                    "init_containers": self.init_containers()
                    if self.cfg["enable_init_containers"]
                    else [],
                    "volumes": [
                        {
                            "name": "signing-keys-json",
                            "secret": {
                                "secret_name": self.secrets[
                                    "signing_keys"
                                ].metadata.name
                            },
                        }
                    ],
                },
            },
        }

    def env_secret(self):
        secret_name = f"aip-env-{STACK}"
        string_data = {}
        for k, v in self.cfg["required_env"].items():
            string_data[k] = v

        return corev1.Secret(
            secret_name,
            metadata={"namespace": self.namespace},
            string_data=string_data,
            opts=ResourceOptions(parent=self),
        )

    def extra_env_secret(self) -> corev1.Secret:
        secret_name = f"aip-extra-env-{STACK}"
        return corev1.Secret(
            secret_name,
            metadata={"namespace": self.namespace},
            # TODO: cast all values as strings
            string_data=self.cfg["extra_env"],
            opts=ResourceOptions(parent=self),
        )

    def signing_key_secret(self) -> corev1.Secret:
        secret_name = f"aip-signing-keys-json-{STACK}"
        return corev1.Secret(
            secret_name,
            metadata={"namespace": self.namespace},
            string_data={"signing_keys.json": self.cfg["signing_keys_json_string"]},
            opts=ResourceOptions(parent=self)
        )

    # alias
    signing_keys_secret = signing_key_secret

    def env_from(self) -> Sequence[corev1.EnvFromSourceArgsDict]:
        # TODO: maybe just iterate over all the secrets
        return [
            {"secret_ref": {"name": self.secrets["required"].metadata.name}},
            {"secret_ref": {"name": self.secrets["extra"].metadata.name}},
        ]

    @property
    def image(self) -> str:
        # TODO: try w/rescue key error
        try:
            if self.cfg["image_slug"]:
                return self.cfg["image_slug"]
            else:
                return f"{IMAGE_REPO}:{self.cfg['image_tag']}"
        except KeyError:
            logger.warn("no `image_slug` present on config, defaulting to `image_tag`")
            return f"{IMAGE_REPO}:{self.cfg['image_tag']}"
