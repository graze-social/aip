# Deploying AIP

This folder contains programs and examples for deploying AIP.

## Prerequisites
1. [aws-cli v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install)
2. [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
3. [pulumi](https://www.pulumi.com/docs/iac/download-install/#download-install-pulumi)
4. [poetry](https://python-poetry.org/docs/#installation) **Note** this might go away, Pulumi Python SDK now supports arbitrary toolchain.


## Setup Steps

1. Configure you cluster context Note: This is a required var in stack config which prevents you from applying to a different cluster. Setting it here helps you view resources after they've been created.

```sh
kubectl config set-context arn:aws:eks:us-east-1:715841359524:cluster/graze-01
```

2. Login to the graze Pulumi state bucket

```sh
pulumi login s3://graze.iac.state
```

3. Select target stack

```sh
pulumi stack select main
```

4. Ready to roll



## Config Interface
This Pulumi program consists of a parent resource called `AIPService` which manages several child resources in Kubernetes. The declared spec of these resources is obfuscated to a small interface for configuration.

The list of controlled resources is as follows:
* A `Deployment` for running the `aip` webserver. This deployment also utilizes init cotainers for running migrations when updating
* A `Service` that exposes the `http` port in a "headless" style, meaning no internal allocated IP
* A `Service` with type "LoadBalancer" that generates an AWS Network Loadbalancer and maps ports 80/443 to the aip webserver port
* A `Secret` That contains required env vars, referenced by the deployment.
* A `Secret` that contains extra env vars. This is used for injecting env vars not specified on the typed config object.
* A `Secret` that mounts a JSON object as a file, as `signing_keys.json`


In order to control aspects of these resources, there are two typed dicts called `AIPConfig` and `AIPRequiredEnv` which contain the following key/values:

```python
class AIPRequiredEnv(TypedDict):
    """These are the known required env vars to be read from encrpyted pulumi state
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
    env_config: AIPRequiredEnv
    # This is additional env you wanna specify, ie DEBUG=true etc
    extra_env: Mapping[str, Input[str]]
    # Signing keys json file. This is encrypted in pulumi state
    signing_keys_json_string: Input[str]
    # ARN for the public ACM cert used w/ service load balancer
    ssl_cert_arn: Input[str]
```
This are set in the stack config under `aip_config` key. View an example [here](./aip/Pulumi.main.yaml). `required_env` enforces values to be set. Pulumi application will fail when values are missing. In order to set a secure value, the `pulumi` sdk is required. Example:

```sh
pulumi config set --path --secret aip_config.required_env.SOME_SECURE_VAR "some-secure-value"
```
This encrypts the value in Pulumi state and is only decrypted at runtime, which is obfuscated from the end user. Note: It is possible to use a custom KMS key, or a third party KMS service.


### Applying changes

Here's a walkthough of a basic use case of updating an image.

1. Get an image tag, ie `v0.1.2`
2. `pulumi select stack main` to targe the main stack.
3. `pulumi config set --path aip_config.image_tag v0.1.2` to set the tag. If it's a plain text value you can also just add it directly in yaml, no need to do long CLI commands.
4. `pulumi preview` should show you this
```sh
Previewing update (main):
     Type                                 Name      Plan       Info
     pulumi:pulumi:Stack                  aip-main
     └─ aip:index:AIPService              aip
 ~      └─ kubernetes:apps/v1:Deployment  aip       update     [diff: ~spec]

Resources:
    ~ 1 to update
    8 unchanged
```
5. You can pass the `--diff` flag to the preview command to expand the diff and show the spec changes.

6. `pulumi up` will run the preview again, but give you a prompt:
```sh
Do you want to perform this update?  [Use arrows to move, type to filter]
  yes
> no
  details
```
You can also view the diff here if you select `details`. selecting `up` will begin the apply.

7. The apply will track changes on the k8s server. In this particular case the image update would trigger a rolling deployment, creating a new replica set. Pulumi is not a native-kubernetes tool, and thus has no built-in visualization of this process, so for granular tracking you must use kubectl, ie something like `kubectl get pods -l app.kubernetes.io/name=aip --watch` to tail the pod update events.

8. voilá

### Go-live Notes:

* **Dependencies** are currently using local-cluster services introduced in [this PR](https://github.com/graze-social/control/pull/1). Even though they are HA-enabled, they are using a lot of default config. We can (should (maybe?)) moved to managed services for the launch, at least for Postgres. Depending on traffic, the local Redis might hold up fine.

* **Key Rotation** I am mounting the current signing_keys.json in a k8s secret by first cat-ing it into an encrypted Pulumi value like `pulumi config set --secret --path aip_config.signing_keys_json_string "$(cat ./signing_keys.json)"`. The `ACTIVE_SIGNING_KEYS` var I am manually setting. I can automate key rotation in a future iteration, probably in a second Pulumi project (which is why this directory is structured with `aip` and `key-rotator` as submodules). Pulumi can uses `aip` utils to generate signing keys and store them with TTLs in external state and combine them into the required values propagated to the cluster. I've done several patterns like this before, but this is a Day 2 problem.

* **Ingress** Right now the `aip` webserver is directly exposed on an AWS NLB. In a (very) near future iteration we should deploy and ingress controller. This will add L7 routing upstream from the webserver which provides many benefits, one of which off top is being able to obfuscate different routes. Right now everything declared in the webserver is live on the internet. I don't have a preference of controller, but we could use something simple with low-config like `nginx-ingress` or `traefik`

* I am unclear what the requirements for the PLC/resolve functionality are, or what I need to add to get them working.

* I have a pre-configured cert-arn for `auth.m.graze.social`. This can be dynamically managed in `graze-social/pasture` as it requires three-step validation involving a DNS challenge.

* I am working on a Tilt setup to be able to jack-in to this deployment using this same Pulumi setup.







