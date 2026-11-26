# terraform/aws — soroauth verification service

Terraform module that deploys the soroauth verification service on AWS Fargate
inside a private VPC. The service is not internet-facing; callers must be inside
the VPC or connected via VPC peering or Transit Gateway.

## Resources created

| Resource | Purpose |
|---|---|
| VPC with private + public subnets | Network isolation across availability zones |
| NAT gateways (one per AZ) | Outbound-only access to Stellar RPC and AWS endpoints |
| Internal Application Load Balancer | HTTPS entry point; never assigned a public IP |
| ECS Fargate cluster + service | Stateless verification workers on managed compute |
| CloudWatch log group | Service logs with configurable retention |
| IAM execution role | Minimal: pull image and write logs only |

No secrets are stored in Terraform state or in the task definition. The
verification service is stateless: it derives everything from the request and
the Stellar RPC endpoint it reaches over HTTPS.

## Prerequisites

- Terraform ≥ 1.9.0
- An ACM certificate in the target region for the internal ALB HTTPS listener
- AWS credentials with permission to create VPCs, ECS clusters, IAM roles,
  ALBs, and CloudWatch log groups

## Usage

```hcl
module "soroauth" {
  source = "./terraform/aws"

  aws_region         = "us-east-1"
  environment        = "staging"
  availability_zones = ["us-east-1a", "us-east-1b"]
  container_image    = "ghcr.io/soroauth/soroauth-go:v0.1.0"
  certificate_arn    = "arn:aws:acm:us-east-1:123456789012:certificate/..."
  stellar_network    = "testnet"
}

output "service_endpoint" {
  value = "https://${module.soroauth.alb_dns_name}"
}
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `aws_region` | yes | — | AWS region (e.g. `us-east-1`) |
| `environment` | yes | — | Environment label for tags |
| `availability_zones` | yes | — | At least two AZs in the region |
| `container_image` | yes | — | Full image URI |
| `certificate_arn` | yes | — | ACM cert for the ALB HTTPS listener |
| `name_prefix` | no | `soroauth-verification` | Prefix for resource names (≤ 20 chars) |
| `vpc_cidr` | no | `10.0.0.0/16` | VPC CIDR block |
| `stellar_network` | no | `testnet` | `testnet`, `public`, or a full passphrase |
| `task_cpu` | no | `256` | Fargate CPU units |
| `task_memory` | no | `512` | Fargate memory (MiB) |
| `desired_count` | no | `1` | Running task count |
| `log_retention_days` | no | `30` | CloudWatch log retention |

## Outputs

| Name | Description |
|---|---|
| `alb_dns_name` | Internal ALB DNS name |
| `alb_arn` | ALB ARN |
| `cluster_arn` | ECS cluster ARN |
| `service_name` | ECS service name |
| `log_group_name` | CloudWatch log group name |
| `private_subnet_ids` | Private subnet IDs |
| `vpc_id` | VPC ID |
| `service_security_group_id` | Service container security group ID |

## CI

`.github/workflows/terraform.yml` runs `terraform validate` and
`terraform fmt -check` on every pull request that touches `terraform/**`.
No `terraform apply` runs in CI; deployment requires explicit credentials in a
dedicated environment.

## Security notes

- The ALB is marked `internal = true` and placed in private subnets. AWS does
  not assign a public IP; DNS resolves only from within the VPC.
- The service containers use `readonlyRootFilesystem = true`. Any write attempt
  indicates a misconfiguration, not a capability the service needs.
- The IAM execution role carries only the AWS-managed
  `AmazonECSTaskExecutionRolePolicy`. No task role is defined because the
  service makes no AWS API calls from inside the container.
- Credentials are never passed through the task definition or environment
  variables. If a future version requires a secret, use an SSM Parameter Store
  reference in the task definition instead of a plaintext value.
