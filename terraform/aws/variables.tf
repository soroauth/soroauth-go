variable "aws_region" {
  type        = string
  description = "AWS region to deploy into (e.g. us-east-1)."
}

variable "environment" {
  type        = string
  description = "Deployment environment label applied to every resource tag (e.g. staging, production)."
}

variable "name_prefix" {
  type        = string
  description = "Short prefix applied to every resource name. Keep it under 20 characters."
  default     = "soroauth-verification"

  validation {
    condition     = length(var.name_prefix) <= 20
    error_message = "name_prefix must be 20 characters or fewer; some AWS resource names have tight length limits."
  }
}

variable "vpc_cidr" {
  type        = string
  description = "IPv4 CIDR block for the VPC. /16 is the recommended size to leave room for many subnets."
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "Availability zones to spread subnets and NAT gateways across. Must belong to var.aws_region."

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "Provide at least two availability zones for resilience."
  }
}

variable "container_image" {
  type        = string
  description = "Full container image URI for the verification service, e.g. ghcr.io/soroauth/soroauth-go:v0.1.0."
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN for the HTTPS listener on the internal ALB."
}

variable "stellar_network" {
  type        = string
  description = "Stellar network the service connects to. Use 'testnet' or 'public', or a full passphrase."
  default     = "testnet"
}

variable "task_cpu" {
  type        = number
  description = "Fargate task CPU units. Valid values: 256, 512, 1024, 2048, 4096."
  default     = 256
}

variable "task_memory" {
  type        = number
  description = "Fargate task memory in MiB. Must be compatible with task_cpu; see AWS docs."
  default     = 512
}

variable "desired_count" {
  type        = number
  description = "Number of running task instances. Set to 0 to stop the service without destroying it."
  default     = 1
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days."
  default     = 30
}
