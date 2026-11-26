output "alb_dns_name" {
  description = "Internal ALB DNS name. Reachable only from within the VPC or via VPC peering."
  value       = aws_lb.main.dns_name
}

output "alb_arn" {
  description = "ARN of the internal Application Load Balancer."
  value       = aws_lb.main.arn
}

output "cluster_arn" {
  description = "ECS cluster ARN. Use this when registering additional services in the same cluster."
  value       = aws_ecs_cluster.main.arn
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.main.name
}

output "log_group_name" {
  description = "CloudWatch log group that receives service logs."
  value       = aws_cloudwatch_log_group.service.name
}

output "private_subnet_ids" {
  description = "Private subnet IDs. Pass these to other modules that need to join the same VPC."
  value       = aws_subnet.private[*].id
}

output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.main.id
}

output "service_security_group_id" {
  description = "Security group ID of the verification service containers. Reference this in a peered VPC's ingress rule to allow traffic without hardcoding CIDR ranges."
  value       = aws_security_group.service.id
}
