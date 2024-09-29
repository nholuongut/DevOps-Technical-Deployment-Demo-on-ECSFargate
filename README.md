# DevOps Technical Deployment Demo on ECS Fargate <br>
# Roadmaps are now interactive, you can click the nodes to read more about the topics.

### [View all Roadmaps](https://github.com/nholuongut/all-roadmaps) &nbsp;&middot;&nbsp; [Best Practices](https://github.com/nholuongut/all-roadmaps/blob/main/public/best-practices/) &nbsp;&middot;&nbsp; [Questions](https://www.linkedin.com/in/nholuong/)

![](https://i.imgur.com/waxVImv.png)

The benefit of ECS Fargate enables containers to run without needing to manage servers or clusters. This easy-to-use, low-maintenance option can be exciting, especially for SMB companies concerned about the complexity of the K8S.<br>
How it works from [AWS Fargatet](https://aws.amazon.com/fargate/) for more information.<br>

# Prerequisites
```
# AWS Account
# AWS CLI
# Terraform
# Nginx

```
# Infrastructure	 architecture	 diagram	
The following diagram illustrates the architecture for the solution:
<img width="907" alt="Deployment Strategy Diagram" src="https://github.com/nholuongut/DevOps-Technical-Deployment-Demo-on-ECSFargate/assets/58627821/37711ce6-5b26-4295-ab3b-6db807657247">


## Step by step to deployment!

The first step is to create the file for the Terraform provider. This file is used to initialize the AWS provider. Create a file called provider.tf and add the following code to the file:
```
# Setup the AWS provider | provider.tf
terraform {
  required_version = ">= 0.12"
}
provider "aws" {
  version = "~> 2.12"
  region = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
```
Then we will need a file for authentication variables. Add the following code to a file called variables-auth.tf:
```
# AWS connection & authentication | variables-auth.tf
variable "aws_access_key" {
  type = string
  description = "AWS access key"
}
variable "aws_secret_key" {
  type = string
  description = "AWS secret key"
}
variable "aws_key_pair_name" {
  type = string
  description = "AWS key pair name"
}
variable "aws_key_pair_file" {
  type = string
  description = "Location of AWS key pair file"
}
variable "aws_region" {
  type = string
  description = "AWS region"
}
```
Create a file called variables-app.tf used for application variables and add the following code:

```
# Application configuration | variables-app.tf
variable "app_name" {
  type = string
  description = "Application name"
}
variable "app_environment" {
  type = string
  description = "Application environment"
}
variable "admin_sources_cidr" {
  type = list(string)
  description = "List of IPv4 CIDR blocks from which to allow admin access"
}
variable "app_sources_cidr" {
  type = list(string)
  description = "List of IPv4 CIDR blocks from which to allow application access"
}
```
Now, we will create all network components required: VPC, Subnets, Internet Gateway (used to provide internet access to public subnets) and Routes to the internet. Create a file called network.tf and add the code below:

Note: for brevity (and save some money), and we will deploy public subnets only. If you need private subnets, add extra private subnets, a NAT Gateway, and extra routes from private subnets to NAT Gateway.
```
# Network Setup: VPC, Subnet, IGW, Routes | network.tf
data "aws_availability_zones" "aws-az" {
  state = "available"
}
# create vpc
resource "aws_vpc" "aws-vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "${var.app_name}-vpc"
    Environment = var.app_environment
  }
}
# create subnets
resource "aws_subnet" "aws-subnet" {
  count = length(data.aws_availability_zones.aws-az.names)
  vpc_id = aws_vpc.aws-vpc.id
  cidr_block = cidrsubnet(aws_vpc.aws-vpc.cidr_block, 8, count.index + 1)
  availability_zone = data.aws_availability_zones.aws-az.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.app_name}-subnet-${count.index + 1}"
    Environment = var.app_environment
  }
}
# create internet gateway
resource "aws_internet_gateway" "aws-igw" {
  vpc_id = aws_vpc.aws-vpc.id
  tags = {
    Name = "${var.app_name}-igw"
    Environment = var.app_environment
  }
}
# create routes
resource "aws_route_table" "aws-route-table" {
  vpc_id = aws_vpc.aws-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.aws-igw.id
  }
  tags = {
    Name = "${var.app_name}-route-table"
    Environment = var.app_environment
  }
}
resource "aws_main_route_table_association" "aws-route-table-association" {
  vpc_id = aws_vpc.aws-vpc.id
  route_table_id = aws_route_table.aws-route-table.id
}
```
# Build the ECS Cluster
The next step is to set up the ECS cluster. First, we need a file for the variables called ecs-cluster-variables.tf, with the following code:

```
# ECS cluster variables | ecs-cluster-variables.tf
variable "cluster_runner_type" {
  type = string
  description = "EC2 instance type of ECS Cluster Runner"
  default = "t3.medium"
}
variable "cluster_runner_count" {
  type = string
  description = "Number of EC2 instances for ECS Cluster Runner" 
  default = "1"
}
```
The second step of the ECS cluster creation is to define the ECS cluster, ECS AMI, IAM policies and security groups in the file ecs-cluster.tf.<br>

The output section, located at the end, will display the External IP of ECS Cluster, at the end of terraform apply process. Optionally, we can move all output pieces to a separate output.tf file.<br>
```
# define & build the ecs cluster | ecs-cluster.tf
# create ecs cluster
resource "aws_ecs_cluster" "aws-ecs" {
  name = var.app_name
}
# get latest ecs ami
data "aws_ami" "ecs-ami" {
  most_recent = true
  filter {
    name = "name"
    values = ["amzn2-ami-ecs-hvm-2.0.*"]
  }
  filter {
    name = "architecture"
    values = ["x86_64"]
  }
  owners = ["amazon"]
}
# override ecs ami image
variable "aws_ecs_ami_override" {
  default = ""
  description = "Machine image to use for ec2 instances"
}
locals {
  aws_ecs_ami = var.aws_ecs_ami_override == "" ? data.aws_ami.ecs-ami.id : var.aws_ecs_ami_override
}
locals {
  ebs_types = ["t2", "t3", "m5", "c5"]
  cpu_by_instance = {
    "t2.small"     = 1024
    "t2.large"     = 2048
    "t2.medium"    = 2048
    "t2.xlarge"    = 4096
    "t3.medium"    = 2048
    "m5.large"     = 2048
    "m5.xlarge"    = 4096
    "m5.2xlarge"   = 8192
    "m5.4xlarge"   = 16384
    "m5.12xlarge"  = 49152
    "m5.24xlarge"  = 98304
    "c5.large"     = 2048
    "c5d.large"    = 2048
    "c5.xlarge"    = 4096
    "c5d.xlarge"   = 4096
    "c5.2xlarge"   = 8192
    "c5d.2xlarge"  = 8192
    "c5.4xlarge"   = 16384
    "c5d.4xlarge"  = 16384
    "c5.9xlarge"   = 36864
    "c5d.9xlarge"  = 36864
    "c5.18xlarge"  = 73728
    "c5d.18xlarge" = 73728
  }
  mem_by_instance = {
    "t2.small"     = 1800
    "t2.medium"    = 3943
    "t2.large"     = 7975
    "t2.xlarge"    = 16039
    "t3.medium"    = 3884
    "m5.large"     = 7680
    "m5.xlarge"    = 15576
    "m5.2xlarge"   = 31368
    "m5.4xlarge"   = 62950
    "m5.12xlarge"  = 189283
    "m5.24xlarge"  = 378652
    "c5.large"     = 3704
    "c5d.large"    = 3704
    "c5.xlarge"    = 7624
    "c5d.xlarge"   = 7624
    "c5.2xlarge"   = 15463
    "c5d.2xlarge"  = 15463
    "c5.4xlarge"   = 31142
    "c5d.4xlarge"  = 31142
    "c5.9xlarge"   = 70341
    "c5d.9xlarge"  = 70341
    "c5.18xlarge"  = 140768
    "c5d.18xlarge" = 140768
  }
}
# ecs cluster runner role policies
resource "aws_iam_role" "ecs-cluster-runner-role" {
  name = "${var.app_name}-cluster-runner-role"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role.json
}
data "aws_caller_identity" "current" {}
data "aws_iam_policy_document" "ecs-cluster-runner-policy" {
  statement {
    actions = ["ec2:Describe*", "ecr:Describe*", "ecr:BatchGet*"]
    resources = ["*"]
  }
  statement {
    actions = ["ecs:*"]
    resources = ["arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/${var.app_name}/*"]
  }
}
resource "aws_iam_role_policy" "ecs-cluster-runner-role-policy" {
  name = "${var.app_name}-cluster-runner-policy"
  role = aws_iam_role.ecs-cluster-runner-role.name
  policy = data.aws_iam_policy_document.ecs-cluster-runner-policy.json
}
resource "aws_iam_instance_profile" "ecs-cluster-runner-profile" {
  name = "${var.app_name}-cluster-runner-iam-profile"
  role = aws_iam_role.ecs-cluster-runner-role.name
}
# ec2 user data for hard drive
data "template_file" "user_data_cluster" {
  template = file("templates/cluster_user_data.sh")
  vars = { 
    ecs_cluster = aws_ecs_cluster.aws-ecs.name
  }
}
# create ec2 instance for the ecs cluster runner
resource "aws_instance" "ecs-cluster-runner" {
  ami = local.aws_ecs_ami
  instance_type = var.cluster_runner_type
  subnet_id = element(aws_subnet.aws-subnet.*.id, 0)
  vpc_security_group_ids = [aws_security_group.ecs-cluster-host.id]
  associate_public_ip_address = true
  key_name = var.aws_key_pair_name
  user_data = data.template_file.user_data_cluster.rendered
  count = var.cluster_runner_count
  iam_instance_profile = aws_iam_instance_profile.ecs-cluster-runner-profile.name
  tags = {
    Name = "${var.app_name}-ecs-cluster-runner"
    Environment = var.app_environment
    Role = "ecs-cluster"
  }
  volume_tags = {
    Name = "${var.app_name}-ecs-cluster-runner"
    Environment = var.app_environment
    Role = "ecs-cluster"
  }
}
# create security group and segurity rules for the ecs cluster
resource "aws_security_group" "ecs-cluster-host" {
  name = "${var.app_name}-ecs-cluster-host"
  description = "${var.app_name}-ecs-cluster-host"
  vpc_id = aws_vpc.aws-vpc.id
  tags = {
    Name = "${var.app_name}-ecs-cluster-host"
    Environment = var.app_environment
    Role = "ecs-cluster"
  }
}
resource "aws_security_group_rule" "ecs-cluster-host-ssh" {
  security_group_id = aws_security_group.ecs-cluster-host.id
  description = "admin SSH access to ecs cluster"
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = var.admin_sources_cidr
}
resource "aws_security_group_rule" "ecs-cluster-egress" {
  security_group_id = aws_security_group.ecs-cluster-host.id
  description = "ecs cluster egress"
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
# output ecs cluster public ip
output "ecs_cluster_runner_ip" {
  description = "External IP of ECS Cluster"
  value = [aws_instance.ecs-cluster-runner.*.public_ip]
}
```
The third step of the ECS cluster creation is to define the ECS policies in the file ecs-cluster-policies.tf:
```
# iam & policies for ec2 instances & ecs cluster | ecs-cluster-policies.tf
data "aws_iam_policy_document" "instance-assume-role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "ecsInstanceRole" {
  name = "${var.app_name}-ecsInstanceRole"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role.json
}
resource "aws_iam_role_policy_attachment" "ecsInstanceRole" {
  role = aws_iam_role.ecsInstanceRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}
resource "aws_iam_instance_profile" "ecsInstanceRole" {
  name = "${var.app_name}-ecsInstanceRole"
  role = aws_iam_role.ecsInstanceRole.name
}
data "aws_iam_policy_document" "task-assume-role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "ecsTaskExecutionRole" {
  name = "${var.app_name}-ecsTaskExecutionRole"
  assume_role_policy = data.aws_iam_policy_document.task-assume-role.json
}
resource "aws_iam_role_policy_attachment" "ecsTaskExecutionRole" {
  role = aws_iam_role.ecsTaskExecutionRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
```
The fourth and final step of the ECS cluster creation is to create the file templates\cluster_user_data.sh. This file is used to configure the hard drive partition of EC2 instances:
```
#!/bin/bash
if [ -e /dev/nvme1n1 ]; then
  if ! file -s /dev/nvme1n1 | grep -q filesystem; then
    mkfs.ext4 /dev/nvme1n1
  fi
  cat >> /etc/fstab <<-EOF
  /dev/nvme1n1  /data  ext4  defaults,noatime,nofail  0  2
  EOF
  
  mkdir /data
  mount /data
fi
echo ECS_CLUSTER=${ecs_cluster} >> /etc/ecs/ecs.config
systemctl try-restart ecs --no-block
```
#Configuring the Nginx Containers
We are getting close to the end. The final step is to create Nginx containers.<br>

The process is split between several files, for clarity, however, you can create a single .tf file.<br>
First, we need to define the variables in the nginx-variables.tf file.
```
# nginx container - nginx-variables.tf
variable "nginx_app_name" {
  description = "Name of Application Container"
  default = "nginx"
}
variable "nginx_app_image" {
  description = "Docker image to run in the ECS cluster"
  default = "nginx:latest"
}
variable "nginx_app_port" {
  description = "Port exposed by the Docker image to redirect traffic to"
  default = 80
}
variable "nginx_app_count" {
  description = "Number of Docker containers to run"
  default = 2
}
variable "nginx_fargate_cpu" {
  description = "Fargate instance CPU units to provision (1 vCPU = 1024 CPU units)"
  default = "1024"
}
variable "nginx_fargate_memory" {
  description = "Fargate instance memory to provision (in MiB)"
  default = "2048"
}
```
In the second step, we will create the nginx.json file, used to configure the Nginx Fairgate container:
```
[
  {
    "name": "${app_name}",
    "image": "${app_image}",
    "cpu": ${fargate_cpu},
    "memory": ${fargate_memory},
    "networkMode": "awsvpc",
    "portMappings": [
      {
        "containerPort": ${app_port},
        "hostPort": ${app_port}
      }
    ]
  }
]
```
Then, in the third step, we will create the file nginx-container.tf, used to build the Nginx container, with this content:
```
# nginx container | nginx-container.tf
# container template
data "template_file" "nginx_app" {
  template = file("./nginx.json")
  vars = {
    app_name = var.nginx_app_name
    app_image = var.nginx_app_image
    app_port = var.nginx_app_port
    fargate_cpu = var.nginx_fargate_cpu
    fargate_memory = var.nginx_fargate_memory
    aws_region = var.aws_region
  }
}
# ECS task definition
resource "aws_ecs_task_definition" "nginx_app" {
  family = "nginx-task"
  execution_role_arn = aws_iam_role.ecsTaskExecutionRole.arn
  network_mode = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu = var.nginx_fargate_cpu
  memory = var.nginx_fargate_memory
  container_definitions = data.template_file.nginx_app.rendered
}
# ECS service
resource "aws_ecs_service" "nginx_app" {
  name = var.nginx_app_name
  cluster = aws_ecs_cluster.aws-ecs.id
  task_definition = aws_ecs_task_definition.nginx_app.arn
  desired_count = var.nginx_app_count
  launch_type = "FARGATE"
  network_configuration {
    security_groups = [aws_security_group.ecs_tasks.id]
    subnets = aws_subnet.aws-subnet.*.id
    assign_public_ip = true
  }
  load_balancer {
    target_group_arn = aws_alb_target_group.nginx_app.id
    container_name = var.nginx_app_name
    container_port = var.nginx_app_port
  }
  depends_on = [aws_alb_listener.front_end]
  tags = {
    Name = "${var.nginx_app_name}-nginx-ecs"
  }
}
```
The next step is to generate the security groups. Create a file called nginx-security.tf with the following content:
```
# nginx security | nginx-security.tf
# ALB Security Group: Edit to restrict access to the application
resource "aws_security_group" "aws-lb" {
  name = "${var.nginx_app_name}-load-balancer"
  description = "Controls access to the ALB"
  vpc_id = aws_vpc.aws-vpc.id
  ingress {
    protocol = "tcp"
    from_port = var.nginx_app_port
    to_port = var.nginx_app_port
    cidr_blocks = [var.app_sources_cidr]
  }
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.nginx_app_name}-load-balancer"
  }
}
# Traffic to the ECS cluster from the ALB
resource "aws_security_group" "aws-ecs-tasks" {
  name = "${var.nginx_app_name}-ecs-tasks"
  description = "Allow inbound access from the ALB only"
  vpc_id = aws_vpc.aws-vpc.id
  ingress {
    protocol = "tcp"
    from_port = var.nginx_app_port
    to_port = var.nginx_app_port
    security_groups = [aws_security_group.aws-lb.id]
  }
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.nginx_app_name}-ecs-tasks"
  }
}
```
Then, we will create the file nginx-alb.tf, used to build the Application Load Balancer for the Nginx containers.<br>

The output section, located at the end, will display the Load Balancer for the Nginx containers, at the end of terraform apply process. Optionally, we can move all output pieces to a separate output.tf file.<br>
```
# Define Application Load Balancer - alb.tf
resource "aws_alb" "main" {
  name = "${var.nginx_app_name}-load-balancer"
  subnets = aws_subnet.aws-subnet.*.id
  security_groups = [aws_security_group.aws-lb.id]
  tags = {
    Name = "${var.app_name}-alb"
  }
}
resource "aws_alb_target_group" "nginx_app" {
  name = "${var.nginx_app_name}-target-group"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.aws-vpc.id
  target_type = "ip"
  health_check {
    healthy_threshold = "3"
    interval = "30"
    protocol = "HTTP"
    matcher = "200"
    timeout = "3"
    path = "/"
    unhealthy_threshold = "2"
  }
  tags = {
    Name = "${var.nginx_app_name}-alb-target-group"
  }
}
# Redirect all traffic from the ALB to the target group
resource "aws_alb_listener" "front_end" {
  load_balancer_arn = aws_alb.main.id
  port = var.nginx_app_port
  protocol = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.nginx_app.id
    type = "forward"
  }
}
# output nginx public ip
output "nginx_dns_lb" {
  description = "DNS load balancer"
  value = aws_alb.main.dns_name
}
```
After that, configure the variables and credentials in the terraform.tfvars file:
```
# Application Definition
app_name = "yourapp" # Do NOT enter any spaces
app_environment = "test" # Dev, Test, Prod, etc
#AWS authentication variables
aws_access_key = "your-aws-access-key"
aws_secret_key = "your-aws-secret-key"
aws_key_pair_name = "yourapp-key-pair"
aws_key_pair_file = "yourapp-key-pair.pem"
aws_region = "eu-west-2"
# Application access
app_sources_cidr = ["0.0.0.0/0"] # Specify a list of IPv4 IPs/CIDRs which can access app load balancers
admin_sources_cidr = ["0.0.0.0/0"] # Specify a list of IPv4 IPs/CIDRs which can admin instances
```
# How to deploy the cluster in AWS.<br>
## 1.Create an IAM user and update the file terraform.tfvars with the credentials. To create an IAM user follow step 1 of the link below.<br>
How it works from [Amazon EC2 key pairs and Linux instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) for more information.<br>
## 2. Update the Amazon ECS ARN and resource ID settings.<br>
Open your AWS Console and go to the ECS service. On the left side, under the Amazon ECS, Account Settings, check the Container instance, Service and Task override checkbox.
## Run Terraform
1. Run the command ```terraform init``` from the command line, in the same folder where your code is located.
2. Then run the command ```terraform apply``` from the command line to start building the infrastructure.

I'm are always open to your feedback.  Please contact as bellow information:
### [Contact ]
* [Name: nho Luong]
* [Skype](luongutnho_skype)
* [Github](https://github.com/nholuongut/)
* [Linkedin](https://www.linkedin.com/in/nholuong/)
* [Email Address](luongutnho@hotmail.com)

![](https://i.imgur.com/waxVImv.png)
![](bitfield.png)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/nholuong)

# License
* Nho Luong (c). All Rights Reserved.
