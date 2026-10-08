# cloud_security/labs/aws/main.tf
#
# Lab didático de infraestrutura-como-código propositalmente mal configurada.
#
# ATENCAO: este Terraform NUNCA foi (e NUNCA deve ser) aplicado contra uma
# conta AWS real. Ele existe apenas como alvo de scan estático local
# (Checkov / trivy config) para demonstrar deteccao de misconfigs classicos.
# Nenhuma credencial AWS e usada ou necessaria.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "lab-fake-access-key"
  secret_key                  = "lab-fake-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# --- Misconfig 1: bucket S3 publico (ACL + bloqueio de acesso publico desligado) ---
resource "aws_s3_bucket" "public_data" {
  bucket = "cyberlab-misconfig-public-bucket"
}

resource "aws_s3_bucket_acl" "public_data_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "public_data_block" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Misconfig adicional: bucket sem versionamento e sem criptografia em repouso.
resource "aws_s3_bucket_versioning" "public_data_versioning" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# --- Misconfig 2: security group aberto a 0.0.0.0/0 em porta sensivel (SSH) ---
resource "aws_security_group" "open_ssh" {
  name        = "cyberlab-misconfig-open-ssh"
  description = "Security group intencionalmente aberto para fins didaticos"

  ingress {
    description = "SSH aberto para qualquer IP do mundo"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP tambem aberto (defesa em profundidade quebrada)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Misconfig 3: IAM policy com Action:"*" / Resource:"*" (privilegio excessivo) ---
resource "aws_iam_policy" "admin_everything" {
  name        = "cyberlab-misconfig-admin-everything"
  description = "Policy intencionalmente overprivileged para fins didaticos"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "overprivileged_role" {
  name = "cyberlab-misconfig-overprivileged-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_admin_everything" {
  role       = aws_iam_role.overprivileged_role.name
  policy_arn = aws_iam_policy.admin_everything.arn
}

# --- Misconfig 4: RDS sem encryption em repouso e exposta publicamente ---
resource "aws_db_instance" "unencrypted_public_db" {
  identifier        = "cyberlab-misconfig-rds"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "cyberlab"
  username = "cyberlab_admin"
  password = "lab-fake-password-not-real"

  storage_encrypted      = false
  publicly_accessible    = true
  skip_final_snapshot    = true
  backup_retention_period = 0
}
