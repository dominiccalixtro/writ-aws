# The four sec. 5.2 finding targets. Each is insecure on purpose and each is
# fenced so that its insecurity has nothing to reach:
#
#   security group   open to the world, attached to nothing
#   S3 bucket        public at most for reads, and empty
#   EBS volume       unencrypted, 1 GiB, holds no data, host has no network
#   IAM policy       "*" on "*", unattached, or attached to a role nobody
#                    can assume
#
# None of them may outlive the capture window: sec. 5.1 destroys the sandbox
# after capture, and sec. 4.4.4 requires `terraform destroy` to do it alone.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# --- 1. Over-permissive security group ingress --------------------------------

# Attribute syntax, not blocks, on purpose: `ingress = []` removes every rule,
# whereas zero `ingress` blocks leaves the existing rules unmanaged, and the
# compliant plan fixture (sec. 5.3) would then show no change at all.
resource "aws_security_group" "open_ingress" {
  name        = "${var.name_prefix}-open-ingress"
  description = "Fixture: SSH open to 0.0.0.0/0 (sec. 5.2). Attached to nothing."
  vpc_id      = data.aws_vpc.default.id

  ingress = var.remediate_security_group ? [] : [
    {
      description      = "fixture: unrestricted SSH"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]

  egress = []
}

# --- 2. Public S3 bucket ------------------------------------------------------

# bucket_prefix, not a name built from the account ID: the lab buckets were
# named writ-lab-*-<account id>, which put the account ID in every ARN a
# finding would carry.
resource "aws_s3_bucket" "public" {
  bucket_prefix = "${var.name_prefix}-public-"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Reads only, on an empty bucket. If the account's own Block Public Access
# still blocks public policies, AWS rejects this with AccessDenied — which is
# the intended failure: see README.md pre-flight.
data "aws_iam_policy_document" "public_read" {
  statement {
    sid       = "FixturePublicRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.public.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "public" {
  count      = var.s3_public_policy ? 1 : 0
  bucket     = aws_s3_bucket.public.id
  policy     = data.aws_iam_policy_document.public_read.json
  depends_on = [aws_s3_bucket_public_access_block.public]
}

# --- 3. Unencrypted EBS volume ------------------------------------------------

data "aws_ebs_encryption_by_default" "current" {}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-${var.ami_architecture}"]
  }

  filter {
    name   = "architecture"
    values = [var.ami_architecture]
  }
}

# The encryption-at-rest control evaluates attached volumes, so the volume
# needs a host. The host has no public address, no ingress, no egress and no
# key pair: nothing can reach it and it can reach nothing.
resource "aws_security_group" "host" {
  name        = "${var.name_prefix}-host"
  description = "Fixture volume host: no ingress, no egress."
  vpc_id      = data.aws_vpc.default.id
  ingress     = []
  egress      = []
}

resource "aws_instance" "volume_host" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = sort(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids      = [aws_security_group.host.id]
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }

  # Encrypted, so the one unencrypted volume in the account is the fixture.
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.name_prefix}-volume-host"
  }

  # A newer AMI published mid-capture would otherwise add an instance
  # replacement to both plan fixtures.
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = aws_instance.volume_host.availability_zone
  size              = 1
  type              = "gp3"
  encrypted         = var.remediate_ebs_volume

  tags = {
    Name = "${var.name_prefix}-unencrypted"
  }

  # With encryption-by-default on, AWS encrypts the volume regardless and the
  # fixture silently stops being the thing it claims to be.
  lifecycle {
    precondition {
      condition     = var.remediate_ebs_volume || !data.aws_ebs_encryption_by_default.current.enabled
      error_message = "EBS encryption by default is on in this region, so an unencrypted volume cannot exist. See README.md pre-flight."
    }
  }
}

resource "aws_volume_attachment" "unencrypted" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.unencrypted.id
  instance_id = aws_instance.volume_host.id
}

# --- 4. IAM policy granting "*" on "*" ----------------------------------------

data "aws_iam_policy_document" "admin_star" {
  statement {
    sid       = "FixtureAdminStar"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin_star" {
  name        = "${var.name_prefix}-admin-star"
  description = "Fixture: grants * on * (sec. 5.2). Unattached unless attach_admin_policy."
  policy      = data.aws_iam_policy_document.admin_star.json
}

# The same trust shape as the broker at rest (terraform/bootstrap): a single
# Deny for every principal, so the attached policy grants nobody anything.
data "aws_iam_policy_document" "nobody" {
  statement {
    sid     = "DenyAll"
    effect  = "Deny"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "admin_holder" {
  count              = var.attach_admin_policy ? 1 : 0
  name               = "${var.name_prefix}-admin-holder"
  description        = "Fixture: holds the * on * policy. Assumable by nobody."
  assume_role_policy = data.aws_iam_policy_document.nobody.json
}

resource "aws_iam_role_policy_attachment" "admin_holder" {
  count      = var.attach_admin_policy ? 1 : 0
  role       = aws_iam_role.admin_holder[0].name
  policy_arn = aws_iam_policy.admin_star.arn
}
