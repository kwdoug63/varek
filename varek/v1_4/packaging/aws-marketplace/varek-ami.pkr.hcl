# SPDX-License-Identifier: MIT
#
# VAREK Enterprise AMI for AWS Marketplace (v1.23).
#
# Builds a hardened Amazon Linux 2023 image with the Warden, the `varek`
# command and the Enterprise policy packs in /opt/varek. Run it through
# build.sh, which makes the source archive and checks the packs first:
#
#   ./build.sh --version 1.23.0 --packs ~/varek-packs --product-id <product ID>
#
# Requirements met here are listed in README.md (AWS Marketplace AMI policy).

packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "varek_version" {
  type        = string
  description = "Release being packaged, e.g. 1.23.0. Goes into the AMI name and tags."
}

variable "source_tarball" {
  type        = string
  description = "git archive of varek/v1_4, v1_6 and v1_7 (build.sh makes it)."
}

variable "packs_dir" {
  type        = string
  description = "Directory holding the Enterprise *.policy.txt packs. Never in the public repo."
}

variable "product_id" {
  type        = string
  default     = ""
  description = "AWS Marketplace product ID used by License Manager (GUID, or prod-...). Empty builds a test image with no license check."
}

variable "dimensions" {
  type        = list(string)
  default     = ["enterprise_tier_b", "enterprise_tier_a"]
  description = "Contract dimension API names the license check accepts, highest tier first."
}

variable "issuer_fingerprint" {
  type        = string
  default     = ""
  description = "Empty uses AWS Marketplace's issuer. Set aws:<account>:Self:issuer-fingerprint only to test with a self-issued License Manager license."
}

variable "region" {
  type    = string
  default = "us-east-1" # AWS Marketplace ingests AMIs from us-east-1
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Subnet with internet access for the build instance. Empty uses the default VPC."
}

data "amazon-ami" "al2023" {
  region      = var.region
  owners      = ["amazon"]
  most_recent = true
  filters = {
    name                = "al2023-ami-2023.*-kernel-6.*-x86_64"
    architecture        = "x86_64"
    virtualization-type = "hvm"
    root-device-type    = "ebs"
  }
}

locals {
  stamp    = formatdate("YYYYMMDD-hhmm", timestamp())
  ami_name = "varek-enterprise-${var.varek_version}-x86_64-${local.stamp}"
}

source "amazon-ebs" "varek" {
  region                      = var.region
  source_ami                  = data.amazon-ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id == "" ? null : var.subnet_id
  associate_public_ip_address = true
  ssh_username                = "ec2-user"
  temporary_key_pair_type     = "ed25519"

  ami_name        = local.ami_name
  ami_description = "VAREK Enterprise ${var.varek_version}: pre-execution authorization for AI agents (Amazon Linux 2023, x86_64)"
  ena_support     = true
  sriov_support   = true
  imds_support    = "v2.0"
  # AWS Marketplace needs an unencrypted snapshot to scan and copy the image.
  encrypt_boot = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = false
  }

  tags = {
    Name          = local.ami_name
    Product       = "VAREK Enterprise"
    VarekVersion  = var.varek_version
    BaseAMI       = data.amazon-ami.al2023.id
    BaseAMIName   = data.amazon-ami.al2023.name
  }
  run_tags = {
    Name = "varek-ami-build"
  }
}

build {
  sources = ["source.amazon-ebs.varek"]

  provisioner "shell" {
    inline = ["mkdir -p /tmp/varek-packs"]
  }

  provisioner "file" {
    source      = var.source_tarball
    destination = "/tmp/varek-src.tar.gz"
  }

  # Trailing slash: copy the directory's contents into /tmp/varek-packs.
  provisioner "file" {
    source      = "${var.packs_dir}/"
    destination = "/tmp/varek-packs"
  }

  provisioner "file" {
    content = jsonencode(merge(
      { product_id = var.product_id, dimensions = var.dimensions },
      var.issuer_fingerprint == "" ? {} : { issuer_fingerprint = var.issuer_fingerprint }
    ))
    destination = "/tmp/varek-marketplace.json"
  }

  provisioner "shell" {
    script           = "${path.root}/scripts/install.sh"
    execute_command  = "chmod +x {{ .Path }}; sudo {{ .Vars }} bash '{{ .Path }}'"
    environment_vars = ["VAREK_VERSION=${var.varek_version}"]
  }

  # Last: removes the build's SSH key, history and host identity.
  provisioner "shell" {
    script          = "${path.root}/scripts/harden.sh"
    execute_command = "chmod +x {{ .Path }}; sudo bash '{{ .Path }}'"
  }

  post-processor "manifest" {
    output     = "${path.root}/manifest.json"
    strip_path = true
    custom_data = {
      varek_version = var.varek_version
      product_id    = var.product_id
      base_ami      = data.amazon-ami.al2023.id
    }
  }
}
