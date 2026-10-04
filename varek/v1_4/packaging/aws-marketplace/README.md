# VAREK Enterprise AMI for AWS Marketplace

This directory builds the Amazon Machine Image (AMI) that AWS Marketplace
sells as VAREK Enterprise: Amazon Linux 2023 (x86_64) with the Warden, the
`varek` command and the Enterprise policy packs installed in `/opt/varek`.

| File | What it does |
|---|---|
| `build.sh` | Checks the inputs, archives the source from `HEAD`, runs Packer |
| `varek-ami.pkr.hcl` | Packer template: launches AL2023 in us-east-1, provisions, snapshots |
| `scripts/install.sh` | On the build instance: patch, build, install, add packs, remove compiler, smoke-test |
| `scripts/harden.sh` | On the build instance, last: SSH and account hardening, remove build identity |
| `iam/instance-license-policy.json` | The permission a buyer's instance role needs for the license check |
| `iam/ec2-trust.json` | Trust policy for that instance role |
| `iam/marketplace-ami-ingestion-trust.json` | Trust policy for the role that lets AWS Marketplace copy the AMI |

Buyers deploy and operate the image with the
[VAREK Enterprise on AWS deployment guide](../../../../docs/aws-deployment-guide.md).

The Enterprise packs (`hipaa.policy.txt`, `soc2.policy.txt`) are licensed
content. They are passed to the build with `--packs` from outside the
repository, and `build.sh` refuses any pack that is tracked in git.

## What the image contains

- `/opt/varek`: the Warden, its tools, the five VAREK Core packs and the
  Enterprise packs, all built from the commit at `HEAD`.
- `/usr/bin/varek`: the command (in `/usr/bin` because AL2023's `sudo` only
  searches `/sbin:/bin:/usr/sbin:/usr/bin`).
- `/opt/varek/marketplace.json`: the Marketplace product ID and the contract
  dimensions the license check accepts. Absent in a `--test` build.
- No `/etc/varek` and no keys: each buyer's `sudo varek init` makes their own
  settings and signing key.

## The license check

AWS lets AMI products with contract pricing check entitlements through AWS
License Manager ([AWS docs](https://docs.aws.amazon.com/marketplace/latest/userguide/ami-license-manager-integration.html)).
On this image, choosing an Enterprise pack (`varek init --pack hipaa`,
`varek policy use soc2`, `varek run --policy ...`) calls `CheckoutLicense`
for each dimension in `marketplace.json`, highest tier first, using the AWS
CLI that ships with AL2023 and the instance's IAM role. Marketplace issues each
contract dimension as a Count entitlement (MaxCount 1), so the checkout asks
for `Value=1,Unit=Count`, and the unit is returned at once with
`CheckInLicense`; a provisional checkout would otherwise hold it for an hour
and refuse the next check (v1.23.1; v1.23.0 asked for `Unit=None`, which
License Manager refuses).

- Licensed: the pack is used.
- Not licensed, or the check cannot be made (no role, no network): the
  command stops with an explanation and lists the VAREK Core packs. The Warden
  and the Core packs never depend on the license.
- `varek license` shows the status; `varek doctor` includes it.

This is a compliance check, not copy protection: the packs are readable text
on the buyer's own instance, and root there can use them directly. AWS
documents License Manager integration as optional for AMI contract products;
it is here so the subscription and the packs stay tied together.

`varek run --policy <enterprise pack>` checks the license on every run, so a
scheduled job that loses its instance role would stop. Choose the pack once
with `sudo varek policy use <pack>` and run without `--policy`.

Buyers attach a role with `iam/instance-license-policy.json` to the instance.
The usage instructions on the listing say so.

## Build it

Run the build in the seller AWS account. AWS CloudShell in us-east-1 already
has credentials, `git` and the AWS CLI.

### 1. Install Packer (once; it stays in your CloudShell home directory)

```bash
V=1.11.2
cd ~ && curl -fsSLO https://releases.hashicorp.com/packer/$V/packer_${V}_linux_amd64.zip \
     && curl -fsSLO https://releases.hashicorp.com/packer/$V/packer_${V}_SHA256SUMS
grep linux_amd64.zip packer_${V}_SHA256SUMS | sha256sum -c -
mkdir -p ~/bin && unzip -o packer_${V}_linux_amd64.zip -d ~/bin && rm packer_${V}_*
export PATH=~/bin:$PATH && packer version
```

CloudShell keeps your home directory between sessions; in a new session run
only the last line.

### 2. Get the source and the packs

```bash
git clone https://github.com/kwdoug63/varek.git
mkdir -p ~/varek-packs        # copy hipaa.policy.txt and soc2.policy.txt here
```

Upload the two pack files with CloudShell's **Actions > Upload file**, then
move them into `~/varek-packs`.

### 3. Build

A test image first (no Marketplace product needed):

```bash
cd varek/varek/v1_4/packaging/aws-marketplace
./build.sh --version 1.23.0 --packs ~/varek-packs --test
```

Then the image for the listing, with the product's ID for License Manager:

```bash
./build.sh --version 1.23.0 --packs ~/varek-packs --product-id <product ID>
```

AWS's License Manager guide calls this the "Product ID with a Globally Unique
Identifier (GUID) format", and the portal may also show a `prod-...` ID for
the same product. `build.sh` accepts either form; confirm which one License
Manager uses with a test license (below) before submitting the version.

#### Test the license check before the listing is live

License Manager can issue a license from your own account that looks like a
Marketplace one. Build with your account's issuer instead of Marketplace's:

```bash
ACCT=$(aws sts get-caller-identity --query Account --output text)
./build.sh --version 1.23.0-lmtest --packs ~/varek-packs --product-id <product ID> \
  --issuer-fingerprint "aws:$ACCT:Self:issuer-fingerprint"
```

Create a test license for that product SKU and a dimension in License Manager
([AWS guide](https://docs.aws.amazon.com/marketplace/latest/userguide/ami-license-manager-integration.html)),
launch the test AMI with a role carrying `iam/instance-license-policy.json`,
and run `varek license`. Never submit an `-lmtest` image to Marketplace.

`build.sh` stops if EBS encryption by default is on in the Region, because
Marketplace needs an unencrypted AMI; turn it off for the build and back on.

A build takes about 15 minutes and costs a few cents of EC2 time. It prints
the AMI ID at the end and writes it to `manifest.json`. If the default VPC has
been deleted, pass `--subnet subnet-...` for a subnet with internet access.

`install.sh` stops the build if anything is wrong: a pack without the
Enterprise header or one that does not lint, a runtime library missing after
the compiler is removed, or a smoke-test run whose refusal, audit or signed
export does not check out. `harden.sh` stops it if password or root login is
still possible, an account has a password, or private key material is found.

## Hand the AMI to AWS Marketplace

AWS Marketplace copies the AMI through a role in the seller account. Create it
once:

```bash
cd ~/varek/varek/v1_4/packaging/aws-marketplace
aws iam create-role --role-name AwsMarketplaceAmiIngestion \
  --assume-role-policy-document file://iam/marketplace-ami-ingestion-trust.json
aws iam attach-role-policy --role-name AwsMarketplaceAmiIngestion \
  --policy-arn arn:aws:iam::aws:policy/AWSMarketplaceAmiIngestion
aws iam get-role --role-name AwsMarketplaceAmiIngestion --query Role.Arn --output text
```

Then, in the AWS Marketplace Management Portal, open the product and choose
**Request changes > Update versions > Add a new version**. Give the AMI ID,
the role ARN above, the OS user `ec2-user`, port 22, and the usage
instructions. AWS scans the AMI before the version is accepted; scan failures
come back in the request's details.

## Before each release

- Rebuild for every VAREK release, and at least every few months, so the image
  carries current AL2023 patches. AWS rejects images with known critical or
  high CVEs and images older than two years.
- Build from a `HEAD` that has passed `make test-cli` and the release's tests;
  `build.sh` warns if the working tree has uncommitted changes, which are not
  in the image.
