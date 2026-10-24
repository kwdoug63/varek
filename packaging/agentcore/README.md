# Measuring AgentCore Runtime's container (v1.35 step 1, D8)

AgentCore Runtime's API gives a container nothing but its image
(`containerConfiguration` has `containerUri` only), and no page AWS
publishes says what the container may do. D8 in
`docs/security/v1.35-frameworks.md` waits on these facts. They are measured
from inside a session, by this probe:

- the container's user, capabilities, `NoNewPrivs` and seccomp state;
- whether it can load a filter that hands calls to a supervisor (the
  Warden's listener), with and without `NoNewPrivs`;
- which namespaces it can make (user, mount, PID, network, cgroup, IPC, UTS);
- whether a parent can take its child's descriptors (`pidfd_getfd`) and
  read its memory (`process_vm_readv`);
- the cgroup file system, and whether it can make a group;
- whether its root is writable; Landlock's ABI; the LSMs; the architecture;
- then `varek doctor`, and a real run: `varek run -- /bin/cat /etc/os-release`
  under the baseline policy, with `varek refusals` on its stream.

The probe answers AgentCore Runtime's container contract: HTTP on port 8080,
`GET /ping` and `POST /invocations`. Each invocation returns the report as
JSON. Of the environment it reports the variables' names, never their values.

Cost: one Graviton instance for about an hour (t4g.large, about $0.07 an
hour), an ECR repository holding about 300 MB, and AgentCore Runtime's
per-second charge for a few invocations, cents in all.

What is measured is AgentCore Runtime's default compute (AWS-managed
microVMs, arm64). The "Instances" compute type (a capacity provider, EC2 in
the account's own VPC, x86_64 or arm64) is a second measurement, at the end.

## 1. Roles (AWS CloudShell, in us-east-1)

Open CloudShell from the console's top bar, in **us-east-1**. These commands
run there, with the console's own sign-in; nothing below asks for a key.

```bash
export AWS_REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# the builder instance's role: push to ECR, and Session Manager (no SSH key)
aws iam create-role --role-name varek-probe-builder \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name varek-probe-builder \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser
aws iam attach-role-policy --role-name varek-probe-builder \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam create-instance-profile --instance-profile-name varek-probe-builder
aws iam add-role-to-instance-profile --instance-profile-name varek-probe-builder \
  --role-name varek-probe-builder

# the runtime's role: pull the image, write its logs
aws iam create-role --role-name varek-probe-runtime \
  --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"bedrock-agentcore.amazonaws.com\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"$ACCOUNT\"}}}]}"
aws iam put-role-policy --role-name varek-probe-runtime --policy-name pull-and-log \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
    {\"Effect\":\"Allow\",\"Action\":[\"ecr:BatchGetImage\",\"ecr:GetDownloadUrlForLayer\"],\"Resource\":\"arn:aws:ecr:us-east-1:$ACCOUNT:repository/varek-agentcore-probe\"},
    {\"Effect\":\"Allow\",\"Action\":\"ecr:GetAuthorizationToken\",\"Resource\":\"*\"},
    {\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\",\"logs:DescribeLogStreams\"],\"Resource\":\"arn:aws:logs:us-east-1:$ACCOUNT:log-group:/aws/bedrock-agentcore/runtimes/*\"}]}"

aws ecr create-repository --repository-name varek-agentcore-probe
```

## 2. The builder (CloudShell, then the instance)

In CloudShell, start a Graviton instance with that profile (Amazon Linux
2023, arm64; the default VPC's subnet; no key pair):

```bash
AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 \
      --query Parameter.Value --output text)
aws ec2 run-instances --image-id "$AMI" --instance-type t4g.large \
  --iam-instance-profile Name=varek-probe-builder \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=varek-probe-builder}]' \
  --query 'Instances[0].InstanceId' --output text
```

(If the profile is not found yet, wait ten seconds and run it again: a new
profile takes a moment to reach EC2.) Then, in the EC2 console, select
**varek-probe-builder**, **Connect**, **Session Manager**, **Connect**. The
rest of this section runs **on the instance**, in that browser shell:

```bash
sudo dnf -y -q install docker git
sudo systemctl start docker
cd ~ && git clone -q --branch claude/varek-roadmap-landing-01dbw5 https://github.com/kwdoug63/varek.git && cd varek
export AWS_REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-agentcore-probe

sudo docker build -q -f packaging/container/Containerfile -t varek:arm64 .
sudo docker build -q --build-arg BASE=varek:arm64 -f packaging/agentcore/Containerfile -t $REPO:1 .

# a smoke test: the probe answers here, in Docker's default settings
sudo docker run --rm --entrypoint python3 $REPO:1 /opt/varek/agentcore_probe.py --once \
  | head -c 400; echo

aws ecr get-login-password | sudo docker login -u AWS --password-stdin $ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
sudo docker push -q $REPO:1
```

The first build takes about ten minutes. `docker login` takes ECR's token
from the instance's role, through the pipe; it is never shown or typed.

## 3. The runtime (CloudShell)

Back in CloudShell:

```bash
export AWS_REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws bedrock-agentcore-control create-agent-runtime --agent-runtime-name varek_probe \
  --agent-runtime-artifact "containerConfiguration={containerUri=$ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/varek-agentcore-probe:1}" \
  --role-arn arn:aws:iam::$ACCOUNT:role/varek-probe-runtime \
  --network-configuration networkMode=PUBLIC \
  --protocol-configuration serverProtocol=HTTP \
  --query agentRuntimeArn --output text | tee runtime.arn

# wait for READY (a minute or two)
RID=$(cut -d/ -f2 runtime.arn)
until s=$(aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id $RID --query status --output text); \
      [ "$s" = READY ] || [ "${s%FAILED}" != "$s" ]; do echo "$s"; sleep 10; done; echo "$s"
```

If it ends `CREATE_FAILED`, show the reason:
`aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id $RID --query failureReason`.

Invoke it twice (a new session each time; a session id has at least 33
characters):

```bash
for i in 1 2; do
  aws bedrock-agentcore invoke-agent-runtime --agent-runtime-arn "$(cat runtime.arn)" \
    --runtime-session-id "varek-probe-$(date +%s)-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    --content-type application/json --cli-binary-format raw-in-base64-out --payload '{}' probe-$i.json
done
python3 -c "import json; d=json.load(open('probe-1.json')); print(json.dumps({k: d[k] for k in ('machine','status','seccomp_listener','seccomp_listener_after_no_new_privs','namespaces','peer','landlock_abi')}, indent=1)); print('varek run exit:', d.get('varek_run',{}).get('exit'))"
```

Send me `probe-1.json` and `probe-2.json` (CloudShell: **Actions**,
**Download file**, `/home/cloudshell-user/probe-1.json`), or paste the
`python3` line's output if the files cannot be shared. Neither holds a
secret: the environment's names only.

## 4. Optional: the Instances compute type

The same probe on EC2 that AgentCore manages in the account (x86_64 or
arm64). It needs a capacity provider, with an operator role and the VPC's
subnets and security groups; it is set up only if the default compute
cannot carry the Warden, since an agent there is on EC2 anyway (where
v1.32's image and v1.34's cluster already run). The commands come then.

## 5. Teardown (CloudShell)

```bash
export AWS_REGION=us-east-1
aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id $(cut -d/ -f2 runtime.arn)
aws ecr delete-repository --repository-name varek-agentcore-probe --force
IID=$(aws ec2 describe-instances --filters Name=tag:Name,Values=varek-probe-builder \
      Name=instance-state-name,Values=pending,running,stopped --query 'Reservations[].Instances[].InstanceId' --output text)
[ -n "$IID" ] && aws ec2 terminate-instances --instance-ids $IID --query 'TerminatingInstances[].CurrentState.Name'
aws iam remove-role-from-instance-profile --instance-profile-name varek-probe-builder --role-name varek-probe-builder
aws iam delete-instance-profile --instance-profile-name varek-probe-builder
aws iam detach-role-policy --role-name varek-probe-builder --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser
aws iam detach-role-policy --role-name varek-probe-builder --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam delete-role --role-name varek-probe-builder
aws iam delete-role-policy --role-name varek-probe-runtime --policy-name pull-and-log
aws iam delete-role --role-name varek-probe-runtime
```

Then check nothing is left: `aws bedrock-agentcore-control list-agent-runtimes`
lists none named `varek_probe`, and the EC2 console shows the instance
terminated.
