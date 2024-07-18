"""Pulumi config to deploy EC2 server for dbtrag"""
import hashlib
import json
import os

import pulumi
from pulumi.resource import ResourceOptions
import pulumi_aws as aws
import pulumi_command as command
from jinja2 import Template, StrictUndefined


###########
# SECRETS #
###########

cfg = pulumi.Config()
jwt_secret_parameter = aws.ssm.get_parameter(name="/dbtrag/JWT_SECRET_KEY")

###############
# CREATE ROLE #
###############

dbtrag_role = aws.iam.role.Role(
    "dbtrag-ec2-role",
    assume_role_policy="""
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
""")

dbtrag_parameter_store_access_policy = aws.iam.Policy(
    "dbtrag-ec2-parameter-store-access-policy",
    path="/",
    description="Read access to dbtrag config in AWS SSM Parameter Store",
    policy=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ssm:GetParametersByPath",
                    "Resource": [
                        "arn:aws:ssm:eu-west-3:715988338250:parameter/dbtrag/",
                    ],
                }
            ],
        }
    ),
)

dbtrag_parameter_store_access_policy_attachment = aws.iam.RolePolicyAttachment(
    "dbtrag-ec2-parameter-store-access-policy-attachment",
    role=dbtrag_role.name,
    policy_arn=dbtrag_parameter_store_access_policy.arn
)

###########
# NETWORK #
###########

# We need fixed IPs (to whitelist them from carcans3 and Ximi)
dbtrag_server_elastic_ip = aws.ec2.Eip(
    "dbtrag-elastic-ip", vpc=True,
    tags={"Name": "dbtrag-elastic-ip"},
    opts=pulumi.ResourceOptions(
        protect=True  # Prevent this resource from being deleted
    )
)

# Managed security groups
dbtrag_ssh_and_egress_security_group = aws.ec2.SecurityGroup(
    "dbtrag-ssh-and-egress-security-group",
    description="Allow SSH and egress",
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": ["::/0"],
        }
    ],
    egress=[
        {
            "from_port": 0,
            "to_port": 0,
            "protocol": "-1",
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": ["::/0"],
        }
    ],
)

dbtrag_https_security_group = aws.ec2.SecurityGroup(
    "dbtrag-https-security-group",
    description="Allow HTTPS ingress",
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": ["::/0"],
        }
    ],
)

dbtrag_http_security_group = aws.ec2.SecurityGroup(
    "dbtrag-http-security-group",
    description="Allow HTTP ingress",
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 80,
            "to_port": 80,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": ["::/0"],
        }
    ],
)


#######
# DNS #
#######

dbtrag_rnd_domain = "dbtrag.rnd.ouihelp.fr"

rnd_zone = aws.route53.get_zone(
    name="rnd.ouihelp.fr",
    private_zone=False)

dbtrag_dns_record = aws.route53.Record(
    "dbtrag-dns-record",
    zone_id=rnd_zone.zone_id,
    name=dbtrag_rnd_domain,
    type="A",
    ttl=300,  # The TTL value in seconds. Adjust as needed.
    records=[dbtrag_server_elastic_ip.public_ip]
)

######################
# DEPLOYMENT SCRIPTS #
######################

etienne_ssh_key = ("ssh-ed25519 "
                   "AAAAC3NzaC1lZDI1NTE5AAAAICh/6pQ6xcrO/2y51XRxTWsDn1Wd8dQ+fcmPJA6d4ANz "
                   "etienne.callies@ouihelp.fr")
dbtrag_keypair = aws.ec2.KeyPair(
    f"dbtrag-keypair",
    public_key=etienne_ssh_key
)

app_name = "dbtrag"
deploy_app_script_name = "deploy_app.sh"
jinja2_kwargs = {
    "app_name": app_name,
    "deploy_app_script_name": deploy_app_script_name,
    "dbtrag_rnd_domain": dbtrag_rnd_domain,
    "letsencrypt_email": 'etienne.callies+letsencrypt@ouihelp.fr',
    "etienne_ssh_key": etienne_ssh_key,
    "timeout_in_seconds": 600,
    "jwt_secret_key": jwt_secret_parameter.value,
}

with open("deploy_app.sh.j2") as f:
    deploy_app_jinja2 = Template(f.read(), undefined=StrictUndefined)
deploy_app_script = deploy_app_jinja2.render(**jinja2_kwargs)

jinja2_kwargs['deploy_app_script'] = deploy_app_script
with open("first_install.sh.j2") as f:
    first_install_jinja2 = Template(f.read(), undefined=StrictUndefined)
dbtrag_user_data = first_install_jinja2.render(**jinja2_kwargs)

#######
# EC2 #
#######

# To get AMI owner, get one AMI id on console and then:
# aws ec2 describe-images --image-ids ami-01b32e912c60acdfa --region eu-west-3 | jq ".Images[0].OwnerId"
dbtrag_server_ami = aws.ec2.get_ami(
    most_recent=True,
    include_deprecated=False,
    owners=["099720109477"],
    filters=[
        {"name": "name", "values": ["*22.04*"]},
        {"name": "architecture", "values": ["x86_64"]},
    ],
)
pulumi.export("AMI", dbtrag_server_ami.name)

# Create an instance profile and attach the role
dbtrag_instance_profile = aws.iam.InstanceProfile(
    "exampleInstanceProfile",
    role=dbtrag_role.name
)

dbtrag_ec2_server = aws.ec2.Instance(
    "dbtrag-ec2-server",
    tags={"Name": "dbtrag-ec2-server"},
    instance_type="t3a.micro",
    vpc_security_group_ids=[dbtrag_ssh_and_egress_security_group.id,
                            dbtrag_http_security_group.id,
                            dbtrag_https_security_group.id],
    ami=dbtrag_server_ami.id,
    iam_instance_profile=dbtrag_instance_profile.name,
    user_data=dbtrag_user_data,
    key_name=dbtrag_keypair.key_name,
    # ipv6_address_count=1,
    root_block_device={"volume_size": 20},
    opts=ResourceOptions(depends_on=[dbtrag_dns_record]),
)

dbtrag_eip_assoc = aws.ec2.EipAssociation(
    f"dbtrag-eip-association",
    instance_id=dbtrag_ec2_server.id,
    allocation_id=dbtrag_server_elastic_ip.id,
    opts=ResourceOptions(depends_on=[dbtrag_ec2_server]),
)


##################
# APP DEPLOYMENT #
##################

def command_with_retry(command_to_execute, max_retries=5, retry_interval_seconds=5):
    return pulumi.Output.concat(
        'for i in {1..', str(max_retries),
        '}; do ', command_to_execute,
        '; [ $? -eq 0 ] && exit 0; echo "Attempt $i failed. Retrying in ',
        str(retry_interval_seconds), ' seconds..."; sleep ', str(retry_interval_seconds),
        '; done; echo "Command failed after ', str(max_retries), ' attempts."')


# Function to compute the hash of a directory's contents
def compute_directory_hash(directory):
    sha = hashlib.sha256()
    # Walk through each files in the directory and sub-directories
    for root, dirs, files in os.walk(directory):
        for names in files:
            filepath = os.path.join(root, names)
            # Read file as bytes and update hash
            with open(filepath, 'rb') as file:
                sha.update(file.read())
    return sha.hexdigest()


# RSYNC dbtrag_optimization directory
# exclude this directory (ops) and other files/directories excluded by .gitignore
rsync_command = pulumi.Output.concat(
        "rsync -e 'ssh -o StrictHostKeyChecking=no' -rz --stats "
        "--exclude='ops' --exclude='tests' --exclude='docs' --exclude='.github' "
        "--exclude='.githooks' --exclude-from=../.gitignore "
        ".. ubuntu@",
        dbtrag_rnd_domain, ":", app_name
)

# Use a Pulumi asset with the hash as the data, which will trigger when the hash changes
trigger_file_hash = pulumi.asset.StringAsset(compute_directory_hash('..'))

rsync_dbtrag_command = command.local.Command(
    "rsync-dbtrag-command",
    create=command_with_retry(rsync_command),
    triggers=[trigger_file_hash.text],
    opts=ResourceOptions(depends_on=[dbtrag_ec2_server, dbtrag_eip_assoc]),
)

# Export the standard output of the command
pulumi.export('rsync command', rsync_command)
# pulumi.export('rsync command output', rsync_dbtrag_command.stdout)

dbt_project_root = '../../hourtin2/dbt_project_bi'
# exclude this directory (ops) and other files/directories excluded by .gitignore
dbt_rsync_command = pulumi.Output.concat(
        "rsync -e 'ssh -o StrictHostKeyChecking=no' -rz --stats "
        "--exclude='dbt_packages' --exclude='logs' --exclude='.github' "
        "--exclude='tests' ", dbt_project_root, " ubuntu@",
        dbtrag_rnd_domain, ":~"
)

# Use a Pulumi asset with the hash as the data, which will trigger when the hash changes
dbt_trigger_file_hash = pulumi.asset.StringAsset(compute_directory_hash(dbt_project_root))

dbt_rsync_dbtrag_command = command.local.Command(
    "dbt-rsync-dbtrag-command",
    create=command_with_retry(dbt_rsync_command),
    triggers=[dbt_trigger_file_hash.text],
    opts=ResourceOptions(depends_on=[rsync_dbtrag_command]),
)

# Export the standard output of the command
pulumi.export('dbt rsync command', dbt_rsync_command)


# (Re-) deploy Flask app
ssh_deploy_command = pulumi.Output.concat(
    "ssh -o StrictHostKeyChecking=no ubuntu@", dbtrag_rnd_domain,
    " /home/ubuntu/", deploy_app_script_name
)

deploy_dbtrag_command = command.local.Command(
    "deploy-dbtrag-command",
    create=command_with_retry(ssh_deploy_command),
    triggers=[rsync_dbtrag_command.stdout],
    opts=ResourceOptions(depends_on=[dbt_rsync_dbtrag_command]),
)

# Export the standard output of the command
pulumi.export('deploy command', ssh_deploy_command)
pulumi.export('deploy command output', deploy_dbtrag_command.stdout)

##########
# OUTPUT #
##########

pulumi.export("Outgoing IP (not needed)", dbtrag_server_elastic_ip.public_ip)
pulumi.export("dbtrag DNS", dbtrag_rnd_domain)
