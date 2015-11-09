#!/usr/bin/env python
"""A VPC with a pair of public and private subnets.

The pairs of subnets are aligned in separate availability zones allowing you to
create highly available applications. A NAT instance is launched into each
public subnet and routing is configured so that instances in the private subnet
can access the Internet through those NAT instances.
"""
from troposphere import (
    FindInMap,
    GetAtt,
    GetAZs,
    Join,
    Output,
    Parameter,
    Ref,
    Select,
    Tags,
    Template,
    cloudwatch,
)
from troposphere.ec2 import (
    EIP,
    Instance,
    InternetGateway,
    NetworkAcl,
    NetworkAclEntry,
    PortRange,
    Route,
    RouteTable,
    SecurityGroup,
    SecurityGroupIngress,
    SecurityGroupRule,
    Subnet,
    SubnetNetworkAclAssociation,
    SubnetRouteTableAssociation,
    Tag,
    VPC,
    VPCEndpoint,
    VPCGatewayAttachment,
)

# Making these cloud formation parameters is kind of hard. These seem like
# sensible defaults and we can easily change the python to generate new json if
# need be, even on a case by case basis.
vpc_cidr = '10.1.0.0/20'
private_cidrs = ['10.1.0.0/22', '10.1.4.0/22']
public_cidrs = ['10.1.8.0/24', '10.1.9.0/24']

t = Template()

t.add_version("2010-09-09")
t.add_description(__doc__.replace("\n", " "))


def add_autorecovery_to_instance(template_obj, instance):
    """Creates a cloudwatch alarm to recover a failed instance."""
    # This url was really helpful in configuring this:
    #   http://docs.aws.amazon.com/ \
    #       AWSEC2/latest/UserGuide/UsingAlarmActions.html
    template_obj.add_resource(cloudwatch.Alarm(
        'InstanceAutoRecovery%s' % (instance.name,),
        ActionsEnabled='true',
        AlarmActions=[
            Join('',
                ['arn:aws:automate:', Ref('AWS::Region'), ':ec2:recover']
            )
        ],
        AlarmDescription='Recover failed instance',
        ComparisonOperator='GreaterThanThreshold',
        Dimensions=[cloudwatch.MetricDimension(
            Name='InstanceId',
            Value=Ref(instance)
        )],
        EvaluationPeriods=2,
        MetricName='StatusCheckFailed_System',
        Namespace='AWS/EC2',
        Period=60,
        Statistic='Average',
        Threshold='0',
    ))


trusted_cidr = t.add_parameter(Parameter(
    "TrustedCidr",
    Type="String",
    Description=
        "This network range will be permitted to SSH to your NAT instance",
    ConstraintDescription=
        "must be a valid IP CIDR range of the form x.x.x.x/x.",
    MinLength="9",
    AllowedPattern="(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})",
    MaxLength="18",
))

keyname_param = t.add_parameter(Parameter(
    "SshKeyName",
    Description="Name of an existing EC2 KeyPair to enable SSH "
                "access to NAT instances. If not specified no key is used.",
    Default="AWS::NoValue",
    Type="AWS::EC2::KeyPair::KeyName",
))


# These are standard freely available Amazon NAT AMIs
t.add_mapping('RegionMap', {
    'us-west-1': {
        'NATAMI': 'ami-ada746e9',
    },
    'us-west-2': {
        'NATAMI': 'ami-75ae8245',
    },
    'us-east-1': {
        'NATAMI': 'ami-b0210ed8',
    }
})

VPC = t.add_resource(VPC(
    "VPC",
    EnableDnsSupport="true",
    CidrBlock=vpc_cidr,
    EnableDnsHostnames="true",
    Tags=Tags(
        Name=Ref("AWS::StackName"),
        Application=Ref("AWS::StackName"),
        Network="VPN Connected VPC",
    )
))

internet_gateway = t.add_resource(
    InternetGateway(
        'InternetGateway',
        Tags=Tags(
            Name=Ref("AWS::StackName"),
            Application=Ref("AWS::StackName")
        ),
))

t.add_resource(
    VPCGatewayAttachment(
        'AttachGateway',
        VpcId=Ref(VPC),
        InternetGatewayId=Ref(internet_gateway)))

PrivateNetworkAcl = t.add_resource(NetworkAcl(
    "PrivateNetworkAcl",
    VpcId=Ref(VPC),
    Tags=Tags(
        Name=Join("", ["Private", Ref("AWS::StackName")]),
        Application=Ref("AWS::StackName"),
        Network="Private",
    )
))
PublicNetworkAcl = t.add_resource(NetworkAcl(
    "PublicNetworkAcl",
    VpcId=Ref(VPC),
    Tags=Tags(
        Name=Join("", ["Public", Ref("AWS::StackName")]),
        Application=Ref("AWS::StackName"),
        Network="Public",
    )
))

def add_acl_entry(t, acl, egress, name, number, proto, port, cidr):
    if egress:
        egress = "true"
    else:
        egress = "false"
    if isinstance(port, (list, tuple)):
        port_range = PortRange(From="%d" %(port[0],), To="%d" % (port[1],))
    else:
        port_str = "%d" % (port,)
        port_range = PortRange(From=port_str, To=port_str)

    t.add_resource(NetworkAclEntry(
        name,
        NetworkAclId=Ref(acl),
        RuleNumber="%d" % (number,),
        Protocol="%d" % (proto,),
        PortRange=port_range,
        Egress=egress,
        RuleAction="allow",
        CidrBlock=cidr,
    ))

def add_public_ingress_acl_entry(name, number, proto, port, src_cidr):
    acl = PublicNetworkAcl
    return add_acl_entry(t, acl, False, name, number, proto, port, src_cidr)

def add_private_ingress_acl_entry(name, number, proto, port, src_cidr):
    acl = PrivateNetworkAcl
    return add_acl_entry(t, acl, False, name, number, proto, port, src_cidr)

def add_public_egress_acl_entry(name, number, proto, port, dst_cidr):
    acl = PublicNetworkAcl
    return add_acl_entry(t, acl, True, name, number, proto, port, dst_cidr)

def add_private_egress_acl_entry(name, number, proto, port, dst_cidr):
    acl = PrivateNetworkAcl
    return add_acl_entry(t, acl, True, name, number, proto, port, dst_cidr)

# This next block of code deals with the configuration of Network ACLs. The
# default configuration here allows access to the Internet using tcp/80 (HTTP),
# tcp/443 (HTTPS) and udp/123 (NTP) access to the Internet.
# These ACLs also permit SSH from the trusted cidr to the public subnet and
# permit SSH from the public subnet to the private subnet.
# Nothing else is explicitly permitted and thus nothing else works.
#
# When making changes here don't forget to also make changes in the
# corresponding security group(s)
# And remember that NACLs are stateless.
#    http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html

# Our public network ACLs
public_egress_acl_entries = [
    ('PublicAllowHTTPSOut', 100, 6, 443, '0.0.0.0/0'),
    ('PublicAllowHTTPOut', 110, 6, 80, '0.0.0.0/0'),
    ('PublicAllowTCPResponsesOut', 120, 6, (1024, 65535), '0.0.0.0/0'),
    ('PublicAllowSSHToPrivateInstances', 130, 6, 22, vpc_cidr),
    ('PublicAllowNTPOut', 140, 17, 123, '0.0.0.0/0'),
    ('PublicAllowBrktOut', 150, 6, (7001, 7002), '0.0.0.0/0')
]
for entry in public_egress_acl_entries:
    add_public_egress_acl_entry(*entry)

public_ingress_acl_entries = [
    ('PublicAllowTCPResponsesIn', 100, 6, (1024, 65535), '0.0.0.0/0'),
    ('PublicAllowSSHIn', 110, 6, 22, Ref(trusted_cidr)),
    ('PublicAllowHTTPSThrough', 120, 6, 443, vpc_cidr),
    ('PublicAllowHTTPThrough', 130, 6, 80, vpc_cidr),
    ('PublicAllowNTPResponsesIn', 140, 17, 123, '0.0.0.0/0'),
    ('PublicAllowBrktIn', 150, 6, (7001, 7002), '0.0.0.0/0')
]
for entry in public_ingress_acl_entries:
    add_public_ingress_acl_entry(*entry)

# Our private network ACLs
private_egress_acl_entries = [
    ('PrivateAllowHTTPSOut', 100, 6, 443, '0.0.0.0/0'),
    ('PrivateAllowHTTPOut', 110, 6, 80, '0.0.0.0/0'),
    ('PrivateAllowTCPResponsesOut', 120, 6, (1024, 65535), vpc_cidr),
    ('PrivateAllowNTPOut', 130, 17, 123, '0.0.0.0/0'),
    ('PrivateAllowBrktOut', 140, 6, (7001, 7002), '0.0.0.0/0')
]
for entry in private_egress_acl_entries:
    add_private_egress_acl_entry(*entry)

private_ingress_acl_entries = [
    ('PrivateAllowTCPResponsesIn', 100, 6, (1024, 65535), '0.0.0.0/0'),
    ('PrivateAllowSSHConnectionsIn', 110, 6, 22, vpc_cidr),
    ('PrivateAllowNTPResponsesIn', 120, 17, 123, '0.0.0.0/0'),
]
for entry in private_ingress_acl_entries:
    add_private_ingress_acl_entry(*entry)


PublicRouteTable = t.add_resource(RouteTable(
    "PublicRouteTable",
    VpcId=Ref("VPC"),
    Tags=Tags(
        Name=Join("", ["Public", Ref("AWS::StackName")]),
        Application=Ref("AWS::StackName"),
        Network="Public",
    )
))
t.add_resource(
    Route(
        'Route',
        DependsOn='AttachGateway',
        GatewayId=Ref(internet_gateway),
        DestinationCidrBlock='0.0.0.0/0',
        RouteTableId=Ref(PublicRouteTable),
    ))

public_subnets = []
for idx, public_cidr in enumerate(public_cidrs):
    public_subnets.append(t.add_resource(Subnet(
        "PublicSubnet%d" % (idx,),
        VpcId=Ref(VPC),
        CidrBlock=public_cidr,
        AvailabilityZone=Select(idx, GetAZs()),
        Tags=Tags(
            Name=Join("", ["Public", Ref("AWS::StackName")]),
            Application=Ref("AWS::StackName"),
            Network="Public",
        )
    )))
    t.add_resource(
        SubnetNetworkAclAssociation(
            "PublicSubnetNetworkAclAssociation%d" % (idx,),
            SubnetId=Ref(public_subnets[-1]),
            NetworkAclId=Ref(PublicNetworkAcl),
        )
    )
    t.add_resource(
        SubnetRouteTableAssociation(
            'PublicSubnetRouteTableAssociation%d' % (idx,),
            SubnetId=Ref(public_subnets[-1]),
            RouteTableId=Ref(PublicRouteTable),
        ))

# By allowing our VPC cidr to send traffic to us on these ports we're
# effectively allowing them to get through us to the Internet. We assume that
# legitimate internet services only run on ports < 1024.
internet_client_sg = t.add_resource(SecurityGroup(
    "InternetClientSG",
    VpcId=Ref(VPC),
    GroupDescription="Instances in this group may access Internet through NAT",
))

# Broken out into SecurityGroupIngress because of circular dependency
allow_ssh_from_nat = t.add_resource(SecurityGroupIngress(
    "AllowSshFromNatIngressRule",
    IpProtocol="tcp",
    FromPort="22",
    ToPort="22",
    GroupId=Ref(internet_client_sg),
    SourceSecurityGroupId=Ref("NATSecurityGroup"),
))

# These rules govern what traffic our internet clients can send to our NAT
# instance. In effect this is the set of traffic that is permitted to flow
# through the NAT instances toward the Internet.
internet_client_rules = [
    # tcp/80 (http)
    SecurityGroupRule(
        IpProtocol="tcp",
        FromPort="80",
        ToPort="80",
        SourceSecurityGroupId=Ref(internet_client_sg),
    ),
    # tcp/443 (https)
    SecurityGroupRule(
        IpProtocol="tcp",
        FromPort="443",
        ToPort="443",
        SourceSecurityGroupId=Ref(internet_client_sg),
    ),
    # tcp/7001 tcp/7002 (brkt traffic)
    SecurityGroupRule(
        IpProtocol="tcp",
        FromPort="7001",
        ToPort="7002",
        SourceSecurityGroupId=Ref(internet_client_sg),
    ),
    # A rule to allow the use of udp/123 (NTP)
   SecurityGroupRule(
        IpProtocol="udp",
        FromPort="123",
        ToPort="123",
        SourceSecurityGroupId=Ref(internet_client_sg),
    ),
]

# A rule to allow SSH from our trusted cidr
ssh_in_rule = SecurityGroupRule(
    IpProtocol="tcp",
    FromPort="22",
    ToPort="22",
    CidrIp=Ref(trusted_cidr),
)
nat_in_rules = internet_client_rules + [ssh_in_rule]
nat_sg = t.add_resource(SecurityGroup(
    "NATSecurityGroup",
    VpcId=Ref(VPC),
    GroupDescription="Controls traffic to our NAT instances",
    SecurityGroupIngress=nat_in_rules,
))

nat_instances = []
for idx, public_subnet in enumerate(public_subnets):
    nat_instances.append(t.add_resource(
        Instance(
            'NatInstance%d' % (idx,),
            KeyName=Ref(keyname_param),
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), 'NATAMI'),
            SecurityGroupIds=[
                Ref(nat_sg)
            ],
            SubnetId=Ref(public_subnet),
            InstanceType='t2.small',
            SourceDestCheck=False,
            Tags=[Tag('Name', 'NatGateway%d' % (idx,))],
            DependsOn='AttachGateway',
        )
    ))
    add_autorecovery_to_instance(t, nat_instances[-1])
    nat_eip = t.add_resource(
        EIP('NATEIP%d' % (idx,),
            DependsOn='AttachGateway',
            Domain='vpc',
            InstanceId=Ref(nat_instances[-1])
    ))

private_subnets = []
private_route_tables = []
for idx, private_cidr in enumerate(private_cidrs):
    private_subnets.append(t.add_resource(Subnet(
        "PrivateSubnet%d" % (idx,),
        VpcId=Ref(VPC),
        CidrBlock=private_cidr,
        AvailabilityZone=GetAtt(public_subnets[idx], 'AvailabilityZone'),
        Tags=Tags(
            Name=Join("", ["Private", Ref("AWS::StackName")]),
            Application=Ref("AWS::StackName"),
            Network="Private",
        )
    )))
    t.add_resource(
        SubnetNetworkAclAssociation(
            "PrivateSubnetNetworkAclAssociation%d" % (idx,),
            SubnetId=Ref(private_subnets[-1]),
            NetworkAclId=Ref(PrivateNetworkAcl),
        )
    )

    private_route_tables.append(t.add_resource(RouteTable(
        "PrivateRouteTable%d" % (idx,),
        VpcId=Ref(VPC),
        Tags=Tags(
            Application=Ref("AWS::StackName"),
            Network="VPN Connected Subnet",
        )
    )))
    t.add_resource(Route(
        "PrivateRoute%d" % (idx,),
        InstanceId=Ref(nat_instances[idx]),
        DestinationCidrBlock="0.0.0.0/0",
        RouteTableId=Ref(private_route_tables[-1]),
    ))
    t.add_resource(
        SubnetRouteTableAssociation(
            'PrivateSubnetRouteTableAssociation%d' % (idx,),
            SubnetId=Ref(private_subnets[-1]),
            RouteTableId=Ref(private_route_tables[-1]),
        ))

# Route all S3 traffic from all of our subnets through this vpc endpoint
t.add_resource(VPCEndpoint(
    "s3VpcEndpoint",
    RouteTableIds=[
        Ref(PublicRouteTable)] + [Ref(x) for x in private_route_tables],
    ServiceName=Join("", ["com.amazonaws.", Ref("AWS::Region"), ".s3"]),
    VpcId=Ref(VPC),
))

# Now we're configuring template outputs. We're done!
for idx, private_subnet in enumerate(private_subnets):
    t.add_output(Output(
        "PrivateSubnet%d" % (idx,),
        Description="SubnetId of a private subnet for %s" % (
            private_cidrs[idx],),
        Value=Ref(private_subnet),
    ))
    t.add_output(Output(
        "PrivateSubnetAvailabilityZone%d" % (idx,),
        Description="AZ of the private subnet for %s" % (private_cidrs[idx],),
        Value=GetAtt(private_subnet, 'AvailabilityZone'),
    ))

VPCId = t.add_output(Output(
    "VPCId",
    Description="VPCId of the newly created VPC",
    Value=Ref(VPC),
))

print(t.to_json())
