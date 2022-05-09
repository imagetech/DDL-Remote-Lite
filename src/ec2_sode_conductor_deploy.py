import os
from aws_cdk import ( Stack, aws_ec2)
from constructs import Construct
import boto3
import botocore
import json

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
#import aws_iam as iam

SAT_OVERVIEW_FILE="satellite_config/sat_overview.json";
CDK_USER_DATA_FILE= "./scripts/soda_conductor_user_data.py"
SODA_EXTERNAL_SERVER_IP=''

# read from overview json
HOME_VPC=''
CONDUCTOR_AMI=''
REQ_INSTANCE_TYPE=''
GLOBAL_CONTROL_KEYPAIR=''
PROFILE = ''
CONTROL_IP=''             # ip of machine running and accessing Sat infrastructure
CONDUCTOR_EIP=''            # ip of Ec2 with Conductor



CDK_DEFAULT_ACCOUNT=os.getenv('CDK_DEFAULT_ACCOUNT')

boto_session = ''

print("#################################### ec2_portal_deploy ###############################")
class Ec2DeployConductorStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        print("kwargs:" + str(kwargs))

        global boto_session

        ## dicts to store the requested parameters and their matching created object
        #  store the requested parameters for the ec2 being deployed
        self.ec2_requested_params = {}
        # store the derived launch parameters for the ec2 being deployed
        self.ec2_launch_params = {}


        # read overview config json
        sat_config = self.readSatelliteConfig()

        # set up global boto session
        boto_session = boto3.Session(profile_name=PROFILE)

        self.CDK_TARGET_REGION=os.getenv('CDK_TARGET_REGION')

        # review passed parameters
        passed_params = kwargs.get("env", {})
        print("passed_params:" + str(passed_params))
        self.ec2_requested_params['env'] =passed_params
        self.ec2_requested_params['target_region'] = self.CDK_TARGET_REGION

        # get the VPC id if not explixitly set
        if HOME_VPC:
            self.ec2_requested_params['vpc_name'] = HOME_VPC
            print("Explicit VPC Set:" + HOME_VPC)
        else:
            self.getDefaultVPC()
            print("No VPC Set so using default")

        ## set the parameters requested for the instance
        self.setEc2RequestedParameters()
        print("REQUESTED PARAMETERS:" + str(self.ec2_requested_params))


        # set admin keypair (global for customer)
        self.ec2_launch_params['keypair'] = GLOBAL_CONTROL_KEYPAIR
        # get ami image to use
        self.ec2_launch_params['ami_image'] = self.getAMI_image()

        # determine instance type for ec2
        self.ec2_launch_params['instance_type'] = self.getInstanceType()
        self.ec2_launch_params['instance_name'] = self.ec2_requested_params.get("instance_name", None)

        # get VPC to lanuch in
        self.ec2_launch_params['vpc'] = self.getVPC()
        
        # create role 
        self.ec2_launch_params['ec2_role']  = self.createRole()

        # setup security groups (inbound/outbound roles)
        self.ec2_launch_params['sec_grp'] = self.setupSecurityRules()

        self.createWorkstation()



    ###################################################
    ## helper functions
    ####################################
    
    # get the VPC id for the default VPC to deploy in
    def getDefaultVPC(self):
    
        target_region = self.ec2_requested_params['target_region']
        print("target_region------:" + str(target_region))
        vpc_client = boto3.client("ec2", region_name=target_region)

        # get all VPCs in the region
        response = vpc_client.describe_vpcs()
        print("VPC ID response:" + str(response))   
        vpcs = response.get("Vpcs", None)

        # find the default VPC
        for curr_vpc in vpcs:
            print("Current VPC:" + str(curr_vpc))
            if curr_vpc.get("IsDefault", None):
                vpc_id = curr_vpc.get("VpcId")

        print("VPC ID:" + str(vpc_id))
            
        self.ec2_requested_params["vpc_name"] = vpc_id

        if not vpc_id:
            print ('Failed finding VPC')
            return None
            
        return vpc_id


    def getVPC(self):

        vpc_name = self.ec2_requested_params.get("vpc_name", None)
        print (f'Using VPC: {vpc_name}')
        vpc = aws_ec2.Vpc.from_lookup(self, 'vpc', vpc_id=vpc_name)
        if not vpc:
            print ('Failed finding VPC')
            return None
                
        return vpc

    def getInstanceType(self):

        req_instance_type = self.ec2_requested_params.get("req_instance_type", None)

        print (f'Looking up instance type: {req_instance_type}')
        instance_type = aws_ec2.InstanceType(req_instance_type)
        if not instance_type:
            print ('Failed finding instance')
            return None

        return instance_type

    def getAMI_image(self):

        ami_name = self.ec2_requested_params.get("ami_name", None)
        print (f'Looking up AMI: {ami_name}')
        
        #ami_image = aws_ec2.MachineImage().lookup(name=ami_name)
        ami_image = aws_ec2.LookupMachineImage(name=ami_name)
        if not ami_image:
            print ('Failed finding AMI image')
            return
        else:
            print ('Found AMI image:' + str(ami_image))

        return ami_image

    # check VPC id exists in the account region
    def getVPCid(self):

        client = boto_session.client('ec2',region_name=self.region)
        response = client.describe_vpcs()

        vpc_id=''
        results = response['Vpcs']
        if results:
            print("VPC:" + str(results))
            for vpc_info in results:
                vpc_id = vpc_info.get("VpcId", None)
                if vpc_id == HOME_VPC:
                    print("Matched VPC ID:" + str(vpc_id))
                    break
        else:
            print('No vpcs found')

        return vpc_id

    ##################
    ### GLOBAL helpers
    def getAccountID(self):
      
        print("Returned Account ID:" + str(CDK_DEFAULT_ACCOUNT))

        return CDK_DEFAULT_ACCOUNT

    ######################################################################################
    ## set the parameters that will eventually passed to start a particular ec2 instance
    ## TODO for now set here
    def setEc2RequestedParameters(self):

        print(f'Set Requested EC2 parameters')

        # TODO set with passed params
        self.ec2_requested_params['instance_name'] = 'DDL Satellite SoDA Conductor'

        print("Set AMI:" + str(CONDUCTOR_AMI))
        self.ec2_requested_params['ami_name'] = CONDUCTOR_AMI

        self.ec2_requested_params['role_name'] = "DDL-SAT_Conductor_Role"
        self.ec2_requested_params['profile'] = PROFILE

        # derived from account
        self.ec2_requested_params['req_instance_type'] = REQ_INSTANCE_TYPE
        self.ec2_requested_params['vpc'] = HOME_VPC

        self.inbound_rules = []             ## inbound rules
        
        self.ec2_launch_params['ec2_role'] = None

        ## TODO TEMP set vals
        #self.CDK_REGION=os.getenv('CDK_TARGET_REGION')
        #print('***Deploy region:' + str(self.CDK_REGION))

        self.ec2_requested_params['vpc_name'] = self.getVPCid()
        print('***Using VPC:' + str(self.ec2_requested_params['vpc_name']))

        return 

    # read the overview json to get the configuration for the satellite deployment
    def readSatelliteConfig(self):

        global CONDUCTOR_AMI
        global HOME_VPC
        global REQ_INSTANCE_TYPE
        global GLOBAL_CONTROL_KEYPAIR
        global PROFILE
        global CONTROL_IP
        global CONDUCTOR_IP

        with open(SAT_OVERVIEW_FILE) as sat_config:
            config_json = json.load(sat_config)
  
        # check for explicit VPC or default
        HOME_VPC =  config_json.get("HOME_VPC", None)
        if  not HOME_VPC:
            print("No VPC Set so using default")
        else:
            print("Explicit VPC Set:" + HOME_VPC)

        # get the source AMI - CONDUCTOR_AMI
        CONDUCTOR_AMI =  config_json.get("CONDUCTOR_AMI", None)
        print("Read CONDUCTOR_AMI:" + CONDUCTOR_AMI)
        if  not CONDUCTOR_AMI:
            print("No AMI set in sat_overview.json")
            exit()
        else:
            print("Set CONDUCTOR_AMI:" + CONDUCTOR_AMI)

        # get the required instance type
        REQ_INSTANCE_TYPE =  config_json.get("REQ_INSTANCE_TYPE", None)
        print("Read REQ_INSTANCE_TYPE:" + REQ_INSTANCE_TYPE)
        if  not REQ_INSTANCE_TYPE:
            print("No instance type set in sat_overview.json")
            exit()
        else:
            print("Set REQ_INSTANCE_TYPE:" + REQ_INSTANCE_TYPE)

        # get the required keypair type
        GLOBAL_CONTROL_KEYPAIR =  config_json.get("GLOBAL_CONTROL_KEYPAIR", None)
        if  not GLOBAL_CONTROL_KEYPAIR:
            print("No keypair set in sat_overview.json")
            exit()
        else:
            print("Set GLOBAL_CONTROL_KEYPAIR:" + GLOBAL_CONTROL_KEYPAIR)

        # get the required keypair type
        PROFILE =  config_json.get("PROFILE", None)
        if  not PROFILE:
            print("No profile set in sat_overview.json")
            exit()
        else:
            print("Set PROFILE:" + PROFILE)

        # get the required control IP
        CONTROL_IP =  config_json.get("CONTROL_IP", None)
        if  not CONTROL_IP:
            print("No control IP set in sat_overview.json")
            exit()
        else:
            print("Set CONTROL_IP:" + CONTROL_IP)

        # get the required EIP for the Conductor install
        CONDUCTOR_IP =  config_json.get("CONDUCTOR_IP", None)
        if  not CONDUCTOR_IP:
            print("No conductor EIP set in sat_overview.json")
            exit()
        else:
            print("Set CONDUCTOR_IP:" + CONDUCTOR_IP)


        return config_json
    

    ######################################################
    ## Security functions
    ####################################

    # check if role exists
    # return ARN if it does exist
    def roleExists(self):

        # boto3 client
        iam_client=boto_session.client("iam")

        workstation_role = self.ec2_requested_params.get('role_name', None)
        role_arn = ''

        print("Check if Role exists (" + str(workstation_role) + "):")
        # check if the Role already exists
        try:
            response = iam_client.get_role(RoleName=workstation_role,)
        except botocore.exceptions.ClientError as error:
            ##  TODO differentiate error types
            print("roleExists can't get role so does not exist:")
            role_arn =  None
        else:
            print("roleExists got response:" + str(response))
            # parse the arn
            role_dict = response.get('Role', {})
            role_arn = role_dict.get("Arn", None)
            print("parse role arn:" + str(role_arn))

        return role_arn

    ## Create or return Role object
    def createRole(self):

        workstation_role = self.ec2_requested_params.get('role_name', None)
        ec2_role = ''
        # get account ID for restricting polices
        accountID = self.getAccountID()

        # check if role exists
        role_arn = self.roleExists()
        if role_arn:
            print("Role already exists:" + str(self.ec2_requested_params.get('role_name', None)))
            # get ec2_role object ARN
            ec2_role = iam.Role.from_role_arn(self, workstation_role, role_arn, mutable=False )
        
        else:
            print("Creating role:" + str(workstation_role))
            ec2_role = iam.Role(self, workstation_role, assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"), role_name=workstation_role)
            print("Creating role:" + str(ec2_role))

            # assign a policy to the Role - access NICE license S3 bucket
            ec2_resources = 'arn:aws:s3:::dcv-license.' + str(self.CDK_TARGET_REGION) + '/*'
            print("Add Policy s3:GetObject for:" + str(ec2_resources))
            ec2_role.add_to_policy(iam.PolicyStatement( effect=iam.Effect.ALLOW, resources=[ec2_resources], actions=["s3:GetObject"] ))

            # Web Portal EC2 policies
            print("Add Portal Policies ec2 for: *")
            ec2_role.add_to_policy(iam.PolicyStatement( effect=iam.Effect.ALLOW, resources=["*"], actions=["ec2:AttachNetworkInterface", "ec2:DescribeImages", "ec2:DescribeTags",  "ec2:DescribeInstanceStatus", "ec2:DescribeVolumes", "ec2:DescribeVolumeAttribute", "ec2:DescribeInstanceAttribute", "ec2:DescribeInstances",  "ec2:DescribeNetworkInterfaces", "ec2:DetachNetworkInterface", "ec2:DescribeNetworkInterfaceAttribute"] ))

           # Conductor Parameter Store
            print("Add Portal Policies ec2 for: *")
            ec2_role.add_to_policy(iam.PolicyStatement( effect=iam.Effect.ALLOW, resources=["*"], actions=["ssm:DescribeParameters"] ))

          # Web Portal EC2 Control policies
            resource = 'arn:aws:ssm:' + str(accountID) + ':' + str(accountID) + ':parameter/*'
            print("Add Portal Policies ec2 for resource:" + str(resource))
            ec2_role.add_to_policy(iam.PolicyStatement( effect=iam.Effect.ALLOW, resources=[resource], actions=["ssm:GetParameters", "ssm:PutParameter"] ))

        print("Returning role:" + str(ec2_role))
        return ec2_role


    ####################################
    ## set up security group rules
    ##  - create Security Group
    ##  - set inbound rules required
    ##  - add the rules to the security group
    def setupSecurityRules(self):
        
        vpc = self.ec2_launch_params.get("vpc", None)
        if not vpc:
            print ('Failed finding vpc')
            return

        print ('Creating security group')
        sec_grp= aws_ec2.SecurityGroup(self, 'ec2-sec-grp', vpc=vpc, allow_all_outbound=True)
        if not sec_grp:
            print ('Failed finding security group')
            return

        # store in instance variable
        self.ec2_launch_params['sec_grp'] = sec_grp

        print ('Creating firewall rules - setting instance inbound rules variable')
        self.setInboundRules()
            
        print("Setting firewall rules for:" + str(sec_grp))
        self.createSGrules()

        return sec_grp


    ################################################################################################
    # set the inbound rules for the EC2 client
    def setInboundRules(self):

        ## add rule
        CONTROL_IP = CONTROL_IP + '/32'
        self.inbound_rule = { "port_range": "22", "protocol":"TCP", "source":CONTROL_IP, "description":"inbound SSH" }
        self.inbound_rules.append(self.inbound_rule)

        ## set access to web portal from control ip
        self.inbound_rule = { "port_range": "80", "protocol":"TCP", "source":CONTROL_IP, "description":"portal HTTP" }
        self.inbound_rules.append(self.inbound_rule)

        ## open to SoDA Servers UDP and TCP
        SODA_EXTERNAL_SERVER_IP = SODA_EXTERNAL_SERVER_IP + '/32'
        self.inbound_rule = { "port_range": "7498 - 7499", "protocol":"UDP", "source":EVERYONE_IP, "description":"SoDA Server" }
        self.inbound_rules.append(self.inbound_rule)

    def createSGrules(self):
        
        sec_grp = self.ec2_launch_params.get("sec_grp", None)
        if not sec_grp:
            print ('Failed finding sec_grp to set rules')
            return

        for inbound_rule in self.inbound_rules:
            print("Add Rule:" + str(inbound_rule))
            curr_source = inbound_rule.get("source", None)
            curr_port_range = inbound_rule.get("port_range", 0)
            curr_description = inbound_rule.get("description", None)
            curr_protocol = inbound_rule.get("protocol", None)

            print("Check Protocol:" + str(curr_protocol))

            # use anyip
            if curr_source == "0.0.0.0./0":
                # set required protocol
                if curr_protocol == "UDP":
                    sec_grp.add_ingress_rule(peer=aws_ec2.Peer.any_ipv4(), description=curr_description, connection=aws_ec2.Port.udp(curr_port_range))
                else:
                    sec_grp.add_ingress_rule(peer=aws_ec2.Peer.any_ipv4(), description=curr_description, connection=aws_ec2.Port.tcp(curr_port_range))
            # use specific IP
            else:   
                if curr_protocol == "UDP":
                    sec_grp.add_ingress_rule(peer=aws_ec2.Peer.ipv4(curr_source), description=curr_description, connection=aws_ec2.Port.udp(int(curr_port_range)))
                else:
                    sec_grp.add_ingress_rule(peer=aws_ec2.Peer.ipv4(curr_source), description=curr_description, connection=aws_ec2.Port.tcp(int(curr_port_range)))


        if not sec_grp:
            print ('Failed creating security group')
            return None

        return 1

    ##########################################
    ## create Workstation EC2
    ####################################

    def createWorkstation(self):
        
        

        instance_name = self.ec2_launch_params.get("instance_name", None)
        instance_type = self.ec2_launch_params.get("instance_type", None)
        ec2_role = self.ec2_launch_params.get("ec2_role", None)
        ami_image = self.ec2_launch_params.get("ami_image", None)
        sec_grp = self.ec2_launch_params.get("sec_grp", None)
        vpc = self.ec2_launch_params.get("vpc", None)
        keypair = self.ec2_launch_params.get("keypair", None)

        print (f'Creating EC2 Instance: {instance_name} using type: {instance_type} role: {ec2_role} with ami: {ami_image}')
                
        ec2_inst = aws_ec2.Instance(
            self, 'ec2_inst', 
            role=ec2_role,
            instance_name=instance_name,
            instance_type=instance_type,
            machine_image=ami_image,
            vpc=vpc,
            security_group=sec_grp,
            key_name=keypair )

        if not ec2_inst:
            print ('Failed creating ec2 instance')
            return

        print ('Finished EC2 Setup')



   


