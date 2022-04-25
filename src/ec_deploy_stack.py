import os
from aws_cdk import ( Stack, aws_ec2)
from constructs import Construct
import boto3
import botocore

import aws_cdk.aws_iam as iam
#import aws_iam as iam

#TODO passed and external
PROFILE = 'ddl-dev2'

boto_session = boto3.Session(profile_name=PROFILE)

class Ec2WorkstationDeployStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        print("kwargs:" + str(kwargs))

        ## dicts to store the requested parameters and their matching created object
        #  store the requested parameters for the ec2 being deployed
        self.ec2_requested_params = {}
        # store the derived launch parameters for the ec2 being deployed
        self.ec2_launch_params = {}
        print("Pre-set REQUESTED PARAMETERS:" + str(self.ec2_requested_params))

        ## set the parameters requested for the instance
        self.setEc2RequestedParameters()
        print("REQUESTED PARAMETERS:" + str(self.ec2_requested_params))

        # review passed parameters
        passed_params = kwargs.get("env", {})
        #passed_env = passed_params.get("Environment", {})
        print("passed_params:" + str(passed_params))
        #print("passed_env:" + str(passed_env))

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
        
        ami_image = aws_ec2.MachineImage().lookup(name=ami_name)
        if not ami_image:
            print ('Failed finding AMI image')
            return
        else:
            print ('Found AMI image:' + str(ami_image))

        return ami_image

    ## set the parameters that will eventually passed to start a particular ec2 instance
    ## TODO for now set here
    def setEc2RequestedParameters(self):

        print(f'Set Requested EC2 parameters')

        # TODO set with passed params
        self.ec2_requested_params['instance_name'] = 'CDK Test'
        self.ec2_requested_params['ami_name'] = 'DDL_Remote_Lite_Client'
        self.ec2_requested_params['vpc_name'] = 'vpc-eccbe784'


        self.ec2_requested_params['role_name'] = "DDL-RL-workstation-role"
        self.ec2_requested_params['profile'] = PROFILE

        # derived from account
        self.ec2_requested_params['req_instance_type'] = 't2.micro'
        self.ec2_requested_params['vpc'] = ''

        self.inbound_rules = []             ## inbound rules
        
        self.ec2_launch_params['ec2_role'] = None

        ## TODO TEMP set vals
        self.CDK_REGION=os.getenv('CDK_DEFAULT_REGION')
        print('***Deploy region:' + str(self.CDK_REGION))

        return 

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

        # check if role exists
        role_arn = self.roleExists()
        if role_arn:
            print("Role already exists:" + str(self.ec2_requested_params.get('role_name', None)))
            # get ec2_role object ARN
            ec2_role = iam.Role.from_role_arn(self, workstation_role, role_arn, mutable=False )
        
        else:
            print("Creating role:" + str(workstation_role))
            ec2_role = iam.Role(self, "DDL-RL-workstation-role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"), role_name=workstation_role)
            print("Creating role:" + str(ec2_role))

            # assign a policy to the Role - access NICE license S3 bucket
            ec2_resources = 'arn:aws:s3:::dcv-license.' + str(self.CDK_REGION) + '/*'
            print("Add Policy s3:GetObject for:" + str(ec2_resources))
            ec2_role.add_to_policy(iam.PolicyStatement( effect=iam.Effect.ALLOW, resources=[ec2_resources], actions=["s3:GetObject"] ))

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
        self.inbound_rule = { "port_range": "8443", "protocol":"TCP", "source":"0.0.0.0/0", "description":"NiceDCV TCP" }
        self.inbound_rules.append(self.inbound_rule)

        ## add rule
        self.inbound_rule = { "port_range": "8443", "protocol":"UDP", "source":"0.0.0.0/0", "description":"NiceDCV UDP" }
        self.inbound_rules.append(self.inbound_rule)

        ## add rule
        self.inbound_rule = { "port_range": "22", "protocol":"TCP", "source":"174.92.126.89/32", "description":"inbound SSH" }
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

        print (f'Creating EC2 Instance: {instance_name} using type: {instance_type} role: {ec2_role} with ami: {ami_image}')
                
        ec2_inst = aws_ec2.Instance(
            self, 'ec2_inst', 
            role=ec2_role,
            instance_name=instance_name,
            instance_type=instance_type,
            machine_image=ami_image,
            vpc=vpc,
            security_group=sec_grp)

        if not ec2_inst:
            print ('Failed creating ec2 instance')
            return

        print ('Finished EC2 Setup')



   


