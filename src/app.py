#!/usr/bin/env python3

import os
#from dotenv import load_dotenv

# load our env file
#print ('Loading env file')
#load_dotenv()

import aws_cdk as cdk


from ec2_deploy.ec2_deploy_stack import Ec2WorkstationDeployStack
from ec2_deploy.ec2_portal_deploy import Ec2DeployPortalStack
from ec2_deploy.ec2_soda_conductor_deploy import Ec2DeployConductorStack
from ec2_deploy.ec2_soda_agent_deploy import Ec2DeploySoDAClientStack

print ('Creating environment')
account=os.getenv('CDK_DEFAULT_ACCOUNT')
region=os.getenv('CDK_TARGET_REGION')


print("Deploy to:" + str(account) + ":" + str(region))

cdk_env = cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=region)
print("app.py cdk_env:" + str(cdk_env))

print("Deploy to:" + str(account) + ":" + str(region))


# deploy reources
app = cdk.App()

# admin web portal
Ec2DeployConductorStack(app, 'Ec2DeployConductorStack',  env=cdk_env)

# admin web portal
#Ec2DeployPortalStack(app, 'Ec2DeployPortalStack',  env=cdk_env)

# SoDA client server (ARM)
#Ec2DeploySoDAClientStack(app, 'Ec2DeploySoDAClientStack', env=cdk_env )

# a workstation
#Ec2WorkstationDeployStack(app, 'Ec2WorkstationDeployStack', env=cdk_env)



# synthesize it
print ('Synthesizing stack')
app.synth()

