# DDL-Remote-Lite
Local Ubuntu install

CDK install prereqs
Aws configure (CLI installed) or manually create the  %USERPROFILE%\.aws\config and %USERPROFILE%\.aws\credentials
npm update
Install npm
Install cdk - npm install -g aws-cdk


cdk init --language python
source .env/bin/activate

pip install -r requirements.txt 
pip install python	-dotenv
               pip3 install boto3

Workstation Install
-	Use NICE DCV AMI
-	Access License File
o	Create policy : access S3 NICE license
o	SG Rules: Open port TCP:UDP 8443


Server Soda Install

SoDA Install
-	EIP for server instance
-	IP setup required with SoDA
-	/usr/local/bin/k3s-uninstall.sh
Main install: curl "https://cloudsodainitscripts-usw2-s-1.s3.us-west-2.amazonaws.com/ddlabs-ton-1.sh?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARSC6MDD7W2USVI2R%2F20220411%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20220411T211838Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=46d18b8fa6e57f73225f3137a31e604ecd5c6f8f6236d79ca43530a23cf2d994" | sudo bash
 
Soda Client Test install
Pre (CLI install)
sudo apt update 
sudo apt -y upgrade
1.(intel)curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
(ARM) curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
		sudo apt install unzip
		unzip awscliv2.zip
		sudo ./aws/install



Portal Install
Copy same key pair to all regions for portal access (send_key_to_all_regions.sh)
Set env variable CURRENT_REGION on portal box


Startup Passed Parameters
AMI, 
Region 



