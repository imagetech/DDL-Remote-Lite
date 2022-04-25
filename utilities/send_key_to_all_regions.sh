#!/bin/sh

## use a 

## set to the keypair name to be used
MyKeyPair='DDL_Remote_Lite'
MyPem=$MyKeyPair".pem"
MyPub="id_rsa_"$MyKeyPair".pub"

echo $MyPem
echo $MyPub

if [ -f $MyPem ]; then
    echo "Key Exists: "$MyPem
else
    echo "Key does NOT Exists: "$MyPem
    exit
fi

## create pub key
echo "Creating public key"
ssh-keygen -y -f $MyPem > $HOME/.ssh/$MyPub

# get all AWS_REGIONS
echo "Getting available AWS Regions"
AWS_REGIONS="$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)"

echo "Using Regions:"$AWS_REGIONS


for each_region in ${AWS_REGIONS} ; 

    do 
        aws ec2 import-key-pair --key-name $MyKeyPair --public-key-material fileb://$HOME/.ssh/$MyPub --region $each_region ; 
    done
