
ENV_FILE="/etc/profile.d/aws_env.sh"

INSTANCE_ID=`curl "http://169.254.169.254/latest/meta-data/instance-id"`
echo "EC2 instance_id:"$INSTANCE_ID
REGION=`curl "http://169.254.169.254/latest/meta-data/placement/region"`
echo "REGION:"$REGION
HOSTNAME=`curl "http://169.254.169.254/latest/meta-data/hostname"`
echo "HOSTNAME:"$HOSTNAME

cat > $ENV_FILE << EOF
export EC2_INSTANCE=$INSTANCE_ID
export EC2_REGION=$REGION
export EC2_HOSTNAME=$HOSTNAME
EOF
chmod a+x $ENV_FILE

## get EIP
IFS=':'
IP_LINE=`aws ec2 allocate-address | grep '"AllocationId"'`
echo $IP_LINE

read -ra iparr <<< $IP_LINE
ALLOC_ID=`echo ${iparr[1]} | sed 's/\"//g' | sed 's/\,//g' | sed 's/^ *//g'`

echo "Created EIP Allocation ID:"$ALLOC_ID
echo "Associating EIP with instance:"$INSTANCE_ID

## associate IP with instance
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $ALLOC_ID
