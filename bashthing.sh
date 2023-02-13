 aws ec2 describe-network-interfaces --output json | jq '.NetworkInterfaces[].Association' | jq '.PublicDnsName,.PublicIp'

 Instance Name
 Instance ID -> - Security Group - port 80
                - Security Group - port 443
                - Security Group - port 22
                                 - port 443
                                 - port 80
