import boto3

client = boto3.client('ec2')
ec2 = boto3.resource('ec2')

def lambda_handler(event, context):
    print(str(event))
    if 'items' not in event['detail']['requestParameters']['ipPermissions']:
        print("Main Items not present")
        return
    items = event['detail']['requestParameters']['ipPermissions']['items']
    sgGroupId = event['detail']['requestParameters']['groupId']
    sg = ec2.SecurityGroup(sgGroupId)
    
    
    for item in items:
        
        
        if item['ipProtocol'] == '-1' or item['fromPort'] == 22 or item['toPort'] == 22:
            # Check IPV4
            if 'items' in item['ipRanges']:
                for cidrDict in item['ipRanges']['items']:
                    # Check for IPV4
                    if 'cidrIp' in cidrDict and cidrDict['cidrIp'] == '0.0.0.0/0':
                        print('Insecure Security Group rule found')
                        sg.revoke_ingress(
                            CidrIp=cidrDict['cidrIp'],
                            IpProtocol=item['ipProtocol'],
                            ToPort = 0 if item['ipProtocol'] == '-1' else item['toPort'],
                            FromPort= 0 if item['ipProtocol'] == '-1' else item['fromPort']
                            )
                        print(f'Removed Insecured Security Group rule In SG with ID {sgGroupId}')
                      
            # Check IPV6
            if 'items' in item['ipv6Ranges']:
                for cidrDict in item['ipv6Ranges']['items']:
                    # Check for IPV4
                    if 'cidrIpv6' in cidrDict and cidrDict['cidrIpv6'] == '::/0':
                        print('Insecure Security Group rule found')
                        
                        sg.revoke_ingress(
                            IpPermissions = [
                                {
                                    'FromPort': 0 if item['ipProtocol'] == '-1' else item['fromPort'],
                                    'ToPort': 0 if item['ipProtocol'] == '-1' else item['toPort'],
                                    'IpProtocol': item['ipProtocol'],
                                    'Ipv6Ranges': [
                                        {
                                            'CidrIpv6': cidrDict['cidrIpv6']
                                        }
                                    ]
                                }
                            ]
                        )
                        print(f'Removed Insecured Security Group rule In SG with ID {sgGroupId}')
