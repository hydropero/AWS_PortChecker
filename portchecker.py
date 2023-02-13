import boto3, paramiko
from pprint import pprint
from rich import print
from rich.console import Console
from rich.table import Table

def port_parser(sec_groups, ec2):
    flat_sec_rules = []
    parsed_rules = []
    for sec_group in sec_groups:
        group_id = sec_group['GroupId']
        group_name = sec_group['GroupName']
        s_group = ec2.SecurityGroup(sec_group['GroupId']).ip_permissions
        if len(s_group) == 1:
            flat_sec_rules.append(s_group[0])
            parsed_rule = {
            'group_name': group_name,
            'group_id': group_id,
            }
            parsed_rules.append(parsed_rule)
        else:
            for rule_id_detailed in s_group:
                parsed_rule = {
                'group_name': group_name,
                'group_id': group_id,
                }
                parsed_rules.append(parsed_rule)
                flat_sec_rules.append(rule_id_detailed)
    count = 0
    for sec_rule in flat_sec_rules:

        parsed_rule = parsed_rules[count]

        if sec_rule['FromPort'] != sec_rule['ToPort']:
            port_range = f'{sec_rule["FromPort"]}-{sec_rule["ToPort"]}'
            parsed_rule['ports'] = port_range
            parsed_rule['protocol'] = sec_rule["IpProtocol"]
            parsed_rule['source_ip_range'] = sec_rule["IpRanges"][0]["CidrIp"]
            parsed_sec_rules.append(parsed_rule)
        else:
            parsed_rule['ports'] = sec_rule["FromPort"]
            parsed_rule['protocol'] = sec_rule["IpProtocol"]
            parsed_rule['source_ip_range'] = sec_rule["IpRanges"][0]["CidrIp"]
            parsed_sec_rules.append(parsed_rule)

        count += 1
    return parsed_sec_rules



ssh = paramiko.SSHClient()
key = paramiko.RSAKey.from_private_key_file("./MylesAWSKey.pem")
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
table = Table(title="Port Security Overview")
table.add_column("Public Hostname", justify="right", style="cyan", no_wrap=True)
table.add_column("Resource Name", justify="right", style="cyan", no_wrap=True)
table.add_column("Public IP", justify="right", style="cyan", no_wrap=True)
table.add_column("Group Namee", justify="right", style="cyan", no_wrap=True)
table.add_column("Group ID", justify="right", style="cyan", no_wrap=True)
table.add_column("AWS Ports", justify="right", style="cyan", no_wrap=True)
table.add_column("Protocol", justify="right", style="cyan", no_wrap=True)
table.add_column("Source IP Range", justify="right", style="cyan", no_wrap=True)
table.add_column("Linux Ports", justify="right", style="cyan", no_wrap=True)

# Let's use Amazon S3
ec2 = boto3.resource('ec2')
ec2_instant_sec_groups = []
current_sec_groups = []
flat_sec_group_detailed = []
complete_security_objects_list = []

count = 0
for instance in ec2.instances.all():
    instance_id = instance.id
    all_instance_sec_groups_full = ec2.Instance(instance_id).security_groups
    current_hostname = ec2.Instance(instance_id).public_dns_name
    ec2_instance_info = {
        'public_hostname': ec2.Instance(instance_id).public_dns_name,
        'resource_name': ec2.Instance(instance_id).tags[0]['Value'], # Instance Name
        'public_ip': ec2.Instance(instance_id).public_ip_address,
        # 'open_ports': 
    }
    print(current_hostname)
    ssh.connect(hostname=current_hostname, username="ec2-user", pkey=key, disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']})
    stdin_, stdout_, stderr_ = ssh.exec_command('sudo netstat -ntlp | cut -d: -f 4 | tail -n +3 | grep [0-9]| xargs')
    stdout_.channel.recv_exit_status()
    lines = stdout_.readlines()
    linux_ports = lines[0].strip().split(' ')
    linux_ports_ints = [eval(i) for i in linux_ports]
    linux_ports_ints.sort(reverse=True)
    linux_ports = [str(i) for i in linux_ports_ints]
    linux_ports = ' '.join(linux_ports)
    print(linux_ports)
    

    ssh.close()
    parsed_sec_rules = []
    #print(f'linux ports: {linux_ports}')
    sec_rules = port_parser(all_instance_sec_groups_full, ec2)
    #print('\n\n' + str(sec_rules) + '\n\n')
    # arraytest = []
    # for item in sec_rules:
    #     for i in range(len(item)):
    #         arraytest += item

    small_parsed_sec_rules = []
    print(f'this is sec_rules {sec_rules}')

    # iterates through ec2 instances
    # interate through rules in a set of rules per instance

    print(f'this is ec2_info {ec2_instance_info}')
    array_out = []
    for rule in sec_rules:
        rule = dict(rule)
        rule.update(ec2_instance_info)
        rule['linux_ports'] = linux_ports
        complete_security_objects_list.append(rule)
        #complete_security_objects_list.append(array_out)

    # for rule in sec_rules:
    #     print(f'this is rule {rule}')
    #     print(len(rule))
    #     for count, rule in enumerate(rule):
    #         print(count,rule)
    #         print(f'this is subrule {rule}')
    #         if count != 0:
    #             ec2_instance_info['group_name'] = rule[count]['group_name']
    #             ec2_instance_info['group_id'] = rule[count]['group_id']
    #             ec2_instance_info['ports'] = rule[count]['ports']
    #             ec2_instance_info['protocol'] = rule[count]['protocol']
    #             ec2_instance_info['source_ip_range'] = rule[count]['source_ip_range']
    #             ec2_instance_info['linux_ports'] = str(linux_ports)
    #             print(f'this is rule after {rule}')
    #             complete_security_objects_list.append(ec2_instance_info)
    #         else:
    #             ec2_instance_info['group_name'] = rule['group_name']
    #             ec2_instance_info['group_id'] = rule['group_id']
    #             ec2_instance_info['ports'] = rule['ports']
    #             ec2_instance_info['protocol'] = rule['protocol']
    #             ec2_instance_info['source_ip_range'] = rule['source_ip_range']
    #             ec2_instance_info['linux_ports'] = str(linux_ports)
    #             print(f'this is rule after {rule}')
    #             complete_security_objects_list.append(ec2_instance_info)
        

print(complete_security_objects_list)

instances_by_openports = []
for sec_obj in complete_security_objects_list:
    print(f'\n\n this is sec_object: {sec_obj}\n\n')
    if any(sec_obj['resource_name'] in d for d in instances_by_openports) != True:
        if '-' not in str(sec_obj['ports']):
            print(f"this is ports {sec_obj['ports']}")
            ports = [sec_obj['ports']]
            instances_by_openports.append({ sec_obj['resource_name']: ports })
        else:
            split_value = sec_obj['ports'].split('-')
            start = int(split_value[0])
            stop = int(split_value[1])
            port_list = []
            for i in range(start, stop):
                port_list.append(i)
            instances_by_openports.append({ sec_obj['resource_name']: port_list })
    else:
        print('else triggered!!!!!!!!!!')
        if '-' not in str(sec_obj['ports']):
            instances_by_openports[sec_obj['resource_name']] += sec_obj['ports']
        else:
            split_value = sec_obj['ports'].split('-')
            start = split_value[0]
            stop = split_value[1]
            port_list = []
            for i in range(start, stop):
                instances_by_openports[sec_obj['resource_name']] += i
            #instances_by_openports[sec_obj['resource_name']] += port_list    
    print("\n\n\n")
    pprint(instances_by_openports)
    print("\n\n\n")

# print("\n\n\n")
# pprint(instances_by_openports)
# print("\n\n\n")

for sec_obj in complete_security_objects_list:
    table.add_row(
        str(sec_obj['public_hostname']),
        str(sec_obj['resource_name']),
        str(sec_obj['public_ip']),
        str(sec_obj['group_name']),
        str(sec_obj['group_id']),
        str(sec_obj['ports']),
        str(sec_obj['protocol']),
        str(sec_obj['source_ip_range']),
        str(sec_obj['linux_ports'])

    )



console = Console()
console.print(table)



    #print(ec2_instance_info)  

# print(len(ec2.SecurityGroup(sec_group['GroupId']).ip_permissions))


# all_instance_sec_groups_full = ec2.Instance(instance_id).security_groups
# for item in all_instance_sec_groups_full:
#     print(item['GroupId'])

#     pprint(ec2.SecurityGroup(item['GroupId']).ip_permissions)



# to get AWS open ports I need to compile an array of all ports collected from all sec groups attached to an ec2 inst.

# Get Sec Group resource and it's details
# Must get ID of security group not EC2 Instance 
# pprint(ec2.SecurityGroup(instance_id).ip_permissions)

# pprint(ec2.Instance(instance_id).public_ip_address)