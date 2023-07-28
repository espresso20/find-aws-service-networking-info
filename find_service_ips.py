import boto3
import csv
import os
import logging
import socket
import time
# import botocore.exceptions 
# import NoCredentialsError

# This script is used to enumerate and document various AWS resources across multiple regions. It leverages boto3 to interact with AWS services and generate a CSV report with relevant details.

# configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# AWS regions and profiles to target
regions = ["us-east-1", "us-west-2"]
profile = "your-aws-profile-here"

# Create a session using your AWS SSO profile
session = boto3.Session(profile_name=profile, region_name=regions)

# List of AWS services to investigate
services = [
    "ec2",
    "elasticloadbalancer",
    "rds",
    "redshift",
    "elasticache",
    "elasticsearch",
    "eks",
    "lambda",
    "apigateway",
    "ecs",
    "eni",
    "eip",
]


# Function to get public IPs of EC2 instances in a region
def get_ec2_ips():
    client = session.client('ec2')
    try:
        instances = client.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                public_ip = instance.get('PublicIpAddress', 'N/A')
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                yield public_ip, private_ip, tags
    except Exception as e:
        logging.error(f"Error getting EC2 Ips: {e}")
    

# Function to get EIP associated with your account in a region
def get_eips():
    client = session.client('ec2')
    try:
        addresses_dict = client.describe_addresses()
        for eip_dict in addresses_dict['Addresses']:
            yield eip_dict['PublicIp'], {}
    except Exception as e:
        logging.error(f"Error Getting EIPS: {e}")

# Function to get RDS instances IPs
def get_rds_ips():
    rds_client = session.client('rds')
    ec2_client = session.client('ec2')
    try:
        instances = rds_client.describe_db_instances()
        for instance in instances['DBInstances']:
            # Public IP can be found in the endpoint
            public_ip = instance['Endpoint']['Address']
            # Attempt to get private IP through the network interfaces of the security groups
            for sg in instance['VpcSecurityGroups']:
                network_interfaces = ec2_client.describe_network_interfaces(
                    Filters=[{'Name': 'group-id', 'Values': [sg['VpcSecurityGroupId']]}]
                )
                for ni in network_interfaces['NetworkInterfaces']:
                    if 'PrivateIpAddress' in ni:
                        # Get the tags for the RDS instance
                        tag_list = rds_client.list_tags_for_resource(ResourceName=instance['DBInstanceArn'])['TagList']
                        tags = {tag['Key']: tag['Value'] for tag in tag_list}
                        yield public_ip, ni['PrivateIpAddress'], tags
                        break
    except Exception as e:
        logging.error(f"Error getting RDS IPs: {e}")

def get_load_balancers():
    client= session.client('elbv2')
    try:
        load_balancers = client.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            dns_name = lb['DNSName']
            ips = socket.gethostbyname_ex(dns_name)[2] # get the IP From DNS name
            tags_response = client.describe_tags(
                ResourceArns=[lb['LoadBalancerArn']]
            )
            tags = {tag['Key']: tag['Value'] for tag_list in tags_response['TagDescriptions'] for tag in tag_list['Tags']}
            yield dns_name, ips, tags
    except Exception as e:
        logging.error(f"Error getting Load Balancers: {e}")

# Function to get IPs from load balancers
def get_load_balancer_ips():
    elbv2 = session.client('elbv2')
    try:
        load_balancers = elbv2.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            dns_name = lb['DNSName']
            ips = socket.gethostbyname_ex(dns_name)[2]
            tags_response = elbv2.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
            tags = {tag['Key']: tag['Value'] for tag_list in tags_response['TagDescriptions'] for tag in tag_list['Tags']}
            yield dns_name, ips, tags
    except Exception as e:
        logging.error(f"Error getting Load Balancers: {e}")

def get_redshift_ips():
    redshift_client = session.client('redshift')
    try:
        clusters = redshift_client.describe_clusters()
        for cluster in clusters['Clusters']:
            # logging.info(f"Found Redshift cluster: {cluster['ClusterIdentifier']}")
            dns_name = cluster['Endpoint']['Address']
            for node in cluster['ClusterNodes']:
                # logging.info(f"Found Node {node} in cluster: {cluster['ClusterIdentifier']}")
                public_ip = node.get('PublicIPAddress', 'N/A')
                # logging.info(f"public ip: {public_ip}")
                private_ip = node.get('PrivateIPAddress', 'N/A')
                # permission issues with redshift prevent getting tags cleanly
                # tag_list = redshift_client.describe_tags(ResourceName=resource_name)
                # tags = {tag['Key']: tag['Value'] for tag in tag_list['TaggedResources']}
                yield public_ip, private_ip, dns_name
    except Exception as e:
        logging.error(f"Error getting Redshift IPs: {e}")

def get_elasticache_redis_nodes():
    elasticache = session.client('elasticache')
    try:
        clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True)
        for cluster in clusters['CacheClusters']:
            for node in cluster['CacheNodes']:
                yield cluster['CacheClusterId'], node['Endpoint']['Address']
    except Exception as e:
        logging.error(f"Error getting Elasticache Redis nodes: {e}")

def get_eks_details():
    eks_client = session.client('eks')
    ec2_client = session.client('ec2')

    try:
        clusters = eks_client.list_clusters()['clusters']
        for cluster_name in clusters:
            cluster_details = eks_client.describe_cluster(name=cluster_name)['cluster']
            cluster_endpoint = cluster_details['endpoint']
            cluster_tags = eks_client.list_tags_for_resource(resourceArn=cluster_details['arn'])['tags']

            name_tag, environment, other_tags = extract_tags(cluster_tags)  # Here is the correction

            # Worker nodes are EC2 instances, let's get their IPs
            # This assumes worker nodes are tagged with 'eks:cluster-name' = <cluster_name>
            # Adjust this depending on how you identify your EKS worker nodes.
            worker_nodes = ec2_client.describe_instances(
                Filters=[{'Name': 'tag:eks:cluster-name', 'Values': [cluster_name]}]
            )

            for reservation in worker_nodes['Reservations']:
                for instance in reservation['Instances']:
                    public_ip = instance.get('PublicIpAddress', 'N/A')
                    private_ip = instance.get('PrivateIpAddress', 'N/A')
                    instance_tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    worker_name_tag, worker_environment, worker_other_tags = extract_tags(instance_tags)
                    yield cluster_name, cluster_endpoint, public_ip, private_ip, name_tag, environment, other_tags, worker_name_tag, worker_environment, worker_other_tags
    except Exception as e:
        logging.error(f"Error getting EKS details: {e}")

# Helper function to parse and extract name, environment, and other tags from a given dictionary of tags
def extract_tags(tags_dict):
    name_tag = tags_dict.pop('Name', 'N/A')
    environment = tags_dict.pop('Environment', 'N/A')
    other_tags = tags_dict
    return name_tag, environment, other_tags

# main loop
for region in regions:
    session = boto3.Session(profile_name=profile, region_name=region)
    try:
        with open(f'{region}-aws-ips.csv', mode='w') as file:
            writer = csv.writer(file)
            writer.writerow(["Service", "Public IP", "Private IP", "DNS Name", "Name Tag", "Environment", "Other Tags", "Worker Name Tag", "Worker Other Tags"])
            # For each AWS service, extract the relevant information and write it to the CSV file
            for service in services:
                if service == "ec2":
                    for public_ip, private_ip, tags in get_ec2_ips():
                        name_tag, environment, other_tags = extract_tags(tags)
                        writer.writerow([service, public_ip, private_ip, 'N/A', name_tag, environment, other_tags])
                elif service == "eip":
                    for eip, tags in get_eips():
                        name_tag, environment, other_tags = extract_tags(tags)
                        writer.writerow([service, eip, 'N/A', 'N/A', 'N/A', name_tag, environment, other_tags])
                elif service == "rds":
                    for public_ip, private_ip, tags in get_rds_ips():
                        name_tag, environment, other_tags = extract_tags(tags)
                        writer.writerow([service, public_ip, private_ip,'N/A', name_tag, environment, other_tags])
                elif service == "elasticloadbalancer":
                    for dns_name, ips, tags in get_load_balancer_ips():
                        for ip in ips:
                            name_tag, environment, other_tags = extract_tags(tags)
                            writer.writerow([service, ip, 'N/A', dns_name, name_tag, environment, other_tags])
                elif service == "redshift":
                    for public_ip, private_ip, dns_name in get_redshift_ips():
                        # if you want to log a row in the csv output...
                        # row = [service, public_ip, private_ip, dns_name, 'N/A', 'N/A']
                        # logging.info(f"Writing row: {row}")
                        writer.writerow([service, public_ip, private_ip, dns_name, 'N/A', 'N/A', 'N/A'])
                elif service == "elasticache":
                    for cluster_id, endpoint in get_elasticache_redis_nodes():
                        writer.writerow([service, 'N/A', 'N/A', endpoint, cluster_id, 'N/A', 'N/A'])
                elif service == "eks":
                    for cluster_name, cluster_endpoint, public_ip, private_ip, name_tag, environment, other_tags, worker_name_tag, worker_environment, worker_other_tags in get_eks_details():
                        writer.writerow([service, public_ip, private_ip, cluster_endpoint, name_tag, environment, other_tags, worker_name_tag, worker_environment, worker_other_tags])
                else:
                    writer.writerow([service, "N/A", "N/A", "N/A", {}, 'N/A', {}])  # Write N/A for other services without implemented retrieval logic
    except Exception as e:
        logging.error(f"Error in region {region}: {e}")


# This script currently supports enumeration of EC2, Elastic IP, RDS, ELB, Redshift, ElastiCache, and EKS services. 
# To support additional services, implement a similar function to the existing ones (like get_ec2_ips) 
# to fetch the required information and update the main loop to call this function.
