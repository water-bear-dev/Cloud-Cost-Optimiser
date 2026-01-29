
import boto3
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from fpdf import FPDF

# --- Constants & Configuration ---
PAGE_TITLE = "AWS Cost Optimization Auditor"
PAGE_ICON = "💰"
LAYOUT = "wide"

# Estimated Savings Constants (Monthly)
EST_COST_EBS_GB = 0.10  # Approx $0.10 per GB for gp3/gp2
EST_COST_EIP = 3.65     # Approx $0.005/hr * 730 hrs
EST_COST_SNAPSHOT_GB = 0.05 # Approx $0.05 per GB Standard
EST_COST_IDLE_EC2 = 20.00 # Conservative avg for small-medium idle instances
EST_COST_S3_GB = 0.023  # Standard tier
EST_COST_RDS = 50.00    # Conservative avg for idle RDS
EST_COST_ALB = 20.00    # Approx ALB hourly cost ~0.0225 + LCUs
EST_COST_LOG_GB = 0.03 # Stored log data cost

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout=LAYOUT)

# --- AWS Helper Functions ---

def get_session(region):
    """Returns a boto3 session for the specified region."""
    return boto3.Session(region_name=region)

def get_orphaned_resources(session, region):
    """
    Detects unattached EBS volumes and unassociated Elastic IPs.
    Also checks for Elastic IPs attached to STOPPED instances.
    """
    ec2 = session.client('ec2', region_name=region)
    findings = []
    
    # 1. Available EBS Volumes
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']
        for vol in volumes:
            size = vol['Size']
            cost = size * EST_COST_EBS_GB
            findings.append({
                'Resource Type': 'EBS Volume',
                'ID': vol['VolumeId'],
                'Details': f"Size: {size} GB, Type: {vol['VolumeType']}",
                'Estimated Monthly Savings ($)': cost,
                'Creation Date': vol['CreateTime'],
                'Type': 'Cleanup' 
            })
    except ClientError as e:
        st.error(f"Error checking EBS volumes: {e}")

    # 2. Unassociated Elastic IPs & Stopped Instance IPs
    try:
        addresses = ec2.describe_addresses()['Addresses']
        for ip in addresses:
            is_waste = False
            details = ""
            
            # Case A: Unassociated
            if 'AssociationId' not in ip:
                is_waste = True
                details = f"Unassociated. AllocationId: {ip.get('AllocationId', 'N/A')}"
            
            # Case B: Associated but Instance is Stopped
            elif 'InstanceId' in ip:
                instance_id = ip['InstanceId']
                try:
                    inst_desc = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
                    if inst_desc['State']['Name'] == 'stopped':
                        is_waste = True
                        details = f"Attached to STOPPED instance {instance_id}"
                except (ClientError, IndexError):
                    pass # Instance might have just terminated or permission issue
            
            if is_waste:
                findings.append({
                    'Resource Type': 'Elastic IP',
                    'ID': ip['PublicIp'],
                    'Details': details,
                    'Estimated Monthly Savings ($)': EST_COST_EIP,
                    'Creation Date': datetime.now(timezone.utc), # EIPs don't have creation time
                    'Type': 'Cleanup'
                })
    except ClientError as e:
        st.error(f"Error checking Elastic IPs: {e}")

    return findings

def get_idle_nat_gateways(session, region):
    """
    Identify NAT Gateways with low activity (< 10KB bytes out) over last 7 days.
    """
    ec2 = session.client('ec2', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        nat_gateways = ec2.describe_nat_gateways(Filters=[{'Name': 'state', 'Values': ['available']}])['NatGateways']
        
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for nat in nat_gateways:
            nat_id = nat['NatGatewayId']
            created = nat['CreateTime']
            
            # Check BytesOut
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/NATGateway',
                MetricName='BytesOutToDestination',
                Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            total_bytes = sum([d['Sum'] for d in datapoints]) if datapoints else 0
            
            # Threshold: Less than 10KB (10240 bytes) in 7 days is basically idle
            if total_bytes < 10240:
                 # Hourly cost + data cost (ignoring data cost as it's near zero)
                 # $0.045/hr * 730 hrs = ~$32.85
                 est_cost = 0.045 * 730 
                 findings.append({
                    'Resource Type': 'NAT Gateway',
                    'ID': nat_id,
                    'Details': f"Bytes Out (7d): {total_bytes / 1024:.2f} KB",
                    'Estimated Monthly Savings ($)': est_cost,
                    'Creation Date': created,
                    'Type': 'Cleanup'
                })

    except ClientError as e:
        # Permission errors or service not available in region
        pass
        
    return findings

def get_old_snapshots(session, region):
    """
    Identify EBS snapshots older than 90 days.
    """
    ec2 = session.client('ec2', region_name=region)
    findings = []
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
    
    try:
        # Filter by OwnerIds=['self'] to only see our own snapshots
        paginator = ec2.get_paginator('describe_snapshots')
        page_iterator = paginator.paginate(OwnerIds=['self'])

        for page in page_iterator:
            for snap in page['Snapshots']:
                start_time = snap['StartTime']
                if start_time < cutoff_date:
                    size = snap['VolumeSize']
                    cost = size * EST_COST_SNAPSHOT_GB
                    findings.append({
                        'Resource Type': 'EBS Snapshot',
                        'ID': snap['SnapshotId'],
                        'Details': f"Size: {size} GB, Created: {start_time.date()}",
                        'Estimated Monthly Savings ($)': cost,
                        'Creation Date': start_time,
                        'Type': 'Cleanup'
                    })
    except ClientError as e:
        st.error(f"Error checking Snapshots: {e}")
        
    return findings

def get_low_cpu_instances(session, region):
    """
    Identify EC2 instances that are 'Running' but have low CPU utilization (avg < 5%) over the last 7 days.
    """
    ec2 = session.client('ec2', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        # Get all running instances
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        instance_list = []
        instance_launch_times = {}

        for reservation in instances['Reservations']:
            for inst in reservation['Instances']:
                instance_list.append(inst['InstanceId'])
                instance_launch_times[inst['InstanceId']] = inst['LaunchTime']
        
        # Check metrics for each instance (batching would be better for many instances, but keeping it simple)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for inst_id in instance_list:
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': inst_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400, # 1 day datapoints
                Statistics=['Average']
            )
            
            datapoints = metrics.get('Datapoints', [])
            if datapoints:
                avg_cpu = sum([d['Average'] for d in datapoints]) / len(datapoints)
                if avg_cpu < 5.0:
                    findings.append({
                        'Resource Type': 'EC2 Instance',
                        'ID': inst_id,
                        'Details': f"Avg CPU (7d): {avg_cpu:.2f}% (Consider Stopping)",
                        'Estimated Monthly Savings ($)': EST_COST_IDLE_EC2,
                        'Creation Date': instance_launch_times.get(inst_id, datetime.now(timezone.utc)),
                        'Type': 'Cleanup' 
                    })
            else:
                 # No data usually means stopped or just launched, but we filtered for running. 
                 # Could be insufficient data, skipping safe.
                 pass

    except ClientError as e:
        st.error(f"Error checking EC2 CPU: {e}")
        
    return findings



def get_s3_no_lifecycle(session, region):
    """
    List S3 buckets that do not have a 'Lifecycle Policy' enabled.
    """
    s3 = session.client('s3', region_name=region)
    findings = []
    
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            b_name = bucket['Name']
            b_creation = bucket['CreationDate']
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=b_name)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchLifecycleConfiguration':
                    findings.append({
                        'Resource Type': 'S3 Bucket',
                        'ID': b_name,
                        'Details': "No Lifecycle Policy found",
                        'Estimated Monthly Savings ($)': 0.0, # Hard to estimate without size calc
                        'Creation Date': b_creation,
                        'Type': 'Cleanup' 
                    })
                # Ignore other errors (permissions etc)
    except ClientError as e:
        st.error(f"Error checking S3 Buckets: {e}")
    
    return findings

def get_idle_rds(session, region):
    """
    Flag RDS instances with 0 connections over the past 7 days.
    """
    rds = session.client('rds', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        dbs = rds.describe_db_instances()['DBInstances']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for db in dbs:
            db_id = db['DBInstanceIdentifier']
            db_create_time = db['InstanceCreateTime']
            if db['DBInstanceStatus'] != 'available':
                continue
                
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='DatabaseConnections',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            # If we have data and sum of connections is 0
            total_connections = sum([d['Sum'] for d in datapoints]) if datapoints else 0
            
            if datapoints and total_connections == 0:
                 findings.append({
                        'Resource Type': 'RDS Instance',
                        'ID': db_id,
                        'Details': "0 Connections in last 7 days",
                        'Estimated Monthly Savings ($)': EST_COST_RDS,
                        'Creation Date': db_create_time,
                        'Type': 'Cleanup'
                    })

    except ClientError as e:
        st.error(f"Error checking RDS: {e}")

    return findings

def get_idle_sagemaker(session, region):
    """
    Identify SageMaker Notebook instances that are 'InService' but unused.
    Disclaimer: It's hard to check 'activity' without CloudWatch, but 'InService' is a good starting point.
    """
    sm = session.client('sagemaker', region_name=region)
    findings = []
    
    try:
        notebooks = sm.list_notebook_instances(StatusEquals='InService')['NotebookInstances']
        for nb in notebooks:
            # For simplicity, we just flag ALL InService notebooks. 
            # ideally we check CPUUtilization from CloudWatch.
            findings.append({
                'Resource Type': 'SageMaker Notebook',
                'ID': nb['NotebookInstanceName'],
                'Details': f"Status: {nb['NotebookInstanceStatus']} (Check if idle)",
                'Estimated Monthly Savings ($)': 50.00, # Approx cost for ml.t2.medium
                'Creation Date': nb['CreationTime'],
                'Type': 'Cleanup' 
            })
    except ClientError:
        pass # SageMaker might not be available
        
    return findings

def get_idle_elasticache(session, region):
    """
    Identify Elasticache clusters with 0 connections.
    """
    elasticache = session.client('elasticache', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        clusters = elasticache.describe_cache_clusters()['CacheClusters']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for cluster in clusters:
            if cluster['CacheClusterStatus'] != 'available':
                continue
            
            cluster_id = cluster['CacheClusterId']
            created = cluster['CacheClusterCreateTime']
            
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/ElastiCache',
                MetricName='CurrConnections',
                Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Maximum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            max_conn = max([d['Maximum'] for d in datapoints]) if datapoints else 0
            
            if datapoints and max_conn == 0:
                findings.append({
                    'Resource Type': 'Elasticache Cluster',
                    'ID': cluster_id,
                    'Details': "0 Connections in last 7 days",
                    'Estimated Monthly Savings ($)': 50.00, # Approx
                    'Creation Date': created,
                    'Type': 'Cleanup'
                })
                
    except ClientError:
        pass
        
    return findings

def get_unused_dynamodb(session, region):
    """
    Identify DynamoDB tables with PROVISIONED capacity but 0 consumption.
    """
    dynamo = session.client('dynamodb', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        tables = dynamo.list_tables()['TableNames']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for t_name in tables:
            desc = dynamo.describe_table(TableName=t_name)['Table']
            created = desc['CreationDateTime']
            
            # Only check provisioned
            if desc.get('BillingModeSummary', {}).get('BillingMode') == 'PAY_PER_REQUEST':
                continue
                
            prov = desc.get('ProvisionedThroughput', {})
            rcu = prov.get('ReadCapacityUnits', 0)
            wcu = prov.get('WriteCapacityUnits', 0)
            
            if rcu > 0 or wcu > 0:
                # Check ConsumedCapacity
                consumed_metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ConsumedReadCapacityUnits',
                    Dimensions=[{'Name': 'TableName', 'Value': t_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                consumed_r = sum([d['Sum'] for d in consumed_metrics['Datapoints']]) if consumed_metrics['Datapoints'] else 0
                
                if consumed_r == 0:
                     # Approx cost: $0.00065/hr per RCU/WCU (very rough)
                     # Cost = (RCU + WCU) * 0.00065 * 730
                     cost = (rcu + wcu) * 0.00065 * 730
                     findings.append({
                        'Resource Type': 'DynamoDB Table',
                        'ID': t_name,
                        'Details': f"Provisioned: {rcu} RCU / {wcu} WCU, but 0 Consumed",
                        'Estimated Monthly Savings ($)': cost,
                        'Creation Date': created,
                        'Type': 'Cleanup' 
                    })
                    
    except ClientError:
        pass
        
    return findings

def get_zombie_elbs(session, region):
    """
    Flag Load Balancers with zero healthy targets.
    """
    elbv2 = session.client('elbv2', region_name=region)
    findings = []
    
    try:
        lbs = elbv2.describe_load_balancers()['LoadBalancers']
        for lb in lbs:
            lb_arn = lb['LoadBalancerArn']
            lb_name = lb['LoadBalancerName']
            lb_created = lb['CreatedTime']
            
            # Get Target Groups for this LB
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
            
            healthy_targets_count = 0
            for tg in tgs:
                tg_arn = tg['TargetGroupArn']
                health = elbv2.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
                # Count 'healthy' targets
                healthy_targets_count += sum(1 for h in health if h['TargetHealth']['State'] == 'healthy')
            
                if healthy_targets_count == 0:
                 findings.append({
                        'Resource Type': 'Load Balancer (ELBv2)',
                        'ID': lb_name,
                        'Details': "0 Healthy Targets",
                        'Estimated Monthly Savings ($)': EST_COST_ALB,
                        'Creation Date': lb_created,
                        'Type': 'Cleanup' 
                    })

    except ClientError as e:
         # Some regions might not have ELBs or permissions issues
         st.error(f"Error checking ELBs: {e}")
         
    return findings

def get_expensive_logs(session, region):
    """
    Flag Log Groups >1GB with no retention policy.
    """
    logs = session.client('logs', region_name=region)
    findings = []
    
    try:
        paginator = logs.get_paginator('describe_log_groups')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for group in page['logGroups']:
                stored_bytes = group.get('storedBytes', 0)
                retention = group.get('retentionInDays')
                creation_ts = group.get('creationTime', 0) # ms
                creation_dt = datetime.fromtimestamp(creation_ts / 1000.0, timezone.utc)

                # Check if > 1GB (1073741824 bytes) and Retention is None (Never Expire)
                if stored_bytes > 1073741824 and retention is None:
                    size_gb = stored_bytes / (1024**3)
                    findings.append({
                        'Resource Type': 'CloudWatch Log Group',
                        'ID': group['logGroupName'],
                        'Details': f"Size: {size_gb:.2f} GB, No Retention Policy",
                        'Estimated Monthly Savings ($)': size_gb * EST_COST_LOG_GB,
                        'Creation Date': creation_dt,
                        'Type': 'Cleanup'
                    })

    except ClientError as e:
        st.error(f"Error checking CloudWatch Logs: {e}")
        
    return findings

def get_ecr_no_lifecycle(session, region):
    """
    Identify ECR repositories without a lifecycle policy.
    """
    ecr = session.client('ecr', region_name=region)
    findings = []
    
    try:
        repos = ecr.describe_repositories()['repositories']
        for repo in repos:
            repo_name = repo['repositoryName']
            created = repo['createdAt']
            try:
                ecr.get_lifecycle_policy(repositoryName=repo_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'LifecyclePolicyNotFoundException':
                    findings.append({
                        'Resource Type': 'ECR Repository',
                        'ID': repo_name,
                        'Details': "No Lifecycle Policy found",
                        'Estimated Monthly Savings ($)': 0.0, # Hard to estimate without image enumeration
                        'Creation Date': created,
                        'Type': 'Cleanup' 
                    })
    except ClientError:
        pass
        
    return findings

def get_efs_no_lifecycle(session, region):
    """
    Identify EFS file systems without a lifecycle policy (transition to IA).
    """
    efs = session.client('efs', region_name=region)
    findings = []
    
    try:
        filesystems = efs.describe_file_systems()['FileSystems']
        for fs in filesystems:
            fs_id = fs['FileSystemId']
            created = fs['CreationTime']
            
            # Check lifecycle
            try:
                lifecycle = efs.describe_lifecycle_configuration(FileSystemId=fs_id)['LifecyclePolicies']
                # If list is empty or doesn't verify IA transition, flag it.
                # Simplifying: if no policies at all, flag it.
                if not lifecycle:
                    findings.append({
                        'Resource Type': 'EFS File System',
                        'ID': fs_id,
                        'Details': "No Lifecycle Policy to IA",
                        'Estimated Monthly Savings ($)': 0.0,
                        'Creation Date': created,
                        'Type': 'Cleanup' 
                    })
            except ClientError as e:
                pass
                
    except ClientError:
        pass
        
    return findings

def get_ec2_rightsizing(session, region):
    """
    Identify EC2 instances with LOW Max CPU (< 30%).
    Recommend downsizing (e.g. T-series or smaller size).
    """
    ec2 = session.client('ec2', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    # Simple map for downsizing
    def get_downsize_recommendation(current_type):
        parts = current_type.split('.')
        if len(parts) < 2: return "generic-downsize"
        family, size = parts[0], parts[1]
        
        sizes = ['nano', 'micro', 'small', 'medium', 'large', 'xlarge', '2xlarge', '4xlarge', '8xlarge', '12xlarge', '16xlarge', '24xlarge', '32xlarge']
        try:
            current_idx = sizes.index(size)
            if current_idx > 0:
                new_size = sizes[current_idx - 1]
                return f"{family}.{new_size}"
        except ValueError:
            pass
        return "t3.medium" # Default fallback if unknown size

    try:
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        instance_list = []
        instance_details = {}

        for reservation in instances['Reservations']:
            for inst in reservation['Instances']:
                inst_id = inst['InstanceId']
                instance_list.append(inst_id)
                instance_details[inst_id] = {
                    'LaunchTime': inst['LaunchTime'],
                    'Type': inst['InstanceType']
                }
        
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for inst_id in instance_list:
            # We want MAXIMUM CPU this time
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': inst_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Maximum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            if datapoints:
                max_cpu = max([d['Maximum'] for d in datapoints])
                # If Max CPU is low, we can resize
                if max_cpu < 30.0:
                    current_type = instance_details[inst_id]['Type']
                    rec_type = get_downsize_recommendation(current_type)
                    
                    # Conservative savings estimate: 50% of current cost (assuming 1 size down)
                    est_savings = EST_COST_IDLE_EC2 * 0.5 
                    
                    findings.append({
                        'Resource Type': 'EC2 Instance',
                        'ID': inst_id,
                        'Details': f"Max CPU: {max_cpu:.1f}%. Current: {current_type} → Recommended: {rec_type}",
                        'Estimated Monthly Savings ($)': est_savings,
                        'Creation Date': instance_details[inst_id].get('LaunchTime'),
                        'Type': 'Rightsizing'
                    })

    except ClientError:
        pass
        
    return findings

def get_ebs_modernization(session, region):
    """
    Identify 'gp2' volumes that can be upgraded to 'gp3' (usually cheaper & better).
    """
    ec2 = session.client('ec2', region_name=region)
    findings = []
    
    try:
        # Find gp2 volumes
        volumes = ec2.describe_volumes(Filters=[{'Name': 'volume-type', 'Values': ['gp2']}])['Volumes']
        for vol in volumes:
            size = vol['Size']
            # gp2 price ~0.10/GB. gp3 price ~0.08/GB. Savings ~20%
            savings = size * 0.02
            
            findings.append({
                'Resource Type': 'EBS Volume',
                'ID': vol['VolumeId'],
                'Details': f"Current: gp2 → Recommended: gp3 (Save ~20%)",
                'Estimated Monthly Savings ($)': savings,
                'Creation Date': vol['CreateTime'],
                'Type': 'Rightsizing'
            })
            
    except ClientError:
        pass
        
    return findings


# --- Demo Data Generator ---

def generate_demo_data():
    """Generates fake findings for demonstration purposes."""
    now = datetime.now(timezone.utc)
    findings = [
        # --- CLEANUP (WASTE) ---
        {
            'Resource Type': 'EBS Volume',
            'ID': 'vol-0123456789abcdef0',
            'Details': 'Size: 100 GB, Type: gp2',
            'Estimated Monthly Savings ($)': 100 * EST_COST_EBS_GB,
            'Creation Date': now - timedelta(days=120),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'Elastic IP',
            'ID': '192.0.2.1',
            'Details': 'Unassociated. AllocationId: eipalloc-12345678',
            'Estimated Monthly Savings ($)': EST_COST_EIP,
            'Creation Date': now - timedelta(days=15),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'Elastic IP',
            'ID': '198.51.100.23',
            'Details': 'Attached to STOPPED instance i-stopped123',
            'Estimated Monthly Savings ($)': EST_COST_EIP,
            'Creation Date': now - timedelta(days=5),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'EBS Snapshot',
            'ID': 'snap-0987654321fedcba0',
            'Details': 'Size: 500 GB, Created: 2023-01-01',
            'Estimated Monthly Savings ($)': 500 * EST_COST_SNAPSHOT_GB,
            'Creation Date': now - timedelta(days=400),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'EC2 Instance',
            'ID': 'i-zombie1234567890',
            'Details': 'Avg CPU (7d): 0.5% (Consider Stopping)',
            'Estimated Monthly Savings ($)': EST_COST_IDLE_EC2,
            'Creation Date': now - timedelta(days=60),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'S3 Bucket',
            'ID': 'demo-unused-bucket-log-archive',
            'Details': 'No Lifecycle Policy found',
            'Estimated Monthly Savings ($)': 0.0,
            'Creation Date': now - timedelta(days=800),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'RDS Instance',
            'ID': 'prod-db-replica-unused',
            'Details': '0 Connections in last 7 days',
            'Estimated Monthly Savings ($)': EST_COST_RDS,
            'Creation Date': now - timedelta(days=40),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'Load Balancer (ELBv2)',
            'ID': 'legacy-staging-lb',
            'Details': '0 Healthy Targets',
            'Estimated Monthly Savings ($)': EST_COST_ALB,
            'Creation Date': now - timedelta(days=200),
            'Type': 'Cleanup'
        },
         {
            'Resource Type': 'CloudWatch Log Group',
            'ID': '/aws/lambda/old-function-logs',
            'Details': 'Size: 5.4 GB, No Retention Policy',
            'Estimated Monthly Savings ($)': 5.4 * EST_COST_LOG_GB,
            'Creation Date': now - timedelta(days=90),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'NAT Gateway',
            'ID': 'nat-0123456789abcdef0',
            'Details': 'Bytes Out (7d): 0.00 KB',
            'Estimated Monthly Savings ($)': 32.85,
            'Creation Date': now - timedelta(days=45),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'SageMaker Notebook',
            'ID': 'exploration-notebook-jan',
            'Details': 'Status: InService (Check if idle)',
            'Estimated Monthly Savings ($)': 50.00,
            'Creation Date': now - timedelta(days=10),
            'Type': 'Cleanup'
        },
        {
             'Resource Type': 'ECR Repository',
             'ID': 'backend-api-v1',
             'Details': 'No Lifecycle Policy found',
             'Estimated Monthly Savings ($)': 0.0,
             'Creation Date': now - timedelta(days=300),
             'Type': 'Cleanup'
        },
        # --- New Cleanup Items ---
        {
            'Resource Type': 'AMI Image',
            'ID': 'ami-01234567890abcdef',
            'Details': 'Created 2023-01-15. Not used by any instance.',
            'Estimated Monthly Savings ($)': 5.00,
            'Creation Date': now - timedelta(days=200),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'Security Group',
            'ID': 'launch-wizard-1 (sg-0123)',
            'Details': 'Not attached to any Network Interface.',
            'Estimated Monthly Savings ($)': 0.0,
            'Creation Date': now - timedelta(days=50),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'Redshift Cluster',
            'ID': 'analytics-cluster-dev',
            'Details': '0 Connections in last 24h. Consider Pausing.',
            'Estimated Monthly Savings ($)': 100.00,
            'Creation Date': now - timedelta(days=40),
            'Type': 'Cleanup'
        },
        {
            'Resource Type': 'CloudWatch Alarm',
            'ID': 'High-CPU-Old-Instance',
            'Details': 'INSUFFICIENT_DATA for > 7 days. Likely broken or unused.',
            'Estimated Monthly Savings ($)': 0.0,
            'Creation Date': now - timedelta(days=20),
            'Type': 'Cleanup'
        },

        # --- RIGHTSIZING (MODERNIZATION) ---
        {
            'Resource Type': 'EBS Volume',
            'ID': 'vol-oldgeneration123',
            'Details': 'Current: gp2 → Recommended: gp3 (Save ~20%)',
            'Estimated Monthly Savings ($)': 20.00, # 1000GB gp2 -> gp3
            'Creation Date': now - timedelta(days=600),
            'Type': 'Rightsizing'
        },
        {
            'Resource Type': 'EC2 Instance',
            'ID': 'i-overprovisioned999',
            'Details': 'Max CPU: 12.5%. Current: m5.2xlarge → Recommended: m5.xlarge',
            'Estimated Monthly Savings ($)': 150.00,
            'Creation Date': now - timedelta(days=90),
            'Type': 'Rightsizing'
        },
        # --- New Rightsizing Items ---
        {
            'Resource Type': 'RDS Instance',
            'ID': 'db-read-replica-01',
            'Details': 'Max CPU: 5.2%. Current: db.m5.large → Recommend Downsizing',
            'Estimated Monthly Savings ($)': 45.00,
            'Creation Date': now - timedelta(days=120),
            'Type': 'Rightsizing'
        },
        {
            'Resource Type': 'Lambda Function',
            'ID': 'image-processor-v2',
            'Details': 'Configured Memory: 3008 MB. Check CloudWatch for actual usage.',
            'Estimated Monthly Savings ($)': 0.0, 
            'Creation Date': now - timedelta(days=30),
            'Type': 'Rightsizing'
        },
        {
            'Resource Type': 'ECS Service',
            'ID': 'frontend-cluster/web-service',
            'Details': 'Avg CPU Util: 8.5%. Reservation might be too high.',
            'Estimated Monthly Savings ($)': 50.00,
            'Creation Date': now - timedelta(days=60),
            'Type': 'Rightsizing'
        }
    ]
    
    # Assign Effort Ratings for Consulting View
    for f in findings:
        if 'Effort' not in f:
            if f['Type'] == 'Cleanup':
                 f['Effort'] = 'Low'
            else:
                 f['Effort'] = 'Medium'
                 
            # Overrides for complex tasks
            if 'DynamoDB' in f['Resource Type']:
                f['Effort'] = 'High'
            if 'Redshift' in f['Resource Type']:
                 f['Effort'] = 'High'
            if 'Graviton' in str(f.get('Details', '')):
                 f['Effort'] = 'High'

    return findings

# --- PDF Report Generator ---
def generate_pdf_report(df, company_name, logo_url):
    class PDF(FPDF):
        def header(self):
            if logo_url:
                try:
                    self.image(logo_url, 10, 8, 33)
                    self.set_xy(50, 10)
                except:
                    pass # Fallback if logo url invalid
            else:
                 self.set_xy(10, 10)
            
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, f'{company_name} - Cloud Cost Audit', 0, 1, 'L')
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    
    # Executive Summary
    total_savings = df['Estimated Monthly Savings ($)'].sum()
    annual_savings = total_savings * 12
    count = len(df)
    
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Executive Summary', 0, 1)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, f"We have identified {count} optimization opportunities with a potential annual saving of ${annual_savings:,.2f}.\nActing on these findings will reduce your monthly AWS bill by ${total_savings:,.2f}.")
    pdf.ln(10)
    
    # Top Opportunities
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Top Optimization Opportunities', 0, 1)
    pdf.set_font('Arial', '', 10)
    
    # Table Header
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(40, 10, 'Service', 1, 0, 'C', 1)
    pdf.cell(30, 10, 'Effort', 1, 0, 'C', 1)
    pdf.cell(80, 10, 'Issue', 1, 0, 'C', 1)
    pdf.cell(40, 10, 'Monthly Savings', 1, 1, 'C', 1)
    
    # Table Rows (Top 10)
    top_findings = df.sort_values(by='Estimated Monthly Savings ($)', ascending=False).head(10)
    
    for index, row in top_findings.iterrows():
        # Sanitize text for PDF (Latin-1)
        r_type = str(row['Resource Type']).replace('→', '->')[:20]
        effort = str(row.get('Effort', 'N/A')).replace('→', '->')
        details = str(row['Details']).replace('→', '->')[:40]
        
        # Safe encode/decode to remove any other incompatible chars
        r_type = r_type.encode('latin-1', 'ignore').decode('latin-1')
        effort = effort.encode('latin-1', 'ignore').decode('latin-1')
        details = details.encode('latin-1', 'ignore').decode('latin-1')

        pdf.cell(40, 10, r_type, 1)
        pdf.cell(30, 10, effort, 1)
        pdf.cell(80, 10, details, 1)
        pdf.cell(40, 10, f"${row['Estimated Monthly Savings ($)']:,.2f}", 1, 1, 'R')

    return bytes(pdf.output())

# --- Main Application ---

def main():
    # --- State Management ---
    if 'data_snapshot' not in st.session_state:
        st.session_state.data_snapshot = None
    if 'audit_run' not in st.session_state:
        st.session_state.audit_run = False
    
    # Defaults for config
    if 'selected_region' not in st.session_state:
        st.session_state.selected_region = "us-east-1"
    if 'use_demo_mode' not in st.session_state:
        st.session_state.use_demo_mode = False
    if 'company_name' not in st.session_state:
        st.session_state.company_name = "Cloud Cost Optimiser"
    if 'logo_url' not in st.session_state:
        st.session_state.logo_url = ""

    available_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2",
        "ap-northeast-1", "sa-east-1"
    ]
    


    # --- Helper: Render Header ---
    def render_header(title_suffix=""):
        col1, col2 = st.columns([1, 4])
        with col1:
             if st.session_state.logo_url:
                 st.image(st.session_state.logo_url, width=80)
             else:
                 st.write(f"<h1>{PAGE_ICON}</h1>", unsafe_allow_html=True)
        with col2:
             st.title(f"{st.session_state.company_name} {title_suffix}")

    # --- Landing Page Logic ---
    if not st.session_state.audit_run:
        # Centered Landing Layout
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            render_header()
            st.markdown(
                """
                <div style='text-align: center; margin-bottom: 20px;'>
                Welcome! This tool scans your AWS environment to identify
                <b>orphaned resources</b>, <b>idle compute</b>, and <b>storage waste</b>.
                </div>
                """, unsafe_allow_html=True
            )

            # Configuration Form
            with st.container(border=True):
                st.subheader("⚙️ Configuration")
                
                region_input = st.selectbox(
                    "Select Target Region", 
                    available_regions, 
                    index=available_regions.index(st.session_state.selected_region) if st.session_state.selected_region in available_regions else 0
                )
                
                demo_input = st.checkbox(
                    "Enable Demo Mode", 
                    value=st.session_state.use_demo_mode,
                    help="Simulate findings without AWS credentials."
                )

                st.markdown("---")
                # AWS Configure Instructions
                with st.expander("ℹ️ Prerequisites"):
                    st.markdown(
                        """
                        Ensure you have the **AWS CLI** installed and configured locally:
                        ```bash
                        aws configure
                        ```
                        [👉 Official Setup Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)
                        """
                    )
                
                # Big Run Button
                if st.button("🚀 Run Cloud Audit", use_container_width=True, type="primary"):
                    st.session_state.selected_region = region_input
                    st.session_state.use_demo_mode = demo_input
                    st.session_state.audit_run = True
                    st.rerun()

    # --- Results Page Logic ---
    else:
        # --- Sidebar Config (Whitelabeling) ---
        with st.sidebar.expander("📝 Report Settings"):
            st.session_state.company_name = st.text_input("Company Name", value=st.session_state.company_name)
            st.session_state.logo_url = st.text_input("Logo URL (Optional)", value=st.session_state.logo_url)
            
            # PDF Download
            if st.session_state.data_snapshot:
                try:
                    pdf_bytes = generate_pdf_report(
                        pd.DataFrame(st.session_state.data_snapshot),
                        st.session_state.company_name,
                        st.session_state.logo_url
                    )
                    st.download_button(
                        label="📄 Download PDF Report",
                        data=pdf_bytes,
                        file_name="cloud_audit_report.pdf",
                        mime="application/pdf"
                    )
                except Exception as e:
                    st.error(f"Failed to generate PDF: {e}")

        # Retrieve config from session state
        region = st.session_state.selected_region
        demo_mode = st.session_state.use_demo_mode

        # Header with Back Button context
        c1, c2 = st.columns([5, 1])
        with c1:
            render_header(title_suffix=f"- Audit Results: {region}")
        with c2:
            if st.button("🔄 New Audit"):
                st.session_state.audit_run = False
                st.session_state.data_snapshot = None
                st.rerun()
        
        # Run Logic (if no data yet)
        if st.session_state.data_snapshot is None:
            with st.spinner(f"Scanning resources in {region}..."):
                try:
                    all_findings = []
                    if demo_mode:
                        all_findings = generate_demo_data()
                    else:
                        # Real AWS Scan
                        session = get_session(region)
                        session.client('sts').get_caller_identity() # Test Auth
                        
                        # Cleanup Scans
                        scan_funcs_cleanup = [
                            get_orphaned_resources, get_old_snapshots, get_low_cpu_instances,
                            get_s3_no_lifecycle, get_idle_rds, get_idle_sagemaker,
                            get_idle_elasticache, get_unused_dynamodb, get_zombie_elbs,
                            get_expensive_logs, get_idle_nat_gateways, get_ecr_no_lifecycle,
                            get_efs_no_lifecycle, get_old_amis, get_unused_security_groups,
                            get_redshift_pausing, get_broken_alarms
                        ]
                        for func in scan_funcs_cleanup:
                            all_findings.extend(func(session, region))
                        
                        # Rightsizing Scans
                        scan_funcs_rightsize = [
                            get_ec2_rightsizing, get_ebs_modernization, get_rds_rightsizing,
                            get_lambda_optimizations, get_ecs_rightsizing, get_dynamodb_ia_recommendations
                        ]
                        for func in scan_funcs_rightsize:
                            all_findings.extend(func(session, region))

                    st.session_state.data_snapshot = all_findings
                
                except (NoCredentialsError, PartialCredentialsError):
                    st.error("❌ AWS Credentials not found.")
                    st.markdown("""
                        Please configure them locally using:
                        ```bash
                        aws configure
                        ```
                        Or enable **Demo Mode** to test without credentials.
                    """)
                    if st.button("Back to Config"):
                        st.session_state.audit_run = False
                        st.rerun()
                    st.stop()
                except Exception as e:
                    st.error(f"❌ An error occurred: {e}")
                    if st.button("Back to Config"):
                        st.session_state.audit_run = False
                        st.rerun()
                    st.stop()
        
        # Display Results
        findings = st.session_state.data_snapshot
        
        if not findings:
            st.success("🎉 No resource waste found! Your environment looks clean.")
            return

        df = pd.DataFrame(findings)
        
        # Ensure standard cols
        if 'Type' not in df.columns: df['Type'] = 'Cleanup'

        # Metrics
        total_savings = df['Estimated Monthly Savings ($)'].sum()
        cleanup_savings = df[df['Type'] == 'Cleanup']['Estimated Monthly Savings ($)'].sum()
        rightsize_savings = df[df['Type'] == 'Rightsizing']['Estimated Monthly Savings ($)'].sum()
        
        # Top Recommendations Summary
        st.markdown("### 📊 Executive Summary")
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Potential Savings", f"${total_savings:,.2f}", delta_color="inverse")
        m2.metric("Cleanup Opportunities", f"${cleanup_savings:,.2f}")
        m3.metric("Rightsizing Opportunities", f"${rightsize_savings:,.2f}")
        
        st.divider()

        # --- Executive Summary ---
        def generate_executive_summary(df):
            total_savings = df['Estimated Monthly Savings ($)'].sum()
            annual_savings = total_savings * 12
            
            # Identify top opportunities
            if not df.empty:
                top_findings = df.sort_values(by='Estimated Monthly Savings ($)', ascending=False).head(3)
                services = top_findings['Resource Type'].unique()
                services_list = list(services)
                if len(services_list) > 1:
                    services_str = ", ".join(services_list[:-1]) + " and " + services_list[-1]
                else:
                    services_str = services_list[0]
            else:
                services_str = "N/A"
            
            summary = f"""
            #### 🚀 Executive Summary
            We have identified **{len(df)}** optimization opportunities with a potential **annual saving of ${annual_savings:,.2f}**.
            
            The most significant opportunities are found in **{services_str}**. 
            Acting on these findings will not only reduce your monthly AWS bill by **${total_savings:,.2f}** but also improve your infrastructure's security and performance posture.
            """
            return summary

        st.info(generate_executive_summary(df))

        # --- High Level Visuals ---
        st.subheader("🏆 Top Savings by Service")
        
        # Group by Resource Type and sum savings
        service_summary = df.groupby('Resource Type')['Estimated Monthly Savings ($)'].sum().reset_index()
        
        # Sort desc and just show top 5 services if there are many
        top_services = service_summary.nlargest(5, 'Estimated Monthly Savings ($)')
        
        st.bar_chart(
            data=top_services, 
            x='Resource Type', 
            y='Estimated Monthly Savings ($)', 
            use_container_width=True, 
            color='#FF4B4B'
        )
        
        st.divider()
        c_head, c_export = st.columns([4, 1])
        with c_head:
            st.subheader("🔍 Detailed Findings")
            st.caption("ℹ️ These findings are advisory. Please consult with your engineering team before taking action.")
        with c_export:
            # Generate CSV for download
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export CSV",
                data=csv_data,
                file_name=f"aws_audit_report_{region}_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                key='download-main'
            )

        # --- Categorization Logic ---
        def get_resource_category(resource_type):
            if resource_type in ['EC2 Instance', 'Elastic IP', 'Load Balancer (ELBv2)', 'NAT Gateway', 'SageMaker Notebook']:
                return 'Compute & Networking'
            elif resource_type in ['EBS Volume', 'EBS Snapshot', 'S3 Bucket', 'EFS File System', 'ECR Repository']:
                return 'Storage'
            elif resource_type in ['RDS Instance', 'DynamoDB Table', 'Elasticache Cluster']:
                return 'Database'
            elif resource_type == 'CloudWatch Log Group':
                return 'Observability'
            return 'Other'

        df['Category'] = df['Resource Type'].apply(get_resource_category)

        # --- Filter Logic ---
        all_types = sorted(df['Resource Type'].unique().tolist())
        selected_types = st.multiselect("🔎 Filter by Service", all_types, placeholder="All Services")
        
        if selected_types:
            df = df[df['Resource Type'].isin(selected_types)]

        # Tabs for view separation
        tab_cleanup, tab_rights, tab_all = st.tabs(["🗑️ Cleanup Scenarios", "📉 Rightsizing Recommendations", "📋 All Findings"])

        # --- Helper: Render Groups ---
        def render_grouped_dataframe(dataframe, mode='standard'):
            cat_order = ['Compute & Networking', 'Database', 'Storage', 'Observability', 'Other']
            has_data = False
            
            for cat in cat_order:
                cat_df = dataframe[dataframe['Category'] == cat]
                if cat_df.empty:
                    continue
                
                has_data = True
                # Sum savings for the category
                cat_savings = cat_df['Estimated Monthly Savings ($)'].sum()
                st.markdown(f"#### 🔹 {cat} — Total: **${cat_savings:,.2f}**")
                
                # Sort by savings desc
                res_summary = cat_df.groupby('Resource Type')['Estimated Monthly Savings ($)'].sum().sort_values(ascending=False)
                
                for r_type in res_summary.index:
                    subset = cat_df[cat_df['Resource Type'] == r_type]
                    total_r_savings = res_summary[r_type]
                    count = len(subset)
                    
                    if total_r_savings > 0:
                        label = f"**{r_type}** ({count}) — Save **${total_r_savings:,.2f}** / month"
                    else:
                        label = f"**{r_type}** ({count}) — **Optimization Opportunities**"
                    
                    # Effort Badge
                    if 'Effort' in subset.columns:
                        effort = subset.iloc[0]['Effort']
                        badge = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}.get(effort, "⚪")
                        label = f"{badge} {label}"
                    
                    with st.expander(label):
                        # Column Config based on mode
                        if mode == 'rightsizing':
                            st.dataframe(
                                subset[['ID', 'Details', 'Estimated Monthly Savings ($)', 'Creation Date']],
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "Details": st.column_config.TextColumn("Recommendation", width="large"),
                                    "Estimated Monthly Savings ($)": st.column_config.NumberColumn("Est. Savings ($)", format="$%.2f")
                                }
                            )
                        else:
                            st.dataframe(
                                subset[['ID', 'Details', 'Estimated Monthly Savings ($)', 'Creation Date']],
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "Details": st.column_config.TextColumn("Details", width="medium"),
                                    "Estimated Monthly Savings ($)": st.column_config.NumberColumn("Est. Savings ($)", format="$%.2f")
                                }
                            )

            if not has_data:
                st.info("No findings in this category.")

        with tab_cleanup:
            # Filter for Cleanup
            cleanup_df = df[df['Type'] == 'Cleanup']
            render_grouped_dataframe(cleanup_df, mode='cleanup')

        with tab_rights:
            # Filter for Rightsizing
            rights_df = df[df['Type'] == 'Rightsizing']
            render_grouped_dataframe(rights_df, mode='rightsizing')

        with tab_all:
             st.dataframe(
                df, 
                use_container_width=True, 
                hide_index=True,
                column_config={
                    "Estimated Monthly Savings ($)": st.column_config.NumberColumn("Savings ($)", format="$%.2f")
                }
            )
            

if __name__ == "__main__":
    main()

def get_rds_rightsizing(session, region):
    """
    Identify RDS instances with low CPU (< 30%) to recommend downsizing.
    """
    rds = session.client('rds', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        dbs = rds.describe_db_instances()['DBInstances']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        for db in dbs:
            db_id = db['DBInstanceIdentifier']
            db_class = db['DBInstanceClass']
            engine = db['Engine']
            
            if db['DBInstanceStatus'] != 'available':
                continue

            # Check CPU
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Maximum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            if datapoints:
                max_cpu = max([d['Maximum'] for d in datapoints])
                if max_cpu < 30.0:
                    findings.append({
                        'Resource Type': 'RDS Instance',
                        'ID': db_id,
                        'Details': f"Max CPU: {max_cpu:.1f}%. Current: {db_class} → Recommend Downsizing",
                        'Estimated Monthly Savings ($)': EST_COST_RDS * 0.3, # Approx 30% saving
                        'Creation Date': db['InstanceCreateTime'],
                        'Type': 'Rightsizing'
                    })
                    
    except ClientError:
        pass
        
    return findings

def get_lambda_optimizations(session, region):
    """
    Identify Lambda functions that might be over-provisioned (High Memory > 1GB, Low Usage).
    Strictly heuristic-based without Logs Insights.
    """
    awslambda = session.client('lambda', region_name=region)
    findings = []
    
    try:
        paginator = awslambda.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                mem = func['MemorySize']
                name = func['FunctionName']
                
                # Heuristic: If Memory > 1024 MB, might be worth checking if it's actually needed.
                # Real optimization requires analyzing 'Max Memory Used' from logs, which is expensive to query here.
                # We will just flag 'Potential' over-provisioning for high-memory functions.
                if mem > 1024:
                    findings.append({
                        'Resource Type': 'Lambda Function',
                        'ID': name,
                        'Details': f"Configured Memory: {mem} MB. Check CloudWatch for actual usage.",
                        'Estimated Monthly Savings ($)': 0.0, # detailed calc too complex for simple scan
                        'Creation Date': datetime.strptime(func['LastModified'].split('+')[0], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc),
                        'Type': 'Rightsizing'
                    })
    except ClientError:
        pass
        
    return findings

def get_ecs_rightsizing(session, region):
    """
    Identify ECS Services with low CPU Utilization vs Reservation.
    """
    ecs = session.client('ecs', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        clusters = ecs.list_clusters()['clusterArns']
        for cluster in clusters:
            services = ecs.list_services(cluster=cluster)['serviceArns']
            # ECS list_services returns max 10. Paginator needed for robust apps, simplified here.
            
            if not services:
                continue
                
            desc_services = ecs.describe_services(cluster=cluster, services=services)['services']
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=7)

            for svc in desc_services:
                svc_name = svc['serviceName']
                cluster_name = cluster.split('/')[-1]
                
                # Check CPU Utilization
                metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ECS',
                    MetricName='CPUUtilization',
                    Dimensions=[
                        {'Name': 'ClusterName', 'Value': cluster_name},
                        {'Name': 'ServiceName', 'Value': svc_name}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Average'] # Avg utilization
                )
                
                datapoints = metrics.get('Datapoints', [])
                if datapoints:
                    avg_cpu = sum([d['Average'] for d in datapoints]) / len(datapoints)
                    # If avg CPU utilization (which is % of Reservation) is very low (< 10%)
                    if avg_cpu < 10.0:
                         findings.append({
                            'Resource Type': 'ECS Service',
                            'ID': f"{cluster_name}/{svc_name}",
                            'Details': f"Avg CPU Util: {avg_cpu:.1f}%. Reservation might be too high.",
                            'Estimated Monthly Savings ($)': 50.00, # Placeholder
                            'Creation Date': svc['createdAt'],
                            'Type': 'Rightsizing'
                        })

    except ClientError:
        pass
    
    return findings

def get_dynamodb_ia_recommendations(session, region):
    """
    Identify Standard tables that could benefit from Infrequent Access (Standard-IA) class.
    Heuristic: Low Read/Write activity relative to storage.
    """
    dynamo = session.client('dynamodb', region_name=region)
    findings = []
    
    try:
        tables = dynamo.list_tables()['TableNames']
        for t_name in tables:
            desc = dynamo.describe_table(TableName=t_name)['Table']
            table_class = desc.get('TableClassSummary', {}).get('TableClass', 'STANDARD')
            
            if table_class == 'STANDARD':
                # If table is > 10GB but has no recent usage? 
                # Checking metrics is best...
                pass 
                # Simplified: Just a placeholder for the logic pattern as specific IA calc is complex without deeper metrics.
                # We will skip active implementation to keep it robust and not noisy.
                
    except ClientError:
        pass
        
    return findings

def get_old_amis(session, region):
    """
    Identify AMIs > 180 days old that are not currently used.
    """
    ec2 = session.client('ec2', region_name=region)
    findings = []
    
    try:
        # Get my AMIs
        amis = ec2.describe_images(Owners=['self'])['Images']
        
        # Get AMIs used by running instances (to avoid deleting active ones)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
        used_amis = set()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                used_amis.add(inst['ImageId'])
                
        cutoff = datetime.now(timezone.utc) - timedelta(days=180)
        
        for ami in amis:
            ami_id = ami['ImageId']
            created = datetime.strptime(ami['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            
            if created < cutoff and ami_id not in used_amis:
                 findings.append({
                    'Resource Type': 'AMI Image',
                    'ID': ami_id,
                    'Details': f"Created {created.date()}. Not used by any instance.",
                    'Estimated Monthly Savings ($)': 5.00, # Approx storage cost for Snapshot
                    'Creation Date': created,
                    'Type': 'Cleanup' 
                })
                
    except ClientError:
        pass
        
    return findings

def get_unused_security_groups(session, region):
    """
    Identify Security Groups not attached to any ENI.
    """
    ec2 = session.client('ec2', region_name=region)
    findings = []
    
    try:
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'owner-id', 'Values': ['self']}])['SecurityGroups']
        all_sgs = {sg['GroupId']: sg['GroupName'] for sg in sgs if sg['GroupName'] != 'default'}
        
        # Find Used SGs
        enis = ec2.describe_network_interfaces()['NetworkInterfaces']
        used_sgs = set()
        for eni in enis:
            for group in eni['Groups']:
                used_sgs.add(group['GroupId'])
                
        for sg_id, sg_name in all_sgs.items():
            if sg_id not in used_sgs:
                 findings.append({
                    'Resource Type': 'Security Group',
                    'ID': f"{sg_name} ({sg_id})",
                    'Details': "Not attached to any Network Interface.",
                    'Estimated Monthly Savings ($)': 0.0, # Hygiene only
                    'Creation Date': datetime.now(timezone.utc), # SG doesn't have create date in describe
                    'Type': 'Cleanup' 
                })
                
    except ClientError:
        pass
        
    return findings

def get_redshift_pausing(session, region):
    """
    Identify Redshift clusters that could be paused (0 connections in last 24h).
    """
    redshift = session.client('redshift', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        clusters = redshift.describe_clusters()['Clusters']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=1)
        
        for cluster in clusters:
            c_id = cluster['ClusterIdentifier']
            status = cluster['ClusterStatus']
            
            if status != 'available':
                continue
                
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/Redshift',
                MetricName='DatabaseConnections',
                Dimensions=[{'Name': 'ClusterIdentifier', 'Value': c_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Maximum']
            )
            
            datapoints = metrics.get('Datapoints', [])
            max_conn = max([d['Maximum'] for d in datapoints]) if datapoints else 0
            
            if datapoints and max_conn == 0:
                findings.append({
                    'Resource Type': 'Redshift Cluster',
                    'ID': c_id,
                    'Details': "0 Connections in last 24h. Consider Pausing.",
                    'Estimated Monthly Savings ($)': 100.00, # Placeholder
                    'Creation Date': cluster['ClusterCreateTime'],
                    'Type': 'Cleanup'
                })
                
    except ClientError:
        pass
        
    return findings

def get_broken_alarms(session, region):
    """
    Identify CloudWatch Alarms in INSUFFICIENT_DATA state for > 7 days.
    """
    cw = session.client('cloudwatch', region_name=region)
    findings = []
    
    try:
        alarms = cw.describe_alarms(StateValue='INSUFFICIENT_DATA')['MetricAlarms']
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        
        for alarm in alarms:
            # updated is when it last changed state
            updated = alarm['StateUpdatedTimestamp'] 
            if updated < cutoff:
                findings.append({
                    'Resource Type': 'CloudWatch Alarm',
                    'ID': alarm['AlarmName'],
                    'Details': "INSUFFICIENT_DATA for > 7 days. Likely broken or unused.",
                    'Estimated Monthly Savings ($)': 0.0, # Alarms cost $0.10, negligible but good hygiene
                    'Creation Date': alarm['AlarmConfigurationUpdatedTimestamp'],
                    'Type': 'Cleanup'
                })
                
    except ClientError:
        pass
        
    return findings
