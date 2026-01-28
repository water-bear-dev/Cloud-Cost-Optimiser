
import boto3
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

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

def get_ec2_rightsizing(session, region):
    """
    Identify EC2 instances with LOW Max CPU (< 30%).
    Recommend downsizing (e.g. T-series or smaller size).
    """
    ec2 = session.client('ec2', region_name=region)
    cloudwatch = session.client('cloudwatch', region_name=region)
    findings = []
    
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
                    # Conservative savings estimate: 50% of current cost (assuming 1 size down)
                    # We'll use a placeholder cost calc since we don't have a pricing API
                    est_savings = EST_COST_IDLE_EC2 * 0.5 
                    
                    findings.append({
                        'Resource Type': 'EC2 Instance',
                        'ID': inst_id,
                        'Details': f"Max CPU (7d): {max_cpu:.2f}%. Current: {current_type}. Recommend Rightsizing.",
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
                'Details': f"Type is gp2. Migrate to gp3 for ~20% savings.",
                'Estimated Monthly Savings ($)': savings,
                'Creation Date': vol['CreateTime'],
                'Type': 'Rightsizing'
            })
            
    except ClientError:
        pass
        
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

        # --- RIGHTSIZING (MODERNIZATION) ---
        {
            'Resource Type': 'EBS Volume',
            'ID': 'vol-oldgeneration123',
            'Details': 'Type is gp2. Migrate to gp3 for ~20% savings.',
            'Estimated Monthly Savings ($)': 20.00, # 1000GB gp2 -> gp3
            'Creation Date': now - timedelta(days=600),
            'Type': 'Rightsizing'
        },
        {
            'Resource Type': 'EC2 Instance',
            'ID': 'i-overprovisioned999',
            'Details': 'Max CPU (7d): 12.5%. Current: m5.2xlarge. Recommend Rightsizing.',
            'Estimated Monthly Savings ($)': 150.00,
            'Creation Date': now - timedelta(days=90),
            'Type': 'Rightsizing'
        }
    ]
    return findings

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

    available_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2",
        "ap-northeast-1", "sa-east-1"
    ]

    # --- Landing Page Logic ---
    if not st.session_state.audit_run:
        # Centered Landing Layout
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.title(f"{PAGE_ICON} AWS Cost Optimiser")
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
        # Retrieve config from session state
        region = st.session_state.selected_region
        demo_mode = st.session_state.use_demo_mode

        # Header with Back Button context
        c1, c2 = st.columns([5, 1])
        with c1:
            st.title(f"{PAGE_ICON} Audit Results: {region}")
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
                            get_efs_no_lifecycle
                        ]
                        for func in scan_funcs_cleanup:
                            all_findings.extend(func(session, region))
                        
                        # Rightsizing Scans
                        scan_funcs_rightsize = [get_ec2_rightsizing, get_ebs_modernization]
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

        # Export Button (Prominent)
        csv_data = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Full Report (CSV)",
            data=csv_data,
            file_name=f'aws_audit_{region}_{datetime.now().strftime("%Y%m%d")}.csv',
            mime='text/csv',
            type="secondary"
        )
        
        st.divider()
        st.subheader("🔍 Detailed Findings")

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

        # Order we want to show categories
        cat_order = ['Compute & Networking', 'Database', 'Storage', 'Observability', 'Other']

        # Loop through Categories
        for cat in cat_order:
            cat_df = df[df['Category'] == cat]
            if cat_df.empty:
                continue
            
            # Category Header
            st.markdown(f"#### 🔹 {cat}")
            
            # Loop through Resource Types in this Category
            # Sort by savings desc
            res_summary = cat_df.groupby('Resource Type')['Estimated Monthly Savings ($)'].sum().sort_values(ascending=False)
            
            for r_type in res_summary.index:
                subset = cat_df[cat_df['Resource Type'] == r_type]
                total_r_savings = res_summary[r_type]
                count = len(subset)

                # Expander Title
                expander_label = f"**{r_type}** ({count}) — Save **${total_r_savings:,.2f}** / month"
                
                with st.expander(expander_label):
                    # Clean Table
                    display_cols = ['ID', 'Details', 'Estimated Monthly Savings ($)', 'Creation Date']
                    valid_cols = [c for c in display_cols if c in subset.columns]
                    
                    st.dataframe(
                        subset[valid_cols],
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "Details": st.column_config.TextColumn(
                                "Details",
                                help="Specific finding details",
                                width="medium"
                            ),
                            "Estimated Monthly Savings ($)": st.column_config.NumberColumn(
                                "Est. Savings ($)",
                                format="$%.2f"
                            )
                        }
                    )

if __name__ == "__main__":
    main()
