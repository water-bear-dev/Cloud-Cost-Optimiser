# AWS Cost Optimization Dashboard

A Python-based web application to audit your AWS environment and identify potential cost savings. This tool runs locally on your machine and uses your configured AWS credentials to scan for wasted resources.

## Prerequisites

1.  **Python 3.9+** installed.
2.  **AWS Credentials** configured locally.
    *   **Install AWS CLI**: If you don't have it, install it from [AWS CLI Install Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
    *   **Configure**: Open your terminal and run:
        ```bash
        aws configure
        ```
        Enter your Access Key ID, Secret Access Key, Default Region (e.g., `us-east-1`), and Output format (`json`).
    *   **Permissions**: Ensure your IAM user has the following **ReadOnly** permissions. You can attach the managed policy `ReadOnlyAccess` or use this least-privilege custom policy:

    <details>
    <summary>Click to view IAM Policy JSON</summary>

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeSnapshots",
                    "ec2:DescribeAddresses",
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLifecycleConfiguration",
                    "rds:DescribeDBInstances",
                    "elasticloadbalancing:DescribeLoadBalancers",
                    "elasticloadbalancing:DescribeTargetGroups",
                    "elasticloadbalancing:DescribeTargetHealth",
                    "cloudwatch:GetMetricStatistics",
                    "logs:DescribeLogGroups"
                ],
                "Resource": "*"
            }
        ]
    }
    ```
    </details>

## Installation

1.  Clone this repository or download the files.
2.  Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## How to Run

1.  Navigate to the directory containing the script.
2.  Run the application using Streamlit:

    ```bash
    streamlit run audit_app.py
    ```

3.  A browser window will open automatically.
4.  Select your **Target Region** from the sidebar and click **Run Audit**.

## Features
    
The tool scans for the following cost-saving opportunities:

*   **Orphaned Resources:** Detached EBS volumes and unassociated Elastic IPs.
*   **Snapshot Hygiene:** EBS snapshots older than 90 days.
*   **Compute Waste:** Running EC2 instances with <5% average CPU utilization (last 7 days).
*   **Storage Waste:** S3 buckets without a Lifecycle Policy.
*   **Idle Databases:** RDS instances with 0 connections (last 7 days).
*   **Zombie Load Balancers:** ELBs with 0 healthy targets.
*   **Expensive Logs:** CloudWatch Log Groups >1GB with no retention policy.

**✨ Demo Mode:**
If you don't have AWS credentials configured but want to test the UI, check the **"Enable Demo Mode"** box in the sidebar to simulate finding data.

## Troubleshooting

-   **"No Credentials" Error:** Check your `~/.aws/credentials` file or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
-   **Permissions Error:** Ensure your IAM user/role has permission to `describe` or `list` resources for the services mentioned above.
