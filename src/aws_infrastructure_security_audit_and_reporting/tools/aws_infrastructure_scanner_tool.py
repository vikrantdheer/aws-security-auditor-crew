from typing import Type, Dict, List, Any
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import boto3
import json
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class AWSInfrastructureScannerInput(BaseModel):
    """Input schema for AWSInfrastructureScanner."""
    service: str = Field(
        ...,
        description="AWS service to scan (e.g., 'ec2', 's3', 'iam', 'rds', 'vpc', 'all')"
    )
    region: str = Field(
        default_factory=lambda: os.getenv('AWS_REGION_NAME', 'us-west-2'),
        description="AWS region to scan"
    )

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class AWSInfrastructureScannerTool(BaseTool):
    name: str = "AWS Infrastructure Scanner"
    description: str = (
        "A tool for scanning and mapping AWS infrastructure components and their configurations. "
        "Can retrieve detailed information about EC2 instances, S3 buckets, IAM configurations, "
        "RDS instances, VPC settings, and security groups. Use this tool to gather information "
        "about specific AWS services or get a complete infrastructure overview."
    )
    args_schema: Type[BaseModel] = AWSInfrastructureScannerInput

    def _run(self, **kwargs: Any) -> str:
        """Run the scanner. Accepts kwargs so CrewAI can pass service/region from LLM tool call."""
        try:
            service = (kwargs.get("service") or kwargs.get("Service") or "").strip() or "all"
            region = (kwargs.get("region") or kwargs.get("Region") or "").strip() or os.getenv("AWS_REGION_NAME", "us-east-1")
            service = service.lower() if service else "all"
            logger.info("AWSInfrastructureScanner: service=%s region=%s", service, region)
            if service == "all":
                logger.info("Scanning ALL services (ec2, s3, iam, rds, vpc) in region=%s", region)
                return json.dumps(self._scan_all_services(region), indent=2, cls=DateTimeEncoder)
            logger.info("Scanning single service: %s in region=%s", service, region)
            return json.dumps(self._scan_service(service, region), indent=2, cls=DateTimeEncoder)
        except Exception as e:
            logger.exception("Error scanning AWS infrastructure")
            return f"Error scanning AWS infrastructure: {str(e)}"

    def _scan_all_services(self, region: str) -> Dict:
        return {
            'ec2': self._scan_service('ec2', region),
            's3': self._scan_service('s3', region),
            'iam': self._scan_service('iam', region),
            'rds': self._scan_service('rds', region),
            'vpc': self._scan_service('vpc', region)
        }

    def _scan_service(self, service: str, region: str) -> Dict:
        session = boto3.Session(region_name=region)

        if service == 'ec2':
            client = session.client('ec2')
            instances = client.describe_instances()
            security_groups = client.describe_security_groups()
            inst_list = instances['Reservations'][:5]
            sg_list = security_groups['SecurityGroups'][:5]
            inst_ids = [inst.get("InstanceId") for r in inst_list for inst in r.get("Instances", [])]
            sg_names = [sg.get("GroupName") or sg.get("GroupId") for sg in sg_list]
            logger.info("EC2 [%s]: found %d instance(s) %s, %d security group(s) %s", region, len(inst_ids), inst_ids or "none", len(sg_names), sg_names or "none")
            return {
                'instances': inst_list,
                'security_groups': sg_list
            }

        elif service == 's3':
            client = session.client('s3')
            buckets = client.list_buckets()
            bucket_details = []
            for bucket in buckets['Buckets'][:5]:
                try:
                    encryption = client.get_bucket_encryption(Bucket=bucket['Name'])
                except client.exceptions.ClientError:
                    encryption = None
                bucket_details.append({
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'],
                    'encryption': encryption
                })
            names = [b['name'] for b in bucket_details]
            logger.info("S3 [%s]: found %d bucket(s) %s", region, len(names), names or "none")
            return {'buckets': bucket_details}

        elif service == 'iam':
            client = session.client('iam')
            users = client.list_users()['Users'][:5]
            roles = client.list_roles()['Roles'][:5]
            policies = client.list_policies(Scope='Local')['Policies'][:5]
            user_names = [u.get("UserName") for u in users]
            role_names = [r.get("RoleName") for r in roles]
            logger.info("IAM [%s]: found %d user(s) %s, %d role(s) %s, %d policy(ies)", region, len(user_names), user_names or "none", len(role_names), role_names or "none", len(policies))
            return {
                'users': users,
                'roles': roles,
                'policies': policies
            }

        elif service == 'rds':
            client = session.client('rds')
            db_list = client.describe_db_instances()['DBInstances'][:5]
            db_ids = [db.get("DBInstanceIdentifier") for db in db_list]
            logger.info("RDS [%s]: found %d instance(s) %s", region, len(db_ids), db_ids or "none")
            return {
                'instances': db_list
            }

        elif service == 'vpc':
            client = session.client('ec2')
            vpcs = client.describe_vpcs()['Vpcs'][:5]
            subnets = client.describe_subnets()['Subnets'][:5]
            nacls = client.describe_network_acls()['NetworkAcls'][:5]
            vpc_ids = [v.get("VpcId") for v in vpcs]
            logger.info("VPC [%s]: found %d VPC(s) %s, %d subnet(s), %d NACL(s)", region, len(vpc_ids), vpc_ids or "none", len(subnets), len(nacls))
            return {
                'vpcs': vpcs,
                'subnets': subnets,
                'network_acls': nacls
            }

        else:
            logger.warning("Unsupported service requested: %s", service)
            return {'error': f'Unsupported service: {service}'}
