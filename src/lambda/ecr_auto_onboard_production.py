#!/usr/bin/env python3
"""
Production ECR Auto-Onboarding Lambda Function with Dynamic IAM Role Discovery

Automatically discovers ECR registries from CrowdStrike Asset Explorer,
dynamically discovers IAM roles from CSPM registration data,
and registers them with Container Security for image assessment.

Key Features:
- Dynamic IAM role discovery (no hardcoded templates)
- Comprehensive logging and error handling
- SNS notifications and Slack integration
- Dry-run mode for testing
- Multi-account support via Asset Explorer
"""

import json
import logging
import os
import boto3
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
import requests

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment variables
USE_SECRETS_MANAGER = os.environ.get('USE_SECRETS_MANAGER', 'true').lower() == 'true'
CROWDSTRIKE_SECRETS_ARN = os.environ.get('CROWDSTRIKE_SECRETS_ARN')
CROWDSTRIKE_CLIENT_ID = os.environ.get('CROWDSTRIKE_CLIENT_ID')
CROWDSTRIKE_CLIENT_SECRET = os.environ.get('CROWDSTRIKE_CLIENT_SECRET')
CROWDSTRIKE_BASE_URL = os.environ.get('CROWDSTRIKE_BASE_URL', 'https://api.crowdstrike.com')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
DRY_RUN_MODE = os.environ.get('DRY_RUN_MODE', 'false').lower() == 'true'
SLACK_WEBHOOK_PARAMETER = os.environ.get('SLACK_WEBHOOK_PARAMETER')
ENABLE_CLEANUP = os.environ.get('ENABLE_CLEANUP', 'true').lower() == 'true'
CLEANUP_OFFLINE_DAYS = int(os.environ.get('CLEANUP_OFFLINE_DAYS', '7'))

# Initialize AWS clients
sns = boto3.client('sns') if SNS_TOPIC_ARN else None
ssm = boto3.client('ssm') if SLACK_WEBHOOK_PARAMETER else None
secrets_manager = boto3.client('secretsmanager') if USE_SECRETS_MANAGER else None

def get_crowdstrike_credentials():
    """Get CrowdStrike credentials from Secrets Manager or environment variables"""
    if USE_SECRETS_MANAGER and CROWDSTRIKE_SECRETS_ARN:
        logger.info("🔐 Retrieving CrowdStrike credentials from Secrets Manager...")
        try:
            response = secrets_manager.get_secret_value(SecretId=CROWDSTRIKE_SECRETS_ARN)
            secret_data = json.loads(response['SecretString'])
            return secret_data['client_id'], secret_data['client_secret']
        except Exception as e:
            logger.error(f"❌ Failed to retrieve secrets from Secrets Manager: {str(e)}")
            raise
    else:
        logger.info("🔐 Using CrowdStrike credentials from environment variables...")
        return CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET

class ECRAutoOnboardingService:
    """Production ECR auto-onboarding service with dynamic IAM role discovery"""

    def __init__(self):
        self.token = None
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')

        logger.info(f"🚀 Initializing ECR Auto-Onboarding Service (Session: {self.session_id})")
        logger.info(f"Configuration:")
        logger.info(f"  Base URL: {CROWDSTRIKE_BASE_URL}")
        logger.info(f"  Credentials Source: {'Secrets Manager' if USE_SECRETS_MANAGER else 'Environment Variables'}")
        logger.info(f"  Dry Run Mode: {DRY_RUN_MODE}")
        logger.info(f"  Cleanup Enabled: {ENABLE_CLEANUP}")
        logger.info(f"  Cleanup Offline Days: {CLEANUP_OFFLINE_DAYS}")
        logger.info(f"  Notifications: {'Enabled' if SNS_TOPIC_ARN else 'Disabled'}")

    def authenticate(self) -> bool:
        """Authenticate with CrowdStrike API"""
        logger.info("🔑 Authenticating with CrowdStrike API...")

        try:
            client_id, client_secret = get_crowdstrike_credentials()

            url = f"{CROWDSTRIKE_BASE_URL}/oauth2/token"
            data = {
                "client_id": client_id,
                "client_secret": client_secret
            }

            response = requests.post(url, data=data, timeout=30)
            response.raise_for_status()

            self.token = response.json()["access_token"]
            logger.info("✅ Authentication successful")
            return True

        except Exception as e:
            logger.error(f"❌ Authentication failed: {str(e)}")
            return False

    def discover_ecr_registries(self) -> List[Dict]:
        """Discover ECR registries from CrowdStrike Asset Explorer"""
        logger.info("🔍 Discovering ECR registries from Asset Explorer...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

        try:
            # Query for ECR repository resource IDs
            query_url = f"{CROWDSTRIKE_BASE_URL}/cloud-security-assets/queries/resources/v1"
            params = {
                'filter': 'resource_type:"AWS::ECR::Repository"+cloud_provider:"aws"',
                'limit': 1000
            }

            response = requests.get(query_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            resource_ids = response.json()["resources"]

            if not resource_ids:
                logger.info("   No ECR repositories found in Asset Explorer")
                return []

            logger.info(f"   Found {len(resource_ids)} ECR repositories")

            # Get detailed resource information in batches
            details_url = f"{CROWDSTRIKE_BASE_URL}/cloud-security-assets/entities/resources/v1"
            all_resources = []

            batch_size = 100
            for i in range(0, len(resource_ids), batch_size):
                batch_ids = resource_ids[i:i + batch_size]
                details_params = {"ids": batch_ids}

                response = requests.get(details_url, headers=headers, params=details_params, timeout=30)
                response.raise_for_status()
                batch_resources = response.json()["resources"]
                all_resources.extend(batch_resources)

            # Group repositories by registry (account_id + region)
            registries_map = defaultdict(lambda: {
                'repositories': [],
                'account_id': None,
                'region': None,
                'registry_url': None
            })

            for resource in all_resources:
                account_id = resource.get('account_id')
                region = resource.get('region')
                repository_name = resource.get('resource_id')

                if account_id and region:
                    registry_key = f"{account_id}_{region}"
                    registry_url = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

                    registries_map[registry_key]['account_id'] = account_id
                    registries_map[registry_key]['region'] = region
                    registries_map[registry_key]['registry_url'] = registry_url
                    registries_map[registry_key]['repositories'].append(repository_name)

            registry_list = list(registries_map.values())
            logger.info(f"✅ Converted to {len(registry_list)} unique ECR registries")

            for registry in registry_list:
                logger.info(f"   📦 {registry['registry_url']} ({len(registry['repositories'])} repos)")

            return registry_list

        except Exception as e:
            logger.error(f"❌ ECR registry discovery failed: {str(e)}")
            return []

    def get_cspm_account_credentials(self, account_ids: List[str]) -> Dict[str, Dict]:
        """Get IAM role and external ID for each account from CSPM registration"""
        logger.info(f"🔑 Discovering IAM credentials for {len(account_ids)} accounts...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        credentials_map = {}

        try:
            # Query CSPM registration data
            url = f"{CROWDSTRIKE_BASE_URL}/cloud-security-registration-aws/entities/account/v1"
            params = {"ids": account_ids}

            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            result = response.json()

            resources = result.get('resources', [])
            for account_data in resources:
                account_id = account_data.get('account_id')
                resource_metadata = account_data.get('resource_metadata', {})

                iam_role_arn = resource_metadata.get('iam_role_arn')
                external_id = resource_metadata.get('external_id')
                account_name = account_data.get('account_name', 'Unknown')

                if account_id and iam_role_arn and external_id:
                    credentials_map[account_id] = {
                        'iam_role_arn': iam_role_arn,
                        'external_id': external_id,
                        'account_name': account_name
                    }
                    logger.info(f"   ✅ {account_id} ({account_name})")
                    logger.info(f"      Role: {iam_role_arn}")
                    logger.info(f"      External ID: {external_id}")
                else:
                    logger.warning(f"   ⚠️  {account_id}: Missing credentials in CSPM registration")

            logger.info(f"✅ Found credentials for {len(credentials_map)} accounts")
            return credentials_map

        except Exception as e:
            logger.error(f"❌ Failed to get CSPM credentials: {str(e)}")
            return {}

    def enhance_registries_with_credentials(self, registries: List[Dict], credentials_map: Dict[str, Dict]) -> List[Dict]:
        """Add IAM credentials to registry data"""
        logger.info("🔗 Mapping registries to IAM credentials...")

        enhanced_registries = []
        missing_credentials = []

        for registry in registries:
            account_id = registry['account_id']

            if account_id in credentials_map:
                creds = credentials_map[account_id]
                enhanced_registry = {
                    **registry,  # Keep original registry data
                    'iam_role_arn': creds['iam_role_arn'],
                    'external_id': creds['external_id'],
                    'account_name': creds['account_name']
                }
                enhanced_registries.append(enhanced_registry)
            else:
                missing_credentials.append(registry['registry_url'])

        if missing_credentials:
            logger.warning(f"⚠️  {len(missing_credentials)} registries missing CSPM credentials:")
            for url in missing_credentials:
                logger.warning(f"   - {url}")

        logger.info(f"✅ Enhanced {len(enhanced_registries)} registries with credentials")
        return enhanced_registries

    def get_existing_registrations(self) -> Set[str]:
        """Get existing ECR registrations from Container Security"""
        logger.info("📋 Checking existing ECR registrations...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

        try:
            # Query for registry IDs
            query_url = f"{CROWDSTRIKE_BASE_URL}/container-security/queries/registries/v1"
            response = requests.get(query_url, headers=headers, timeout=30)
            response.raise_for_status()
            registry_ids = response.json()["resources"]

            if not registry_ids:
                logger.info("   No existing registrations found")
                return set()

            # Get detailed registry information
            details_url = f"{CROWDSTRIKE_BASE_URL}/container-security/entities/registries/v1"
            details_params = {"ids": registry_ids}

            response = requests.get(details_url, headers=headers, params=details_params, timeout=30)
            response.raise_for_status()
            registries = response.json()["resources"]

            # Extract ECR registry URLs
            existing_urls = set()
            for registry in registries:
                if registry.get('type') == 'ecr':
                    url = registry.get('url')
                    if url:
                        existing_urls.add(url)
                        logger.info(f"   ✅ {url}")

            logger.info(f"✅ Found {len(existing_urls)} existing ECR registrations")
            return existing_urls

        except Exception as e:
            logger.error(f"❌ Failed to get existing registrations: {str(e)}")
            return set()

    def get_detailed_registrations(self) -> List[Dict]:
        """Get detailed information about existing ECR registrations including status"""
        logger.info("📋 Getting detailed ECR registration information...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

        try:
            # Query for registry IDs
            query_url = f"{CROWDSTRIKE_BASE_URL}/container-security/queries/registries/v1"
            response = requests.get(query_url, headers=headers, timeout=30)
            response.raise_for_status()
            registry_ids = response.json()["resources"]

            if not registry_ids:
                logger.info("   No existing registrations found")
                return []

            # Get detailed registry information
            details_url = f"{CROWDSTRIKE_BASE_URL}/container-security/entities/registries/v1"
            details_params = {"ids": registry_ids}

            response = requests.get(details_url, headers=headers, params=details_params, timeout=30)
            response.raise_for_status()
            registries = response.json()["resources"]

            # Filter ECR registries and extract relevant information
            ecr_registrations = []
            for registry in registries:
                if registry.get('type') == 'ecr':
                    url = registry.get('url')
                    if url:
                        # Extract account ID from registry URL
                        account_id = url.split('.')[0].split('//')[1] if '//' in url else None

                        registration_info = {
                            'id': registry.get('id'),
                            'url': url,
                            'account_id': account_id,
                            'state': registry.get('state', 'unknown'),
                            'last_activity': registry.get('last_activity'),
                            'created_at': registry.get('created_at'),
                            'updated_at': registry.get('updated_at')
                        }
                        ecr_registrations.append(registration_info)
                        logger.info(f"   📦 {url} (State: {registration_info['state']}, ID: {registration_info['id']})")

            logger.info(f"✅ Found {len(ecr_registrations)} detailed ECR registrations")
            return ecr_registrations

        except Exception as e:
            logger.error(f"❌ Failed to get detailed registrations: {str(e)}")
            return []

    def identify_registrations_for_cleanup(self, detailed_registrations: List[Dict], cspm_accounts: Dict[str, Dict]) -> List[Dict]:
        """Identify ECR registrations that should be cleaned up based on business rules"""
        logger.info("🔍 Analyzing ECR registrations for cleanup...")

        cleanup_candidates = []
        keep_registrations = []
        ignore_registrations = []

        cutoff_date = datetime.now() - timedelta(days=CLEANUP_OFFLINE_DAYS)

        for registration in detailed_registrations:
            account_id = registration['account_id']
            url = registration['url']
            state = registration['state']
            last_activity = registration.get('last_activity')

            # Rule 1: Account not in CSPM + ECR in Image Assessment = IGNORE (manual registration)
            if account_id not in cspm_accounts:
                ignore_registrations.append(registration)
                logger.info(f"   🔒 IGNORE: {url} (Account {account_id} not in CSPM - manual registration)")
                continue

            # Account is in CSPM, check state and activity
            if state == 'offline' and last_activity:
                try:
                    # Parse last activity date (assuming ISO format)
                    activity_date = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))

                    # Rule 3: Account in CSPM + ECR offline 7+ days = DELETE
                    if activity_date < cutoff_date:
                        cleanup_candidates.append(registration)
                        logger.info(f"   🗑️  DELETE: {url} (Offline since {last_activity}, > {CLEANUP_OFFLINE_DAYS} days)")
                    else:
                        keep_registrations.append(registration)
                        logger.info(f"   ✅ KEEP: {url} (Offline but < {CLEANUP_OFFLINE_DAYS} days)")

                except Exception as e:
                    # If we can't parse the date, keep it safe
                    keep_registrations.append(registration)
                    logger.warning(f"   ⚠️  KEEP: {url} (Could not parse last_activity date: {str(e)})")
            else:
                # Rule 4: Otherwise = KEEP (active or unknown state)
                keep_registrations.append(registration)
                logger.info(f"   ✅ KEEP: {url} (State: {state})")

        logger.info(f"📊 CLEANUP ANALYSIS:")
        logger.info(f"   Cleanup candidates: {len(cleanup_candidates)}")
        logger.info(f"   Keep registrations: {len(keep_registrations)}")
        logger.info(f"   Ignore (manual): {len(ignore_registrations)}")

        return cleanup_candidates

    def determine_cleanup_reason(self, registration: Dict, cspm_accounts: Dict[str, Dict] = None) -> str:
        """Determine the reason why a registry is being cleaned up"""
        account_id = registration.get('account_id', 'unknown')
        last_activity = registration.get('last_activity', 'unknown')
        state = registration.get('state', 'unknown')

        if cspm_accounts and account_id not in cspm_accounts:
            return "Account not in CSPM (manual registration preserved)"

        if last_activity and last_activity != 'unknown':
            try:
                cutoff_date = datetime.now() - timedelta(days=CLEANUP_OFFLINE_DAYS)
                activity_date = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                if activity_date < cutoff_date:
                    days_offline = (datetime.now().replace(tzinfo=activity_date.tzinfo) - activity_date).days
                    return f"Registry offline for {days_offline} days (>{CLEANUP_OFFLINE_DAYS} day threshold)"
            except:
                pass

        return f"Registry state: {state}, last activity: {last_activity}"

    def delete_ecr_registry(self, registration: Dict, cleanup_reason: str = None) -> Dict:
        """Delete ECR registry from Container Security"""
        registry_id = registration['id']
        registry_url = registration['url']

        logger.info(f"🗑️  {'[DRY RUN] ' if DRY_RUN_MODE else ''}Deleting registry {registry_url}")
        logger.info(f"   Registry ID: {registry_id}")
        logger.info(f"   Account: {registration['account_id']}")
        logger.info(f"   State: {registration['state']}")
        if cleanup_reason:
            logger.info(f"   Reason: {cleanup_reason}")

        if DRY_RUN_MODE:
            logger.info("   🧪 Dry run mode - deletion skipped")
            return {
                'success': True,
                'registry': registration,
                'cleanup_reason': cleanup_reason or 'Dry run mode',
                'error': None
            }

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }

        try:
            url = f"{CROWDSTRIKE_BASE_URL}/container-security/entities/registries/v1"
            params = {"ids": [registry_id]}

            response = requests.delete(url, headers=headers, params=params, timeout=30)

            if response.status_code in [200, 204]:
                logger.info(f"   ✅ Registry deleted successfully!")
                return {
                    'success': True,
                    'registry': registration,
                    'cleanup_reason': cleanup_reason or 'Manual cleanup',
                    'error': None
                }
            else:
                try:
                    error_response = response.json()
                    errors = error_response.get('errors', [])
                    error_message = errors[0].get('message', 'Unknown error') if errors else f"HTTP {response.status_code}"
                except:
                    error_message = f"HTTP {response.status_code}"
                logger.error(f"   ❌ Deletion failed: {error_message}")
                return {
                    'success': False,
                    'registry': registration,
                    'cleanup_reason': cleanup_reason or 'Manual cleanup',
                    'error': error_message
                }

        except Exception as e:
            error_message = str(e)
            logger.error(f"   ❌ Deletion failed: {error_message}")
            return {
                'success': False,
                'registry': registration,
                'cleanup_reason': cleanup_reason or 'Manual cleanup',
                'error': error_message
            }

    def register_ecr_registry(self, registry: Dict) -> Dict:
        """Register ECR registry using discovered credentials"""
        registry_url = registry['registry_url']
        iam_role_arn = registry['iam_role_arn']
        external_id = registry['external_id']
        account_name = registry['account_name']

        logger.info(f"📝 {'[DRY RUN] ' if DRY_RUN_MODE else ''}Registering {registry_url}")
        logger.info(f"   Account: {account_name}")
        logger.info(f"   IAM Role: {iam_role_arn}")
        logger.info(f"   Repositories: {len(registry['repositories'])}")

        if DRY_RUN_MODE:
            logger.info("   🧪 Dry run mode - registration skipped")
            return {
                'success': True,
                'registry': registry,
                'registry_id': 'dry-run-id',
                'error': None
            }

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        payload = {
            "type": "ecr",
            "url": registry_url,
            "user_defined_alias": f"Auto-{account_name}-{registry['region']}",
            "credential": {
                "details": {
                    "aws_iam_role": iam_role_arn,
                    "aws_external_id": external_id
                }
            }
        }

        try:
            url = f"{CROWDSTRIKE_BASE_URL}/container-security/entities/registries/v1"
            response = requests.post(url, headers=headers, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                result = response.json()
                registry_data = result.get('resources', {})
                registry_id = registry_data.get('id', 'unknown')
                logger.info(f"   ✅ Registration successful! Registry ID: {registry_id}")
                return {
                    'success': True,
                    'registry': registry,
                    'registry_id': registry_id,
                    'error': None
                }
            else:
                error_response = response.json()
                errors = error_response.get('errors', [])
                error_message = errors[0].get('message', 'Unknown error') if errors else f"HTTP {response.status_code}"
                logger.error(f"   ❌ Registration failed: {error_message}")
                return {
                    'success': False,
                    'registry': registry,
                    'registry_id': None,
                    'error': error_message
                }

        except Exception as e:
            error_message = str(e)
            logger.error(f"   ❌ Registration failed: {error_message}")
            return {
                'success': False,
                'registry': registry,
                'registry_id': None,
                'error': error_message
            }

    def send_notification(self, message: str):
        """Send notification via SNS and/or Slack"""
        if SNS_TOPIC_ARN and sns:
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="ECR Auto-Onboarding Results",
                    Message=message
                )
                logger.info("📧 SNS notification sent")
            except Exception as e:
                logger.error(f"❌ Failed to send SNS notification: {str(e)}")

        if SLACK_WEBHOOK_PARAMETER and ssm:
            try:
                # Get Slack webhook URL from SSM
                response = ssm.get_parameter(Name=SLACK_WEBHOOK_PARAMETER, WithDecryption=True)
                webhook_url = response['Parameter']['Value']

                slack_message = {
                    "text": f"ECR Auto-Onboarding Results",
                    "attachments": [{
                        "color": "good",
                        "text": message
                    }]
                }

                requests.post(webhook_url, json=slack_message, timeout=10)
                logger.info("📱 Slack notification sent")
            except Exception as e:
                logger.error(f"❌ Failed to send Slack notification: {str(e)}")

    def generate_html_notification(self, result: Dict) -> str:
        """Generate rich HTML email notification with detailed registry information"""

        # Extract detailed results
        newly_registered = result.get('newly_registered', [])
        deleted_registries = result.get('deleted_registries', [])
        failed_registrations = result.get('failed_registrations_list', [])
        failed_deletions = result.get('failed_deletions_list', [])

        # Calculate totals
        total_new = len(newly_registered)
        total_deleted = len(deleted_registries)
        total_failed = len(failed_registrations) + len(failed_deletions)

        # Determine email color theme based on results
        header_color = "#28a745" if total_failed == 0 else "#dc3545" if total_failed > 0 else "#007bff"

        # Format timestamp
        end_time = datetime.fromisoformat(result.get('end_time', datetime.now().isoformat()))
        formatted_time = end_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build sections
        new_registrations_section = ""
        if newly_registered:
            new_registrations_section = self._build_new_registrations_section(newly_registered)

        deleted_registries_section = ""
        if deleted_registries:
            deleted_registries_section = self._build_deleted_registries_section(deleted_registries)

        failed_operations_section = ""
        if failed_registrations or failed_deletions:
            failed_operations_section = self._build_failed_operations_section(failed_registrations, failed_deletions)

        no_changes_section = ""
        if total_new == 0 and total_deleted == 0 and total_failed == 0:
            no_changes_section = f"""
            <div class="section">
                <div class="section-title">✅ No Changes Required</div>
                <p>All ECR registries are up-to-date. {result.get('existing_registrations', 0)} registries already onboarded.</p>
            </div>
            """

        # Calculate next run time (approximate)
        next_run = end_time + timedelta(hours=6)  # Next scheduled run (6AM, 12PM, 6PM pattern)

        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, {header_color} 0%, {header_color}CC 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ padding: 20px; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .metric {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; flex: 1; min-width: 120px; }}
        .metric.success {{ border-left: 4px solid #28a745; }}
        .metric.warning {{ border-left: 4px solid #ffc107; }}
        .metric.error {{ border-left: 4px solid #dc3545; }}
        .metric.info {{ border-left: 4px solid #17a2b8; }}
        .section {{ margin: 25px 0; }}
        .section-title {{ font-size: 18px; font-weight: bold; margin-bottom: 15px; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }}
        td {{ padding: 12px; border-bottom: 1px solid #e9ecef; vertical-align: top; }}
        .status {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; display: inline-block; }}
        .status.success {{ background: #d4edda; color: #155724; }}
        .status.error {{ background: #f8d7da; color: #721c24; }}
        .status.warning {{ background: #fff3cd; color: #856404; }}
        .reason {{ font-style: italic; color: #6c757d; font-size: 11px; }}
        .footer {{ background: #f8f9fa; padding: 15px; text-align: center; color: #6c757d; border-radius: 0 0 8px 8px; font-size: 12px; }}
        .repos {{ font-size: 11px; color: #6c757d; max-height: 80px; overflow-y: auto; }}
        .repo-item {{ margin-bottom: 2px; }}
        .dry-run-notice {{ background: #fff3cd; color: #856404; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #ffc107; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚢 ECR Auto-Onboarding Report</h1>
            <p><strong>Session:</strong> {result.get('session_id', 'unknown')} | <strong>Duration:</strong> {result.get('execution_time', 0):.1f}s | <strong>{formatted_time}</strong></p>
            {'<div class="dry-run-notice">🧪 <strong>DRY RUN MODE</strong> - No actual changes were made</div>' if result.get('dry_run_mode', False) else ''}
        </div>

        <div class="content">
            <div class="summary">
                <div class="metric success">
                    <div style="font-size: 24px; font-weight: bold;">{total_new}</div>
                    <div>New Registrations</div>
                </div>
                <div class="metric error">
                    <div style="font-size: 24px; font-weight: bold;">{total_deleted}</div>
                    <div>Deleted Registrations</div>
                </div>
                <div class="metric warning">
                    <div style="font-size: 24px; font-weight: bold;">{total_failed}</div>
                    <div>Failed Operations</div>
                </div>
                <div class="metric info">
                    <div style="font-size: 24px; font-weight: bold;">{result.get('discovered_registries', 0)}</div>
                    <div>Total Discovered</div>
                </div>
            </div>

            {new_registrations_section}
            {deleted_registries_section}
            {failed_operations_section}
            {no_changes_section}
        </div>

        <div class="footer">
            <p>🤖 Generated by ECR Auto-Onboarding Lambda | Next scheduled run: ~{next_run.strftime("%H:%M UTC")}</p>
        </div>
    </div>
</body>
</html>"""
        return html_template

    def _build_new_registrations_section(self, newly_registered: List[Dict]) -> str:
        """Build HTML section for newly registered ECR repositories"""
        if not newly_registered:
            return ""

        rows = ""
        for reg_result in newly_registered:
            registry = reg_result.get('registry', {})
            account_name = registry.get('account_name', 'Unknown Account')
            account_id = registry.get('account_id', 'unknown')
            registry_url = registry.get('registry_url', 'unknown')
            iam_role = registry.get('iam_role_arn', 'unknown')
            repositories = registry.get('repositories', [])

            # Format repositories list
            repo_list = ""
            for i, repo in enumerate(repositories[:5]):  # Show first 5
                repo_list += f'<div class="repo-item">• {repo.get("repositoryName", "unknown")}</div>'
            if len(repositories) > 5:
                repo_list += f'<div class="repo-item"><em>... and {len(repositories) - 5} more</em></div>'

            rows += f"""
            <tr>
                <td><strong>{account_name}</strong><br><small>{account_id}</small></td>
                <td><small>{registry_url}</small></td>
                <td class="repos">{repo_list}</td>
                <td><small>{iam_role.split('/')[-1] if '/' in iam_role else iam_role}</small></td>
                <td><span class="status success">✅ Registered</span></td>
            </tr>"""

        return f"""
        <div class="section">
            <div class="section-title">🆕 Newly Registered ECR Repositories</div>
            <table>
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Registry URL</th>
                        <th>Repositories</th>
                        <th>IAM Role</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _build_deleted_registries_section(self, deleted_registries: List[Dict]) -> str:
        """Build HTML section for deleted ECR registrations"""
        if not deleted_registries:
            return ""

        rows = ""
        for del_result in deleted_registries:
            registry = del_result.get('registry', {})
            account_id = registry.get('account_id', 'unknown')
            registry_url = registry.get('url', 'unknown')
            last_activity = registry.get('last_activity', 'unknown')
            cleanup_reason = del_result.get('cleanup_reason', 'Manual cleanup')

            rows += f"""
            <tr>
                <td>{account_id}</td>
                <td><small>{registry_url}</small></td>
                <td>{last_activity}</td>
                <td class="reason">{cleanup_reason}</td>
                <td><span class="status error">🗑️ Deleted</span></td>
            </tr>"""

        return f"""
        <div class="section">
            <div class="section-title">🗑️ Cleaned Up ECR Registrations</div>
            <table>
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Registry URL</th>
                        <th>Last Activity</th>
                        <th>Cleanup Reason</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _build_failed_operations_section(self, failed_registrations: List[Dict], failed_deletions: List[Dict]) -> str:
        """Build HTML section for failed operations"""
        if not failed_registrations and not failed_deletions:
            return ""

        rows = ""

        # Add failed registrations
        for fail_result in failed_registrations:
            registry = fail_result.get('registry', {})
            account_name = registry.get('account_name', 'Unknown Account')
            registry_url = registry.get('registry_url', 'unknown')
            error_message = fail_result.get('error', 'Unknown error')

            rows += f"""
            <tr>
                <td>{account_name}</td>
                <td><small>{registry_url}</small></td>
                <td>Registration</td>
                <td class="reason">{error_message}</td>
                <td><span class="status error">❌ Failed</span></td>
            </tr>"""

        # Add failed deletions
        for fail_result in failed_deletions:
            registry = fail_result.get('registry', {})
            account_id = registry.get('account_id', 'unknown')
            registry_url = registry.get('url', 'unknown')
            error_message = fail_result.get('error', 'Unknown error')

            rows += f"""
            <tr>
                <td>{account_id}</td>
                <td><small>{registry_url}</small></td>
                <td>Cleanup</td>
                <td class="reason">{error_message}</td>
                <td><span class="status error">❌ Failed</span></td>
            </tr>"""

        return f"""
        <div class="section">
            <div class="section-title">❌ Failed Operations</div>
            <table>
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Registry URL</th>
                        <th>Operation</th>
                        <th>Error</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def send_enhanced_notification(self, result: Dict):
        """Send enhanced HTML notification with detailed registry information"""

        # Generate HTML and text versions
        html_message = self.generate_html_notification(result)

        # Generate text fallback (enhanced version of current)
        text_message = self._generate_enhanced_text_notification(result)

        # Send via SNS with HTML support
        if SNS_TOPIC_ARN and sns:
            try:
                # Count totals for subject line
                total_new = len(result.get('newly_registered', []))
                total_deleted = len(result.get('deleted_registries', []))
                total_failed = len(result.get('failed_registrations_list', [])) + len(result.get('failed_deletions_list', []))

                subject = f"ECR Auto-Onboarding: {total_new} new, {total_deleted} deleted"
                if total_failed > 0:
                    subject += f", {total_failed} failed"
                if result.get('dry_run_mode', False):
                    subject += " (DRY RUN)"

                # Send HTML email
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=subject,
                    Message=html_message,
                    MessageAttributes={
                        'AWS.SNS.SMS.SenderID': {
                            'DataType': 'String',
                            'StringValue': 'ECR-AutoOnboard'
                        }
                    }
                )
                logger.info("📧 Enhanced HTML notification sent via SNS")
            except Exception as e:
                logger.error(f"❌ Failed to send enhanced SNS notification: {str(e)}")
                # Fallback to text notification
                try:
                    sns.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Subject="ECR Auto-Onboarding Results (Text Fallback)",
                        Message=text_message
                    )
                    logger.info("📧 Fallback text notification sent")
                except Exception as fallback_e:
                    logger.error(f"❌ Fallback notification also failed: {str(fallback_e)}")

        # Send Slack notification (enhanced)
        if SLACK_WEBHOOK_PARAMETER and ssm:
            try:
                self._send_enhanced_slack_notification(result)
            except Exception as e:
                logger.error(f"❌ Failed to send enhanced Slack notification: {str(e)}")

    def _generate_enhanced_text_notification(self, result: Dict) -> str:
        """Generate enhanced plain text notification with registry details"""

        newly_registered = result.get('newly_registered', [])
        deleted_registries = result.get('deleted_registries', [])
        failed_registrations = result.get('failed_registrations_list', [])
        failed_deletions = result.get('failed_deletions_list', [])

        lines = [
            f"ECR Auto-Onboarding & Cleanup Results (Session: {result.get('session_id', 'unknown')})",
            "=" * 60,
            ""
        ]

        if result.get('dry_run_mode', False):
            lines.extend([
                "🧪 DRY RUN MODE - No actual changes were made",
                ""
            ])

        # Summary
        lines.extend([
            "📊 SUMMARY:",
            f"   Discovered: {result.get('discovered_registries', 0)} registries",
            f"   Already registered: {result.get('existing_registrations', 0)} registries",
            f"   New registrations: {len(newly_registered)} registries",
            f"   Failed registrations: {len(failed_registrations)} registries",
        ])

        if result.get('cleanup_enabled', False):
            lines.extend([
                f"   Deleted registrations: {len(deleted_registries)} registries",
                f"   Failed deletions: {len(failed_deletions)} registries",
            ])

        lines.extend([
            f"   Execution time: {result.get('execution_time', 0):.2f}s",
            ""
        ])

        # Detailed sections
        if newly_registered:
            lines.extend([
                "🆕 NEWLY REGISTERED:",
                "-" * 30
            ])
            for reg_result in newly_registered:
                registry = reg_result.get('registry', {})
                account_name = registry.get('account_name', 'Unknown')
                registry_url = registry.get('registry_url', 'unknown')
                repo_count = len(registry.get('repositories', []))
                lines.append(f"   ✅ {account_name}: {registry_url} ({repo_count} repos)")
            lines.append("")

        if deleted_registries:
            lines.extend([
                "🗑️  DELETED REGISTRATIONS:",
                "-" * 30
            ])
            for del_result in deleted_registries:
                registry = del_result.get('registry', {})
                registry_url = registry.get('url', 'unknown')
                reason = del_result.get('cleanup_reason', 'Manual cleanup')
                lines.append(f"   🗑️  {registry_url}")
                lines.append(f"       Reason: {reason}")
            lines.append("")

        if failed_registrations or failed_deletions:
            lines.extend([
                "❌ FAILED OPERATIONS:",
                "-" * 30
            ])
            for fail_result in failed_registrations:
                registry = fail_result.get('registry', {})
                registry_url = registry.get('registry_url', 'unknown')
                error = fail_result.get('error', 'Unknown error')
                lines.append(f"   ❌ Registration failed: {registry_url}")
                lines.append(f"       Error: {error}")

            for fail_result in failed_deletions:
                registry = fail_result.get('registry', {})
                registry_url = registry.get('url', 'unknown')
                error = fail_result.get('error', 'Unknown error')
                lines.append(f"   ❌ Deletion failed: {registry_url}")
                lines.append(f"       Error: {error}")
            lines.append("")

        return "\\n".join(lines)

    def _send_enhanced_slack_notification(self, result: Dict):
        """Send enhanced Slack notification with registry details"""

        # Get Slack webhook URL from SSM
        response = ssm.get_parameter(Name=SLACK_WEBHOOK_PARAMETER, WithDecryption=True)
        webhook_url = response['Parameter']['Value']

        # Count results
        total_new = len(result.get('newly_registered', []))
        total_deleted = len(result.get('deleted_registries', []))
        total_failed = len(result.get('failed_registrations_list', [])) + len(result.get('failed_deletions_list', []))

        # Determine color
        color = "good" if total_failed == 0 else "danger" if total_failed > 0 else "#439FE0"

        # Build attachment fields
        fields = [
            {
                "title": "New Registrations",
                "value": str(total_new),
                "short": True
            },
            {
                "title": "Deleted Registrations",
                "value": str(total_deleted),
                "short": True
            },
            {
                "title": "Failed Operations",
                "value": str(total_failed),
                "short": True
            },
            {
                "title": "Total Discovered",
                "value": str(result.get('discovered_registries', 0)),
                "short": True
            }
        ]

        # Add registry details if any
        details = []
        if total_new > 0:
            newly_registered = result.get('newly_registered', [])[:3]  # Show first 3
            for reg_result in newly_registered:
                registry = reg_result.get('registry', {})
                account_name = registry.get('account_name', 'Unknown')
                repo_count = len(registry.get('repositories', []))
                details.append(f"✅ {account_name} ({repo_count} repos)")
            if len(result.get('newly_registered', [])) > 3:
                details.append(f"... and {len(result.get('newly_registered', [])) - 3} more")

        if details:
            fields.append({
                "title": "Registry Details",
                "value": "\\n".join(details),
                "short": False
            })

        slack_message = {
            "text": f"ECR Auto-Onboarding Results {'(DRY RUN)' if result.get('dry_run_mode', False) else ''}",
            "attachments": [{
                "color": color,
                "fields": fields,
                "footer": f"Session: {result.get('session_id', 'unknown')} | Duration: {result.get('execution_time', 0):.1f}s",
                "ts": int(datetime.now().timestamp())
            }]
        }

        requests.post(webhook_url, json=slack_message, timeout=10)
        logger.info("📱 Enhanced Slack notification sent")

    def run_onboarding_workflow(self) -> Dict:
        """Execute the complete ECR auto-onboarding and cleanup workflow"""
        start_time = datetime.now()

        logger.info("🚀 Starting ECR Auto-Onboarding & Cleanup Workflow")
        logger.info("=" * 60)

        # Initialize result tracking
        result = {
            'session_id': self.session_id,
            'start_time': start_time.isoformat(),
            'discovered_registries': 0,
            'enhanced_registries': 0,
            'existing_registrations': 0,
            'new_registrations': 0,
            'failed_registrations': 0,
            'cleanup_enabled': ENABLE_CLEANUP,
            'cleanup_candidates': 0,
            'deleted_registrations': 0,
            'failed_deletions': 0,
            'dry_run_mode': DRY_RUN_MODE,
            'errors': [],

            # Enhanced detailed tracking
            'newly_registered': [],           # Full registry details
            'deleted_registries': [],         # Full deletion details with reasons
            'failed_registrations_list': [],  # Registry details + error messages
            'failed_deletions_list': []       # Registry details + error messages
        }

        try:
            # Step 1: Authenticate
            if not self.authenticate():
                result['errors'].append('Authentication failed')
                return result

            # Step 2: Discover ECR registries
            registries = self.discover_ecr_registries()
            result['discovered_registries'] = len(registries)

            if not registries:
                logger.info("✅ No ECR registries found - nothing to onboard")
                return result

            # Step 3: Get unique account IDs and their CSPM credentials
            account_ids = list(set(registry['account_id'] for registry in registries))
            credentials_map = self.get_cspm_account_credentials(account_ids)

            # Step 4: Enhance registries with credentials
            enhanced_registries = self.enhance_registries_with_credentials(registries, credentials_map)
            result['enhanced_registries'] = len(enhanced_registries)

            if not enhanced_registries:
                error = "No registries could be enhanced with CSPM credentials"
                logger.error(f"❌ {error}")
                result['errors'].append(error)
                return result

            # Step 5: Check existing registrations
            existing_registrations = self.get_existing_registrations()
            result['existing_registrations'] = len(existing_registrations)

            # Step 6: Calculate what needs registration
            to_register = [reg for reg in enhanced_registries if reg['registry_url'] not in existing_registrations]

            logger.info("📊 REGISTRATION SUMMARY:")
            logger.info("-" * 30)
            logger.info(f"   Discovered registries: {result['discovered_registries']}")
            logger.info(f"   Enhanced with credentials: {result['enhanced_registries']}")
            logger.info(f"   Already registered: {result['existing_registrations']}")
            logger.info(f"   Need registration: {len(to_register)}")

            if not to_register:
                logger.info("✅ All ECR registries are already onboarded!")
                return result

            # Step 7: Register missing registries
            logger.info(f"🔧 {'DRY RUN MODE' if DRY_RUN_MODE else 'LIVE MODE'} - Processing {len(to_register)} registrations:")

            for registry in to_register:
                reg_result = self.register_ecr_registry(registry)
                if reg_result['success']:
                    result['new_registrations'] += 1
                    result['newly_registered'].append(reg_result)
                else:
                    result['failed_registrations'] += 1
                    result['failed_registrations_list'].append(reg_result)

            # Step 8: ECR Cleanup (if enabled)
            if ENABLE_CLEANUP:
                logger.info("🧹 Starting ECR Registry Cleanup Process...")

                # Get detailed registration information for cleanup analysis
                detailed_registrations = self.get_detailed_registrations()

                if detailed_registrations:
                    # Identify registrations for cleanup using CSPM accounts
                    cleanup_candidates = self.identify_registrations_for_cleanup(detailed_registrations, credentials_map)
                    result['cleanup_candidates'] = len(cleanup_candidates)

                    if cleanup_candidates:
                        logger.info(f"🗑️  {'DRY RUN MODE' if DRY_RUN_MODE else 'LIVE MODE'} - Processing {len(cleanup_candidates)} cleanup candidates:")

                        for registration in cleanup_candidates:
                            cleanup_reason = self.determine_cleanup_reason(registration, credentials_map)
                            del_result = self.delete_ecr_registry(registration, cleanup_reason)
                            if del_result['success']:
                                result['deleted_registrations'] += 1
                                result['deleted_registries'].append(del_result)
                            else:
                                result['failed_deletions'] += 1
                                result['failed_deletions_list'].append(del_result)
                    else:
                        logger.info("✅ No registrations require cleanup")
                else:
                    logger.info("⚠️  Could not get detailed registration information for cleanup")
            else:
                logger.info("🚫 ECR cleanup is disabled")

            # Calculate execution time
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            result['end_time'] = end_time.isoformat()
            result['execution_time'] = execution_time

            logger.info("🎉 ECR Auto-Onboarding & Cleanup Complete!")
            logger.info(f"   New registrations: {result['new_registrations']}")
            logger.info(f"   Failed registrations: {result['failed_registrations']}")
            if ENABLE_CLEANUP:
                logger.info(f"   Deleted registrations: {result['deleted_registrations']}")
                logger.info(f"   Failed deletions: {result['failed_deletions']}")
            logger.info(f"   Execution time: {execution_time:.2f}s")

            # Send notification
            notification_needed = (result['new_registrations'] > 0 or
                                 result['failed_registrations'] > 0 or
                                 (ENABLE_CLEANUP and (result['deleted_registrations'] > 0 or result['failed_deletions'] > 0)))

            if notification_needed:
                cleanup_section = ""
                if ENABLE_CLEANUP:
                    cleanup_section = f"""
Cleanup enabled: {ENABLE_CLEANUP}
Cleanup candidates: {result['cleanup_candidates']} registries
Deleted registrations: {result['deleted_registrations']} registries
Failed deletions: {result['failed_deletions']} registries"""

                message = f"""ECR Auto-Onboarding & Cleanup Results (Session: {self.session_id})

Discovered: {result['discovered_registries']} registries
Enhanced: {result['enhanced_registries']} registries
Already registered: {result['existing_registrations']} registries
New registrations: {result['new_registrations']} registries
Failed registrations: {result['failed_registrations']} registries{cleanup_section}
Execution time: {execution_time:.2f}s
Dry run mode: {DRY_RUN_MODE}"""

                self.send_enhanced_notification(result)

            return result

        except Exception as e:
            logger.error(f"❌ Workflow failed: {str(e)}")
            result['errors'].append(str(e))
            return result


def lambda_handler(event, context):
    """AWS Lambda handler function"""
    service = ECRAutoOnboardingService()

    logger.info(f"Lambda invocation - Event: {json.dumps(event)}")

    # Handle dry run override from event
    global DRY_RUN_MODE
    if event.get('dry_run') is True:
        DRY_RUN_MODE = True
        logger.info("🧪 Dry run mode enabled via event parameter")

    result = service.run_onboarding_workflow()

    # Return result for Lambda response
    return {
        'statusCode': 200 if not result.get('errors') else 500,
        'body': json.dumps(result, indent=2)
    }


if __name__ == "__main__":
    # For local testing
    import sys

    # Mock environment variables for local testing
    if not os.environ.get('CROWDSTRIKE_CLIENT_ID'):
        os.environ['CROWDSTRIKE_CLIENT_ID'] = "4079b341af774edc93ddf128d883022a"
        os.environ['CROWDSTRIKE_CLIENT_SECRET'] = "XkNOUBdquRIEorac3j75sx4Wi0D8zFt6f1pJ2QL9"
        os.environ['DRY_RUN_MODE'] = "true"

    service = ECRAutoOnboardingService()
    result = service.run_onboarding_workflow()
    print(json.dumps(result, indent=2))