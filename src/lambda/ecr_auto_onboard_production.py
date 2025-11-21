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

    def delete_ecr_registry(self, registration: Dict) -> bool:
        """Delete ECR registry from Container Security"""
        registry_id = registration['id']
        registry_url = registration['url']

        logger.info(f"🗑️  {'[DRY RUN] ' if DRY_RUN_MODE else ''}Deleting registry {registry_url}")
        logger.info(f"   Registry ID: {registry_id}")
        logger.info(f"   Account: {registration['account_id']}")
        logger.info(f"   State: {registration['state']}")

        if DRY_RUN_MODE:
            logger.info("   🧪 Dry run mode - deletion skipped")
            return True

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
                return True
            else:
                try:
                    error_response = response.json()
                    errors = error_response.get('errors', [])
                    if errors:
                        logger.error(f"   ❌ Deletion failed: {errors[0].get('message', 'Unknown error')}")
                    else:
                        logger.error(f"   ❌ Deletion failed: HTTP {response.status_code}")
                except:
                    logger.error(f"   ❌ Deletion failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"   ❌ Deletion failed: {str(e)}")
            return False

    def register_ecr_registry(self, registry: Dict) -> bool:
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
            return True

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
                return True
            else:
                error_response = response.json()
                errors = error_response.get('errors', [])
                if errors:
                    logger.error(f"   ❌ Registration failed: {errors[0].get('message', 'Unknown error')}")
                else:
                    logger.error(f"   ❌ Registration failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"   ❌ Registration failed: {str(e)}")
            return False

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
            'errors': []
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
                if self.register_ecr_registry(registry):
                    result['new_registrations'] += 1
                else:
                    result['failed_registrations'] += 1

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
                            if self.delete_ecr_registry(registration):
                                result['deleted_registrations'] += 1
                            else:
                                result['failed_deletions'] += 1
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

                self.send_notification(message)

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