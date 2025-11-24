#!/usr/bin/env python3
"""
Manual ECR Auto-Onboarding Script

Pure local ECR auto-onboarding solution that uses only CrowdStrike APIs.
No AWS dependencies - just discovers and registers ECR repositories.

Usage:
    python3 ecr_auto_onboard_manual.py [OPTIONS]

Features:
- Dynamic IAM role discovery via CrowdStrike APIs
- Comprehensive logging and error handling
- Local configuration file support
- Dry-run mode for testing
- Multi-account support via Asset Explorer
- Pure CrowdStrike API solution (no AWS SDK dependencies)
"""

import argparse
import json
import logging
import os
import sys
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
import requests


class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log output"""

    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(verbose=False):
    """Setup colored logging for console output"""
    log_level = logging.DEBUG if verbose else logging.INFO

    # Create console handler with colored output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    # Create formatter
    formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(formatter)

    # Setup logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.handlers = []  # Clear existing handlers
    logger.addHandler(console_handler)

    return logger


def load_config(config_path: str = None) -> Dict:
    """Load configuration from YAML file with environment variable fallbacks"""

    # Default configuration (simplified - no AWS dependencies)
    config = {
        'crowdstrike': {
            'base_url': 'https://api.crowdstrike.com',
            'client_id': '',
            'client_secret': ''
        },
        'settings': {
            'dry_run_mode': False,
            'enable_cleanup': False  # Disabled for pure local solution
        }
    }

    # Try to load from config file
    if config_path:
        config_file = Path(config_path)
    else:
        # Look for config.yaml in script directory
        script_dir = Path(__file__).parent
        config_file = script_dir / 'config.yaml'

    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                # Merge file config into default config
                for section, values in file_config.items():
                    if section in config:
                        config[section].update(values)
            print(f"✅ Loaded configuration from: {config_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file {config_file}: {e}")
    else:
        print(f"ℹ️  No config file found at {config_file}, using environment variables and defaults")

    # Environment variable fallbacks
    env_mappings = {
        'CROWDSTRIKE_BASE_URL': ('crowdstrike', 'base_url'),
        'CROWDSTRIKE_CLIENT_ID': ('crowdstrike', 'client_id'),
        'CROWDSTRIKE_CLIENT_SECRET': ('crowdstrike', 'client_secret'),
        'DRY_RUN_MODE': ('settings', 'dry_run_mode')
    }

    for env_var, (section, key) in env_mappings.items():
        if env_value := os.environ.get(env_var):
            if key == 'dry_run_mode':
                config[section][key] = env_value.lower() == 'true'
            else:
                config[section][key] = env_value

    return config


class ECRAutoOnboardingService:
    """Pure local ECR auto-onboarding service using only CrowdStrike APIs"""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.token = None
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')

        self.logger.info(f"🚀 Initializing ECR Auto-Onboarding Service (Session: {self.session_id})")
        self.logger.info("Configuration:")
        self.logger.info(f"  Base URL: {config['crowdstrike']['base_url']}")
        self.logger.info(f"  Dry Run Mode: {config['settings']['dry_run_mode']}")
        self.logger.info("  Pure Local Mode: No AWS SDK dependencies")

    def authenticate(self) -> bool:
        """Authenticate with CrowdStrike API"""
        self.logger.info("🔑 Authenticating with CrowdStrike API...")

        try:
            url = f"{self.config['crowdstrike']['base_url']}/oauth2/token"
            data = {
                "client_id": self.config['crowdstrike']['client_id'],
                "client_secret": self.config['crowdstrike']['client_secret']
            }

            response = requests.post(url, data=data, timeout=30)
            response.raise_for_status()

            self.token = response.json()["access_token"]
            self.logger.info("✅ Authentication successful")
            return True

        except Exception as e:
            self.logger.error(f"❌ Authentication failed: {str(e)}")
            return False

    def discover_ecr_registries(self) -> List[Dict]:
        """Discover ECR registries from CrowdStrike Cloud Security Assets"""
        self.logger.info("🔍 Discovering ECR registries from Asset Explorer...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

        try:
            # Query for ECR repository resource IDs
            query_url = f"{self.config['crowdstrike']['base_url']}/cloud-security-assets/queries/resources/v1"
            params = {
                'filter': 'resource_type:"AWS::ECR::Repository"+cloud_provider:"aws"',
                'limit': 1000
            }

            response = requests.get(query_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            resource_ids = response.json()["resources"]

            if not resource_ids:
                self.logger.info("   No ECR repositories found in Asset Explorer")
                return []

            self.logger.info(f"   Found {len(resource_ids)} ECR repositories")

            # Get detailed resource information in batches
            details_url = f"{self.config['crowdstrike']['base_url']}/cloud-security-assets/entities/resources/v1"
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
            self.logger.info(f"✅ Converted to {len(registry_list)} unique ECR registries")

            for registry in registry_list:
                self.logger.info(f"   📦 {registry['registry_url']} ({len(registry['repositories'])} repos)")

            return registry_list

        except Exception as e:
            self.logger.error(f"❌ ECR registry discovery failed: {str(e)}")
            return []

    def get_cspm_credentials(self, account_ids: List[str]) -> Dict[str, Dict]:
        """Get IAM role and external ID for each account from CSPM registration"""
        self.logger.info(f"🔐 Discovering IAM credentials for {len(account_ids)} accounts...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        credentials_map = {}

        try:
            # Query CSPM registration data
            url = f"{self.config['crowdstrike']['base_url']}/cloud-security-registration-aws/entities/account/v1"
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
                    self.logger.info(f"   ✅ {account_id} ({account_name})")
                    self.logger.info(f"      Role: {iam_role_arn}")
                    self.logger.info(f"      External ID: {external_id}")
                else:
                    self.logger.warning(f"   ⚠️  {account_id}: Missing credentials in CSPM registration")

            self.logger.info(f"✅ Found credentials for {len(credentials_map)} accounts")
            return credentials_map

        except Exception as e:
            self.logger.error(f"❌ Failed to get CSPM credentials: {str(e)}")
            return {}

    def enhance_registries_with_credentials(self, registries: List[Dict], credentials_map: Dict[str, Dict]) -> List[Dict]:
        """Enhance discovered registries with CSPM IAM credentials"""
        self.logger.info("🔗 Enhancing registries with CSPM IAM credentials...")

        enhanced_registries = []
        for registry in registries:
            account_id = registry['account_id']
            if account_id in credentials_map:
                creds = credentials_map[account_id]
                enhanced_registry = {
                    **registry,
                    'account_name': creds['account_name'],
                    'iam_role_arn': creds['iam_role_arn'],
                    'external_id': creds['external_id']
                }
                enhanced_registries.append(enhanced_registry)
                self.logger.debug(f"   ✅ Enhanced {registry['registry_url']} with {creds['account_name']}")
            else:
                self.logger.warning(f"   ⚠️  No CSPM credentials found for account {account_id}")

        self.logger.info(f"✅ Enhanced {len(enhanced_registries)} registries with credentials")
        return enhanced_registries

    def get_existing_registrations(self) -> List[str]:
        """Get existing ECR registrations from Container Security"""
        self.logger.info("📋 Checking existing ECR registrations...")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

        try:
            # Query for registry IDs
            query_url = f"{self.config['crowdstrike']['base_url']}/container-security/queries/registries/v1"
            response = requests.get(query_url, headers=headers, timeout=30)
            response.raise_for_status()
            registry_ids = response.json()["resources"]

            if not registry_ids:
                self.logger.info("   No existing registrations found")
                return []

            # Get detailed registry information
            details_url = f"{self.config['crowdstrike']['base_url']}/container-security/entities/registries/v1"
            details_params = {"ids": registry_ids}

            response = requests.get(details_url, headers=headers, params=details_params, timeout=30)
            response.raise_for_status()
            registries = response.json()["resources"]

            # Extract ECR registry URLs
            existing_urls = []
            for registry in registries:
                if registry.get('type') == 'ecr':
                    url = registry.get('url')
                    if url:
                        existing_urls.append(url)
                        self.logger.info(f"   ✅ {url}")

            self.logger.info(f"✅ Found {len(existing_urls)} existing ECR registrations")
            return existing_urls

        except Exception as e:
            self.logger.error(f"❌ Failed to get existing registrations: {str(e)}")
            return []

    def register_ecr_registry(self, registry: Dict) -> Dict:
        """Register ECR registry using discovered credentials"""
        registry_url = registry['registry_url']
        iam_role_arn = registry['iam_role_arn']
        external_id = registry['external_id']
        account_name = registry['account_name']

        self.logger.info(f"📝 {'[DRY RUN] ' if self.config['settings']['dry_run_mode'] else ''}Registering {registry_url}")
        self.logger.info(f"   Account: {account_name}")
        self.logger.info(f"   IAM Role: {iam_role_arn}")
        self.logger.info(f"   Repositories: {len(registry['repositories'])}")

        if self.config['settings']['dry_run_mode']:
            self.logger.info("   🧪 Dry run mode - registration skipped")
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
            url = f"{self.config['crowdstrike']['base_url']}/container-security/entities/registries/v1"
            response = requests.post(url, headers=headers, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                result = response.json()
                registry_data = result.get('resources', {})
                registry_id = registry_data.get('id', 'unknown')
                self.logger.info(f"   ✅ Registration successful! Registry ID: {registry_id}")
                return {
                    'success': True,
                    'registry': registry,
                    'registry_id': registry_id,
                    'error': None
                }
            else:
                error_response = response.json() if response.content else {}
                errors = error_response.get('errors', [])
                error_message = errors[0].get('message', 'Unknown error') if errors else f"HTTP {response.status_code}"
                self.logger.error(f"   ❌ Registration failed: {error_message}")
                return {
                    'success': False,
                    'registry': registry,
                    'registry_id': None,
                    'error': error_message
                }

        except Exception as e:
            error_message = str(e)
            self.logger.error(f"   ❌ Registration failed: {error_message}")
            return {
                'success': False,
                'registry': registry,
                'registry_id': None,
                'error': error_message
            }

    def run_onboarding_workflow(self) -> Dict:
        """Execute the complete ECR auto-onboarding workflow"""
        start_time = datetime.now()

        self.logger.info("🚀 Starting ECR Auto-Onboarding Workflow")
        self.logger.info("=" * 60)

        # Initialize result tracking
        result = {
            'session_id': self.session_id,
            'start_time': start_time.isoformat(),
            'discovered_registries': 0,
            'enhanced_registries': 0,
            'existing_registrations': 0,
            'new_registrations': 0,
            'failed_registrations': 0,
            'dry_run_mode': self.config['settings']['dry_run_mode'],
            'errors': [],
            'newly_registered': [],           # Full registry details
            'failed_registrations_list': []   # Registry details + error messages
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
                self.logger.info("ℹ️  No ECR registries discovered")
                return result

            # Step 3: Get unique account IDs and their CSPM credentials
            account_ids = list(set(registry['account_id'] for registry in registries))
            credentials_map = self.get_cspm_credentials(account_ids)
            if not credentials_map:
                self.logger.warning("⚠️  No CSPM credentials found")
                result['errors'].append('No CSPM credentials found')
                return result

            # Step 4: Enhance registries with credentials
            enhanced_registries = self.enhance_registries_with_credentials(registries, credentials_map)
            result['enhanced_registries'] = len(enhanced_registries)

            if not enhanced_registries:
                self.logger.warning("⚠️  No registries could be enhanced with credentials")
                return result

            # Step 5: Check existing registrations
            existing_registrations = self.get_existing_registrations()
            result['existing_registrations'] = len(existing_registrations)

            # Step 6: Calculate what needs registration
            to_register = [reg for reg in enhanced_registries if reg['registry_url'] not in existing_registrations]

            self.logger.info("📊 REGISTRATION SUMMARY:")
            self.logger.info("-" * 30)
            self.logger.info(f"   Discovered registries: {result['discovered_registries']}")
            self.logger.info(f"   Enhanced with credentials: {result['enhanced_registries']}")
            self.logger.info(f"   Already registered: {result['existing_registrations']}")
            self.logger.info(f"   Need registration: {len(to_register)}")

            if not to_register:
                self.logger.info("✅ All ECR registries are already onboarded!")

            # Step 7: Register missing registries
            self.logger.info(f"🔧 {'DRY RUN MODE' if self.config['settings']['dry_run_mode'] else 'LIVE MODE'} - Processing {len(to_register)} registrations:")

            for registry in to_register:
                reg_result = self.register_ecr_registry(registry)
                if reg_result['success']:
                    result['new_registrations'] += 1
                    result['newly_registered'].append(reg_result)
                else:
                    result['failed_registrations'] += 1
                    result['failed_registrations_list'].append(reg_result)

            # Calculate execution time
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            result['end_time'] = end_time.isoformat()
            result['execution_time'] = execution_time

            self.logger.info("🎉 ECR Auto-Onboarding Complete!")
            self.logger.info(f"   New registrations: {result['new_registrations']}")
            self.logger.info(f"   Failed registrations: {result['failed_registrations']}")
            self.logger.info(f"   Execution time: {execution_time:.2f}s")

            return result

        except Exception as e:
            self.logger.error(f"❌ Workflow failed: {str(e)}")
            result['errors'].append(str(e))
            return result


def main():
    """Main entry point for manual execution"""
    parser = argparse.ArgumentParser(
        description='CrowdStrike ECR Auto-Onboarding - Pure Local Manual Execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run with default configuration
    python3 ecr_auto_onboard_manual.py

    # Run in dry-run mode
    python3 ecr_auto_onboard_manual.py --dry-run

    # Run with custom config file
    python3 ecr_auto_onboard_manual.py --config /path/to/config.yaml

    # Run with verbose logging
    python3 ecr_auto_onboard_manual.py --verbose
        """
    )

    parser.add_argument('--config', '-c',
                      help='Path to configuration YAML file (default: config.yaml in script directory)')
    parser.add_argument('--dry-run', action='store_true',
                      help='Run in dry-run mode (no actual changes)')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(verbose=args.verbose)

    try:
        # Load configuration
        config = load_config(args.config)

        # Apply command-line overrides
        if args.dry_run:
            config['settings']['dry_run_mode'] = True

        # Validate required configuration
        if not config['crowdstrike']['client_id'] or not config['crowdstrike']['client_secret']:
            logger.error("❌ CrowdStrike credentials not configured. Please set client_id and client_secret in config file or environment variables.")
            return 1

        logger.info("🚀 Starting ECR Auto-Onboarding - Pure Local Execution")

        # Initialize and run the service
        service = ECRAutoOnboardingService(config, logger)
        result = service.run_onboarding_workflow()

        # Print final results
        if result.get('errors'):
            logger.error("❌ Execution completed with errors:")
            for error in result['errors']:
                logger.error(f"   - {error}")
            return 1
        else:
            logger.info("✅ Execution completed successfully!")
            return 0

    except KeyboardInterrupt:
        logger.info("\n⏹️  Execution interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        return 1


if __name__ == '__main__':
    sys.exit(main())