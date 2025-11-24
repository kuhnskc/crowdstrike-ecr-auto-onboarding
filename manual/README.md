# Manual ECR Auto-Onboarding

Pure local ECR auto-onboarding solution using only CrowdStrike APIs. Perfect for testing, debugging, or environments where Lambda deployment isn't preferred.

## Features

- **Same functionality as Lambda version** - Dynamic IAM role discovery, multi-account support
- **Colorized console output** with clear progress indicators
- **Simple configuration** with YAML config file support
- **Built-in dry-run mode** for safe testing
- **Command-line interface** with flexible options
- **Pure CrowdStrike API solution** - No AWS SDK dependencies

## Quick Start

### 1. Install Dependencies

**Virtual Environment Required**: Modern systems often require virtual environments to install Python packages due to PEP 668 (externally-managed-environment protection).

```bash
cd manual/

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> **Tip**: Always activate the virtual environment before running the script:
> ```bash
> source venv/bin/activate  # Run this each time you open a new terminal
> python3 ecr_auto_onboard_manual.py --dry-run
> ```

### 2. Configure Credentials

**Option A: Configuration File (Recommended)**
```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your CrowdStrike credentials
```

**Option B: Environment Variables**
```bash
export CROWDSTRIKE_CLIENT_ID="your-client-id"
export CROWDSTRIKE_CLIENT_SECRET="your-client-secret"
export CROWDSTRIKE_BASE_URL="https://api.crowdstrike.com"  # Optional
```

### 3. Test Run (Dry Mode)

```bash
# Test without making any changes
python3 ecr_auto_onboard_manual.py --dry-run --verbose
```

### 4. Live Run

```bash
# Run with actual registration
python3 ecr_auto_onboard_manual.py
```

## Configuration

### Configuration File (config.yaml)

```yaml
crowdstrike:
  # CrowdStrike API base URL (adjust for your region)
  base_url: "https://api.crowdstrike.com"

  # CrowdStrike API credentials
  client_id: "your-client-id"
  client_secret: "your-client-secret"

settings:
  # Dry run mode - set to true to test without making changes
  dry_run_mode: false
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CROWDSTRIKE_CLIENT_ID` | CrowdStrike API Client ID | Required |
| `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike API Client Secret | Required |
| `CROWDSTRIKE_BASE_URL` | API endpoint | `https://api.crowdstrike.com` |
| `DRY_RUN_MODE` | Enable dry-run mode | `false` |

## Command-Line Options

```bash
python3 ecr_auto_onboard_manual.py [OPTIONS]

Options:
  -c, --config PATH     Custom configuration file path
  --dry-run            Run in dry-run mode (no changes)
  -v, --verbose        Enable verbose logging
  -h, --help           Show help message
```

## Usage Examples

### Basic Operations

```bash
# Always activate virtual environment first
source venv/bin/activate

# Default run with config.yaml
python3 ecr_auto_onboard_manual.py

# Dry-run with verbose output
python3 ecr_auto_onboard_manual.py --dry-run --verbose

# Use custom config file
python3 ecr_auto_onboard_manual.py --config /path/to/my-config.yaml
```


## Prerequisites

1. **Python 3.7+** with pip
2. **CrowdStrike API credentials** with required scopes:
   - **CSPM registration**: READ
   - **Cloud Security API Assets**: READ
   - **Falcon Container Image**: READ
   - **Falcon Container Image**: WRITE
3. **CSPM roles updated** for Container Security (run `../setup-cspm-role.sh` first)

## Disclaimer

This project was co-authored with Claude AI and is an **unofficial, unsupported** tool. Use at your own risk. While designed to work with CrowdStrike products, this is not an official CrowdStrike solution and comes with no warranties or support guarantees.