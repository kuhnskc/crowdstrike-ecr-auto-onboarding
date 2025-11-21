#!/bin/bash
# CrowdStrike ECR Auto-Onboarding: CSPM Role Setup Script
# This script updates your existing CSPM role to enable ECR auto-onboarding
# Supports both single account and AWS Organizations multi-account deployment

set -e

# Debug logging
DEBUG=false
debug_log() {
    if [ "$DEBUG" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" >&2
    fi
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Add error trap for debugging (after colors are defined)
trap 'echo -e "${RED}[ERROR]${NC} Script exiting due to error on line $LINENO" >&2' ERR

# Configuration
CONTAINER_SECURITY_PRINCIPAL="arn:aws:iam::292230061137:role/CrowdStrikeCustomerRegistryAssessmentRole"
ORG_ASSUME_ROLE="OrganizationAccountAccessRole"  # Default cross-account role

print_header() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  CrowdStrike ECR Auto-Onboarding Setup${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS] [CSPM_ROLE_NAME]"
    echo ""
    echo "This script updates your CrowdStrike CSPM role(s) to enable ECR auto-onboarding."
    echo ""
    echo "Options:"
    echo "  --org                 Enable AWS Organizations mode (run from management account)"
    echo "  --assume-role NAME    Cross-account role name (default: OrganizationAccountAccessRole)"
    echo "  --dry-run             Show what would be done without making changes"
    echo "  --debug               Enable debug logging"
    echo "  --account-id ID       Test specific account (with --org)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Arguments:"
    echo "  CSPM_ROLE_NAME        Name of your CSPM role (e.g., CrowdStrikeCSPMReader-ABC123XYZ)"
    echo "                        If not provided, script will attempt to find it automatically"
    echo ""
    echo "Examples:"
    echo "  # Single account setup"
    echo "  $0 CrowdStrikeCSPMReader-ABC123XYZ"
    echo "  $0  # Auto-discover role name"
    echo ""
    echo "  # Organizations setup (run from management account)"
    echo "  $0 --org"
    echo "  $0 --org --assume-role MyCustomRole"
    echo "  $0 --org --dry-run  # Test without changes"
    echo ""
    exit 1
}

check_organizations_access() {
    print_info "Checking AWS Organizations access..."

    if ! aws organizations describe-organization >/dev/null 2>&1; then
        print_error "Cannot access AWS Organizations"
        print_info "Please ensure you're running from the management account with proper permissions"
        return 1
    fi

    print_success "Organizations access confirmed"
    return 0
}

list_org_accounts() {
    debug_log "Listing organization accounts..."

    local accounts
    accounts=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Id,Name]' --output text 2>/dev/null) || {
        print_error "Failed to list organization accounts"
        return 1
    }

    if [ -z "$accounts" ]; then
        print_error "No active accounts found in organization"
        return 1
    fi

    echo "$accounts"
}

assume_cross_account_role() {
    local account_id="$1"
    local assume_role_name="$2"
    local role_arn="arn:aws:iam::${account_id}:role/${assume_role_name}"

    debug_log "Attempting to assume role: $role_arn"

    # Try to assume the role and get temporary credentials
    local assume_output
    assume_output=$(aws sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "ECRAutoOnboardSetup-$(date +%s)" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>/dev/null) || {
        debug_log "Failed to assume role: $role_arn"
        return 1
    }

    # Export the temporary credentials
    local access_key=$(echo "$assume_output" | cut -f1)
    local secret_key=$(echo "$assume_output" | cut -f2)
    local session_token=$(echo "$assume_output" | cut -f3)

    export AWS_ACCESS_KEY_ID="$access_key"
    export AWS_SECRET_ACCESS_KEY="$secret_key"
    export AWS_SESSION_TOKEN="$session_token"

    debug_log "Successfully assumed cross-account role"
    return 0
}

restore_original_credentials() {
    debug_log "Starting credential restoration..."
    # Unset the temporary credentials to restore original session
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN
    debug_log "Restored original AWS credentials"

    # Verify credentials are working
    local current_account
    debug_log "Attempting to get caller identity..."
    current_account=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || {
        debug_log "Failed to get caller identity after credential restore"
        return 1
    }
    debug_log "Current account after credential restore: $current_account"
    debug_log "Credential restoration completed successfully"
}

process_single_account() {
    local account_id="$1"
    local account_name="$2"
    local csmp_role_name="$3"
    local dry_run="$4"

    print_info "Processing account: $account_name ($account_id)"

    # Find or use specified role name
    local role_name="$csmp_role_name"
    if [ -z "$role_name" ]; then
        role_name=$(find_cspm_role 2>/dev/null) || {
            print_warning "No CSPM role found in account $account_name ($account_id)"
            return 0
        }
    fi

    print_info "Found CSPM role: $role_name"

    # Get current trust policy
    local current_trust_policy=$(get_current_trust_policy "$role_name" 2>/dev/null) || {
        print_warning "Cannot access role $role_name in account $account_name"
        return 0
    }

    # Extract external ID
    local csmp_external_id=$(extract_cspm_external_id "$current_trust_policy")

    if [ "$csmp_external_id" = "null" ] || [ -z "$csmp_external_id" ]; then
        print_warning "Could not find CSPM external ID in account $account_name"
        return 0
    fi

    # Check if already configured - early return if yes
    if check_container_security_access "$current_trust_policy"; then
        print_success "Container Security access already configured in $account_name"
        debug_log "About to verify permissions for role: $role_name"

        # Skip permission verification in assumed role context for Organizations mode
        if [ "$ORG_MODE" = true ]; then
            debug_log "Skipping ECR permission verification in Organizations mode"
        else
            verify_permissions "$role_name" 2>/dev/null || true
        fi

        debug_log "Account $account_name already properly configured"
        debug_log "About to return 0 from process_single_account"
        return 0
    fi

    if [ "$dry_run" = "true" ]; then
        print_info "[DRY RUN] Would update role $role_name in account $account_name"
        print_info "[DRY RUN] Would add Container Security principal with external ID: $csmp_external_id"
        return 0
    fi

    # Create and apply updated trust policy
    print_info "Updating trust policy for role: $role_name"
    local updated_policy=$(create_updated_trust_policy "$current_trust_policy" "$csmp_external_id")

    if [ $? -ne 0 ] || [ "$updated_policy" = "null" ] || [ -z "$updated_policy" ]; then
        print_error "Failed to create updated trust policy for account $account_name"
        return 1
    fi

    if update_role_trust_policy "$role_name" "$updated_policy"; then
        print_success "Updated trust policy in account $account_name"
        verify_permissions "$role_name"
        print_success "Account $account_name setup completed successfully"
    else
        print_error "Failed to update trust policy in account $account_name"
        return 1
    fi
}

run_organizations_mode() {
    local csmp_role_name="$1"
    local assume_role_name="$2"
    local dry_run="$3"

    print_header
    print_info "Running in AWS Organizations mode..."

    # Check Organizations access
    check_organizations_access || exit 1

    # Store original credentials
    local orig_access_key="$AWS_ACCESS_KEY_ID"
    local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
    local orig_session_token="$AWS_SESSION_TOKEN"

    # Get list of accounts
    local accounts=$(list_org_accounts) || exit 1
    local total_accounts=$(echo "$accounts" | wc -l)

    print_info "Found $total_accounts active accounts in organization"

    if [ "$dry_run" = "true" ]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi

    echo ""

    # Process each account
    local success_count=0
    local skip_count=0
    local error_count=0

    debug_log "Starting to process $total_accounts accounts"
    debug_log "Raw accounts data: '$accounts'"
    debug_log "Accounts data length: ${#accounts}"

    # Convert accounts to array for more reliable iteration
    local account_array=()
    while IFS=$'\t' read -r account_id account_name; do
        debug_log "Processing line: account_id='$account_id' account_name='$account_name'"
        # Skip empty lines
        if [ -n "$account_id" ] && [ -n "$account_name" ]; then
            account_array+=("$account_id:$account_name")
            debug_log "Added to array: '$account_id:$account_name'"
        else
            debug_log "Skipping empty or incomplete line"
        fi
    done <<< "$accounts"

    debug_log "Converted to array with ${#account_array[@]} accounts"
    debug_log "Array contents: ${account_array[*]}"

    # Process each account using array iteration (CloudShell compatible)
    debug_log "About to start for loop with array of ${#account_array[@]} elements"

    # Use C-style for loop to avoid array expansion issues in CloudShell
    for (( i=0; i<${#account_array[@]}; i++ )); do
        local account_entry="${account_array[$i]}"
        local iteration_num=$((i + 1))  # Display counter starting at 1
        debug_log "ENTERED for loop - iteration $iteration_num, processing entry: '$account_entry'"

        # Extract account ID and name
        local account_id="${account_entry%%:*}"
        local account_name="${account_entry#*:}"

        debug_log "Loop iteration $iteration_num - processing account: $account_id $account_name"
        echo -e "${BLUE}----------------------------------------${NC}"

        # Skip if targeting specific account
        if [ -n "$TARGET_ACCOUNT_ID" ] && [ "$account_id" != "$TARGET_ACCOUNT_ID" ]; then
            print_info "Skipping account $account_name ($account_id) - not target account"
            continue
        fi

        # Skip management account (current account)
        local current_account=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
        debug_log "Current account identity: $current_account, processing: $account_id"

        if [ "$account_id" = "$current_account" ]; then
            print_info "Processing management account: $account_name ($account_id)"
            debug_log "About to call process_single_account for management account..."
            # Process management account with current credentials
            if process_single_account "$account_id" "$account_name" "$csmp_role_name" "$dry_run"; then
                debug_log "Management account process_single_account returned success"
                success_count=$((success_count + 1))
                debug_log "Incremented management success_count to: $success_count"
                debug_log "Management account processed successfully"
            else
                debug_log "Management account process_single_account returned failure"
                error_count=$((error_count + 1))
                debug_log "Incremented management error_count to: $error_count"
                debug_log "Management account processing failed"
            fi
        else
            # Assume role in member account
            print_info "Assuming role in account: $account_name ($account_id)"

            if assume_cross_account_role "$account_id" "$assume_role_name"; then
                debug_log "Successfully assumed role, processing account"
                debug_log "About to call process_single_account..."

                if process_single_account "$account_id" "$account_name" "$csmp_role_name" "$dry_run"; then
                    debug_log "process_single_account returned success (0)"
                    success_count=$((success_count + 1))
                    debug_log "Incremented success_count to: $success_count"
                    debug_log "Member account processed successfully"
                else
                    debug_log "process_single_account returned failure"
                    error_count=$((error_count + 1))
                    debug_log "Incremented error_count to: $error_count"
                    debug_log "Member account processing failed"
                fi
                debug_log "Back from process_single_account call, about to restore credentials"
                # Restore original credentials
                debug_log "Restoring original credentials"
                restore_original_credentials || true
                debug_log "Credentials restored, continuing in loop"
            else
                print_warning "Cannot assume role in account $account_name (role: $assume_role_name)"
                print_info "Skipping account $account_id"
                skip_count=$((skip_count + 1))
                debug_log "Incremented skip_count to: $skip_count"
                debug_log "Failed to assume role, skipping account"
            fi
        fi

        echo ""
        print_info "Processed account $((success_count + error_count + skip_count)) of $total_accounts"
        debug_log "Current counts - success: $success_count, error: $error_count, skip: $skip_count"

        # If targeting specific account, exit after processing
        if [ -n "$TARGET_ACCOUNT_ID" ] && [ "$account_id" = "$TARGET_ACCOUNT_ID" ]; then
            debug_log "Target account processed, breaking loop"
            break
        fi

        debug_log "Continuing to next account in loop (iteration $iteration_num of ${#account_array[@]})"
    done

    debug_log "Finished processing all accounts - exited for loop normally"

    # Summary
    echo -e "${BLUE}========================================${NC}"
    print_success "Organizations setup complete!"
    echo -e "  ${GREEN}Accounts processed successfully: $success_count${NC}"
    if [ $skip_count -gt 0 ]; then
        echo -e "  ${YELLOW}Accounts skipped: $skip_count${NC}"
    fi
    if [ $error_count -gt 0 ]; then
        echo -e "  ${RED}Accounts with errors: $error_count${NC}"
    fi
    echo -e "  ${BLUE}Total accounts: $total_accounts${NC}"

    if [ "$dry_run" = "false" ] && [ $success_count -gt 0 ]; then
        echo ""
        echo -e "${GREEN}Next steps:${NC}"
        echo -e "  1. Deploy the CrowdStrike ECR Auto-Onboarding Lambda"
        echo -e "  2. ${YELLOW}No external ID configuration needed!${NC}"
        echo -e "     The Lambda will automatically discover external IDs from each account"
        echo -e "  3. Test the auto-onboarding functionality"
    fi
}

find_cspm_role() {
    debug_log "Starting find_cspm_role function"

    # Look specifically for the CSPM Reader role pattern (most specific first)
    debug_log "Running AWS CLI command to find CSPM Reader roles..."
    local role_names
    role_names=$(aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrikeCSPMReader`)].RoleName' --output text 2>&1) || {
        debug_log "CSPM Reader search failed with exit code $?, output: $role_names"
        role_names=""
    }
    debug_log "CSPM Reader role search result: '$role_names'"

    # If no CSPM Reader found, try broader CSPM pattern but exclude service roles
    if [ -z "$role_names" ]; then
        debug_log "No CSPM Reader roles found, trying broader CSPM pattern..."
        role_names=$(aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrike`) && contains(RoleName, `CSPM`) && !contains(RoleName, `CloudformationService`) && !contains(RoleName, `CustomResource`) && !contains(RoleName, `ComputeRole`) && !contains(RoleName, `JobRole`) && !contains(RoleName, `SpotFleet`)].RoleName' --output text 2>&1) || {
            debug_log "Broader CSPM search failed with exit code $?, output: $role_names"
            role_names=""
        }
        debug_log "Broader CSPM role search result: '$role_names'"
    fi

    # If still no CSPM roles, try alternative patterns
    if [ -z "$role_names" ]; then
        debug_log "No CSPM roles found, trying alternative pattern..."
        role_names=$(aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrike`) && contains(RoleName, `Reader`)].RoleName' --output text 2>&1) || {
            debug_log "Alternative AWS CLI command failed with exit code $?, output: $role_names"
            role_names=""
        }
        debug_log "Alternative role search result: '$role_names'"
    fi

    if [ -z "$role_names" ]; then
        debug_log "No CrowdStrike roles found at all"
        return 1
    fi

    local role_count=$(echo "$role_names" | wc -w)
    debug_log "Found $role_count role(s): $role_names"

    if [ "$role_count" -eq 1 ]; then
        debug_log "Returning single role: $role_names"
        echo "$role_names"
    else
        # Return first role found for Organizations mode, or show options for single mode
        if [ "$ORG_MODE" = true ]; then
            echo "$role_names" | awk '{print $1}'
        else
            print_warning "Multiple CrowdStrike roles found:"
            echo "$role_names" | tr '\t' '\n' | sed 's/^/  - /'
            print_info "Please specify the CSPM role name: $0 <ROLE_NAME>"
            exit 1
        fi
    fi
}

get_current_trust_policy() {
    local role_name="$1"
    debug_log "Getting trust policy for role: $role_name"
    local trust_policy
    trust_policy=$(aws iam get-role --role-name "$role_name" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
    debug_log "Raw trust policy JSON: $trust_policy"
    echo "$trust_policy"
}

extract_cspm_external_id() {
    local trust_policy="$1"
    debug_log "Extracting external ID from trust policy"
    debug_log "Trust policy input: $trust_policy"

    # Try to extract external ID from any statement that has CrowdStrike principals
    # Look for statements with either CSMP or Container Security principals
    local external_id

    # First try: Look for statement with CSMP principal
    external_id=$(echo "$trust_policy" | jq -r '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCSPMConnector")) else contains("CrowdStrikeCSPMConnector") end) | .Condition.StringEquals."sts:ExternalId"' 2>/dev/null)
    debug_log "External ID from CSMP principal statement: '$external_id'"

    # If not found or empty, try Container Security principal
    if [ -z "$external_id" ] || [ "$external_id" = "null" ]; then
        debug_log "No external ID from CSMP statement, trying Container Security statement"
        external_id=$(echo "$trust_policy" | jq -r '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end) | .Condition.StringEquals."sts:ExternalId"' 2>/dev/null)
        debug_log "External ID from Container Security statement: '$external_id'"
    fi

    # If still not found, try any statement with CrowdStrike in the principal
    if [ -z "$external_id" ] || [ "$external_id" = "null" ]; then
        debug_log "No external ID found, trying any CrowdStrike statement"
        external_id=$(echo "$trust_policy" | jq -r '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrike")) else contains("CrowdStrike") end) | .Condition.StringEquals."sts:ExternalId"' 2>/dev/null)
        debug_log "External ID from any CrowdStrike statement: '$external_id'"
    fi

    echo "$external_id"
}

check_container_security_access() {
    local trust_policy="$1"
    echo "$trust_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end)' >/dev/null 2>&1
}

create_updated_trust_policy() {
    local current_policy="$1"
    local csmp_external_id="$2"

    debug_log "Creating updated trust policy with external ID: $csmp_external_id"
    debug_log "Current policy JSON: $current_policy"

    # Check if Container Security access already exists
    local has_container_security=$(echo "$current_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end)' >/dev/null 2>&1 && echo "true" || echo "false")
    debug_log "Container Security access exists: $has_container_security"

    # Check if CSPM access already exists
    local has_cspm=$(echo "$current_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCSPMConnector")) else contains("CrowdStrikeCSPMConnector") end)' >/dev/null 2>&1 && echo "true" || echo "false")
    debug_log "CSPM access exists: $has_cspm"

    # Additional debug: show all principals
    debug_log "All principals in policy: $(echo "$current_policy" | jq -c '.Statement[].Principal.AWS' 2>/dev/null || echo 'none')"

    if [ "$has_container_security" = "true" ] && [ "$has_cspm" = "true" ]; then
        debug_log "Both CSPM and Container Security access already configured"
        return 0
    fi

    if [ "$has_container_security" = "true" ] && [ "$has_cspm" = "false" ]; then
        debug_log "Container Security exists but CSPM missing - adding CSPM principal"
        # Add CSMP principal to existing Container Security statement
        echo "$current_policy" | jq --arg ext_id "$csmp_external_id" --arg csmp_principal "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector" '
            .Statement |= map(
                if (.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end) then
                    .Principal.AWS = (
                        if (.Principal.AWS | type == "array") then
                            (.Principal.AWS + [$csmp_principal]) | unique
                        else
                            [.Principal.AWS, $csmp_principal]
                        end
                    ) |
                    .Condition.StringEquals."sts:ExternalId" = $ext_id
                else
                    .
                end
            )
        '
    elif [ "$has_cspm" = "true" ] && [ "$has_container_security" = "false" ]; then
        debug_log "CSPM exists but Container Security missing - adding Container Security principal"
        # Add Container Security principal to existing CSPM statement
        echo "$current_policy" | jq --arg ext_id "$csmp_external_id" --arg container_principal "$CONTAINER_SECURITY_PRINCIPAL" '
            .Statement |= map(
                if (.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCSPMConnector")) else contains("CrowdStrikeCSPMConnector") end) then
                    .Principal.AWS = (
                        if (.Principal.AWS | type == "array") then
                            (.Principal.AWS + [$container_principal]) | unique
                        else
                            [.Principal.AWS, $container_principal]
                        end
                    ) |
                    .Condition.StringEquals."sts:ExternalId" = $ext_id
                else
                    .
                end
            )
        '
    else
        debug_log "Neither CSPM nor Container Security found in trust policy"
        print_warning "Trust policy doesn't contain expected CrowdStrike statements"
        print_info "This may not be a standard CSPM role or has a custom configuration"

        # Show what principals exist for troubleshooting
        local principals=$(echo "$current_policy" | jq -c '.Statement[].Principal.AWS' 2>/dev/null | head -3)
        print_info "Found principals: $principals"

        return 1
    fi
}

update_role_trust_policy() {
    local role_name="$1"
    local updated_policy="$2"

    # Write policy to temporary file
    local temp_policy="/tmp/updated_trust_policy_$$.json"
    echo "$updated_policy" > "$temp_policy"

    # Update the role
    if aws iam update-assume-role-policy --role-name "$role_name" --policy-document "file://$temp_policy" 2>/dev/null; then
        rm -f "$temp_policy"
        return 0
    else
        rm -f "$temp_policy"
        return 1
    fi
}

verify_permissions() {
    local role_name="$1"

    local policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[].PolicyName' --output text 2>/dev/null)

    if echo "$policies" | grep -q "AmazonEC2ContainerRegistryReadOnly"; then
        debug_log "ECR read permissions: OK"
    else
        print_info "Adding ECR read permissions..."

        if aws iam attach-role-policy --role-name "$role_name" --policy-arn "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly" 2>/dev/null; then
            print_success "ECR read permissions added successfully"
        else
            print_warning "Failed to add ECR read permissions"
        fi
    fi
}

# Parse command line arguments
ORG_MODE=false
ASSUME_ROLE_NAME="$ORG_ASSUME_ROLE"
DRY_RUN=false
CSPM_ROLE_NAME=""
TARGET_ACCOUNT_ID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --org)
            ORG_MODE=true
            shift
            ;;
        --assume-role)
            ASSUME_ROLE_NAME="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --account-id)
            TARGET_ACCOUNT_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            print_error "Unknown option: $1"
            usage
            ;;
        *)
            if [ -z "$CSPM_ROLE_NAME" ]; then
                CSPM_ROLE_NAME="$1"
            else
                print_error "Multiple role names specified"
                usage
            fi
            shift
            ;;
    esac
done

# Check dependencies
debug_log "Checking dependencies..."
if ! command -v aws >/dev/null 2>&1; then
    print_error "AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    print_error "jq not found. Please install jq for JSON processing."
    exit 1
fi

# Check AWS credentials
aws sts get-caller-identity >/dev/null 2>&1 || {
    print_error "AWS credentials not configured. Please run 'aws configure' first."
    exit 1
}

# Run in appropriate mode
if [ "$ORG_MODE" = true ]; then
    run_organizations_mode "$CSPM_ROLE_NAME" "$ASSUME_ROLE_NAME" "$DRY_RUN"
else
    # Single account mode (original functionality)
    print_header

    # Get role name
    role_name="$CSPM_ROLE_NAME"
    if [ -z "$role_name" ]; then
        role_name=$(find_cspm_role)
        print_success "Found CSPM role: $role_name"
    else
        print_info "Using specified role: $role_name"
    fi

    # Get current trust policy
    print_info "Retrieving current role configuration..."
    current_trust_policy=$(get_current_trust_policy "$role_name")

    if [ "$current_trust_policy" = "null" ] || [ -z "$current_trust_policy" ]; then
        print_error "Could not retrieve role trust policy for: $role_name"
        print_info "Please verify the role name and your AWS permissions"
        exit 1
    fi

    # Extract CSPM external ID
    csmp_external_id=$(extract_cspm_external_id "$current_trust_policy")

    if [ "$csmp_external_id" = "null" ] || [ -z "$csmp_external_id" ]; then
        print_error "Could not find CSPM external ID in trust policy"
        print_info "Please verify this is a valid CrowdStrike CSPM role"
        exit 1
    fi

    print_success "Found CSPM external ID: $csmp_external_id"

    # Check if already configured
    if check_container_security_access "$current_trust_policy"; then
        print_success "Container Security access already configured!"
        verify_permissions "$role_name"

        echo ""
        print_success "Setup complete! Use this configuration in your Lambda deployment:"
        echo -e "  ${YELLOW}CSPM Role:${NC} $role_name"
        echo -e "  ${YELLOW}External ID:${NC} $csmp_external_id"
        exit 0
    fi

    if [ "$DRY_RUN" = true ]; then
        print_warning "DRY RUN MODE - Would update role: $role_name"
        print_info "Would add Container Security principal with external ID: $csmp_external_id"
        exit 0
    fi

    # Create updated trust policy
    print_info "Creating updated trust policy..."
    updated_policy=$(create_updated_trust_policy "$current_trust_policy" "$csmp_external_id")

    if [ $? -ne 0 ] || [ "$updated_policy" = "null" ] || [ -z "$updated_policy" ]; then
        print_error "Failed to create updated trust policy"
        exit 1
    fi

    # Show what will change
    print_warning "Will add Container Security access to role: $role_name"
    print_info "New principal: $CONTAINER_SECURITY_PRINCIPAL"
    print_info "Using external ID: $csmp_external_id"

    # Confirm update
    echo ""
    read -p "Proceed with role update? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled"
        exit 0
    fi

    # Update role trust policy
    print_info "Updating role trust policy..."
    if update_role_trust_policy "$role_name" "$updated_policy"; then
        print_success "Trust policy updated successfully"
    else
        print_error "Failed to update trust policy"
        exit 1
    fi

    # Verify permissions
    verify_permissions "$role_name"

    # Success summary
    echo ""
    print_success "🎉 ECR Auto-Onboarding setup complete!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo -e "  1. Deploy the CrowdStrike ECR Auto-Onboarding Lambda"
    echo -e "  2. ${YELLOW}No external ID configuration needed!${NC}"
    echo -e "     The Lambda will automatically discover and use: ${YELLOW}$csmp_external_id${NC}"
    echo -e "  3. Test the auto-onboarding functionality"
    echo ""
fi