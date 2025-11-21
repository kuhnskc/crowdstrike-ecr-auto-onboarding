#!/bin/bash
# CrowdStrike ECR Auto-Onboarding: CSPM Role Setup Script
# This script updates your existing CSPM role to enable ECR auto-onboarding

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

# Configuration
CONTAINER_SECURITY_PRINCIPAL="arn:aws:iam::292230061137:role/CrowdStrikeCustomerRegistryAssessmentRole"

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
    echo "Usage: $0 [CSPM_ROLE_NAME]"
    echo ""
    echo "This script updates your CrowdStrike CSPM role to enable ECR auto-onboarding."
    echo ""
    echo "Arguments:"
    echo "  CSPM_ROLE_NAME    Name of your CSPM role (e.g., CrowdStrikeCSPMReader-gt7elswu7hug)"
    echo "                    If not provided, script will attempt to find it automatically"
    echo ""
    echo "Examples:"
    echo "  $0 CrowdStrikeCSPMReader-gt7elswu7hug"
    echo "  $0  # Auto-discover role name"
    echo ""
    exit 1
}

find_cspm_role() {
    debug_log "Starting find_cspm_role function"
    print_info "Searching for CrowdStrike CSPM role..."

    # Look for roles with CrowdStrike CSPM patterns
    debug_log "Running AWS CLI command to find CSPM roles..."
    local role_names
    role_names=$(aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrike`) && contains(RoleName, `CSPM`)].RoleName' --output text 2>&1) || {
        debug_log "First AWS CLI command failed with exit code $?, output: $role_names"
        role_names=""
    }
    debug_log "CSPM role search result: '$role_names'"

    if [ -z "$role_names" ]; then
        debug_log "No CSMP roles found, trying alternative pattern..."
        # Try alternative patterns
        role_names=$(aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrike`) && contains(RoleName, `Reader`)].RoleName' --output text 2>&1) || {
            debug_log "Alternative AWS CLI command failed with exit code $?, output: $role_names"
            role_names=""
        }
        debug_log "Alternative role search result: '$role_names'"
    fi

    if [ -z "$role_names" ]; then
        debug_log "No CrowdStrike roles found at all"
        print_error "Could not automatically find CrowdStrike CSPM role"
        print_info "Please run: aws iam list-roles --query 'Roles[?contains(RoleName, \`CrowdStrike\`)].RoleName' --output table"
        print_info "Then run this script with the role name: $0 <ROLE_NAME>"
        exit 1
    fi

    local role_count=$(echo "$role_names" | wc -w)
    debug_log "Found $role_count role(s): $role_names"

    if [ "$role_count" -eq 1 ]; then
        debug_log "Returning single role: $role_names"
        echo "$role_names"
    else
        print_warning "Multiple CrowdStrike roles found:"
        echo "$role_names" | tr '\t' '\n' | sed 's/^/  - /'
        print_info "Please specify the CSPM role name: $0 <ROLE_NAME>"
        exit 1
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

    # First, let's see if we can find the CSPM statement
    local cspm_statement
    cspm_statement=$(echo "$trust_policy" | jq '.Statement[] | select(.Principal.AWS | contains("CrowdStrikeCSPMConnector"))' 2>/dev/null)
    debug_log "CSPM statement found: $cspm_statement"

    # If no CSPM statement, try Container Security (might be already configured)
    if [ -z "$cspm_statement" ] || [ "$cspm_statement" = "null" ]; then
        debug_log "No CSPM statement found, checking for Container Security statement"
        local container_statement
        container_statement=$(echo "$trust_policy" | jq '.Statement[] | select(.Principal.AWS | contains("CrowdStrikeCustomerRegistryAssessmentRole"))' 2>/dev/null)
        debug_log "Container Security statement found: $container_statement"

        if [ -n "$container_statement" ] && [ "$container_statement" != "null" ]; then
            debug_log "Found Container Security statement, extracting external ID from it"
            local external_id
            external_id=$(echo "$trust_policy" | jq -r '.Statement[] | select(.Principal.AWS | contains("CrowdStrikeCustomerRegistryAssessmentRole")) | .Condition.StringEquals."sts:ExternalId"' 2>/dev/null)
            debug_log "External ID from Container Security statement: '$external_id'"
            echo "$external_id"
            return 0
        fi
    fi

    # Try to extract from CSPM statement
    local external_id
    external_id=$(echo "$trust_policy" | jq -r '.Statement[] | select(.Principal.AWS | contains("CrowdStrikeCSPMConnector")) | .Condition.StringEquals."sts:ExternalId"' 2>/dev/null)
    debug_log "jq extraction result from CSPM: '$external_id'"

    echo "$external_id"
}

check_container_security_access() {
    local trust_policy="$1"
    echo "$trust_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end)' >/dev/null 2>&1
}

create_updated_trust_policy() {
    local current_policy="$1"
    local cspm_external_id="$2"

    debug_log "Creating updated trust policy with external ID: $cspm_external_id"

    # Check if Container Security access already exists
    local has_container_security=$(echo "$current_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end)' >/dev/null 2>&1 && echo "true" || echo "false")
    debug_log "Container Security access exists: $has_container_security"

    # Check if CSPM access already exists
    local has_cspm=$(echo "$current_policy" | jq -e '.Statement[] | select(.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCSPMConnector")) else contains("CrowdStrikeCSPMConnector") end)' >/dev/null 2>&1 && echo "true" || echo "false")
    debug_log "CSPM access exists: $has_cspm"

    if [ "$has_container_security" = "true" ] && [ "$has_cspm" = "true" ]; then
        debug_log "Both CSPM and Container Security access already configured"
        print_info "Both CSPM and Container Security access already configured"
        return 0
    fi

    if [ "$has_container_security" = "true" ] && [ "$has_cspm" = "false" ]; then
        debug_log "Container Security exists but CSPM missing - adding CSPM principal"
        # Add CSPM principal to existing Container Security statement
        echo "$current_policy" | jq --arg ext_id "$cspm_external_id" --arg cspm_principal "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector" '
            .Statement |= map(
                if (.Principal.AWS | if type == "array" then any(contains("CrowdStrikeCustomerRegistryAssessmentRole")) else contains("CrowdStrikeCustomerRegistryAssessmentRole") end) then
                    .Principal.AWS = (
                        if (.Principal.AWS | type == "array") then
                            (.Principal.AWS + [$cspm_principal]) | unique
                        else
                            [.Principal.AWS, $cspm_principal]
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
        echo "$current_policy" | jq --arg ext_id "$cspm_external_id" --arg container_principal "$CONTAINER_SECURITY_PRINCIPAL" '
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
        debug_log "Neither CSPM nor Container Security found - this shouldn't happen"
        print_error "Could not find either CSPM or Container Security statement in trust policy"
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

    print_info "Checking role permissions..."

    local policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[].PolicyName' --output text 2>/dev/null)

    if echo "$policies" | grep -q "AmazonEC2ContainerRegistryReadOnly"; then
        print_success "ECR read permissions: OK"
    else
        print_warning "ECR read permissions missing"
        print_info "Adding AmazonEC2ContainerRegistryReadOnly policy..."

        if aws iam attach-role-policy --role-name "$role_name" --policy-arn "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly" 2>/dev/null; then
            print_success "ECR read permissions: Added"
        else
            print_error "Failed to add ECR read permissions"
            return 1
        fi
    fi
}

test_role_configuration() {
    local role_name="$1"
    local external_id="$2"

    print_info "Testing role configuration..."

    # Verify we can retrieve role details
    if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
        print_success "Role access: OK"
    else
        print_error "Cannot access role"
        return 1
    fi

    print_success "Role configuration appears valid"
    print_info "External ID for Lambda configuration: $external_id"
}

main() {
    print_header

    # Get role name
    local role_name="$1"
    if [ -z "$role_name" ]; then
        role_name=$(find_cspm_role)
        print_success "Found CSPM role: $role_name"
    else
        print_info "Using specified role: $role_name"
    fi

    # Get current trust policy
    print_info "Retrieving current role configuration..."
    local current_trust_policy=$(get_current_trust_policy "$role_name")

    if [ "$current_trust_policy" = "null" ] || [ -z "$current_trust_policy" ]; then
        print_error "Could not retrieve role trust policy for: $role_name"
        print_info "Please verify the role name and your AWS permissions"
        exit 1
    fi

    # Extract CSPM external ID
    local cspm_external_id=$(extract_cspm_external_id "$current_trust_policy")

    if [ "$cspm_external_id" = "null" ] || [ -z "$cspm_external_id" ]; then
        print_error "Could not find CSPM external ID in trust policy"
        print_info "Please verify this is a valid CrowdStrike CSPM role"
        exit 1
    fi

    print_success "Found CSPM external ID: $cspm_external_id"

    # Check if already configured
    if check_container_security_access "$current_trust_policy"; then
        print_success "Container Security access already configured!"
        verify_permissions "$role_name"
        test_role_configuration "$role_name" "$cspm_external_id"

        echo ""
        print_success "Setup complete! Use this configuration in your Lambda deployment:"
        echo -e "  ${YELLOW}CSPM Role:${NC} $role_name"
        echo -e "  ${YELLOW}External ID:${NC} $cspm_external_id"
        exit 0
    fi

    # Create updated trust policy
    print_info "Creating updated trust policy..."
    local updated_policy=$(create_updated_trust_policy "$current_trust_policy" "$cspm_external_id")

    if [ $? -ne 0 ] || [ "$updated_policy" = "null" ] || [ -z "$updated_policy" ]; then
        print_error "Failed to create updated trust policy"
        exit 1
    fi

    # Show what will change
    print_warning "Will add Container Security access to role: $role_name"
    print_info "New principal: $CONTAINER_SECURITY_PRINCIPAL"
    print_info "Using external ID: $cspm_external_id"

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

    # Test configuration
    test_role_configuration "$role_name" "$cspm_external_id"

    # Success summary
    echo ""
    print_success "🎉 ECR Auto-Onboarding setup complete!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo -e "  1. Deploy the CrowdStrike ECR Auto-Onboarding Lambda"
    echo -e "  2. ${YELLOW}No external ID configuration needed!${NC}"
    echo -e "     The Lambda will automatically discover and use: ${YELLOW}$cspm_external_id${NC}"
    echo -e "  3. Test the auto-onboarding functionality"
    echo ""
    echo -e "${BLUE}Key Points:${NC}"
    echo -e "  ✅ Your CSMP role now supports Container Security access"
    echo -e "  ✅ Same external ID (${YELLOW}$cspm_external_id${NC}) works for both services"
    echo -e "  ✅ Lambda automatically discovers external IDs from CSPM API"
    echo -e "  ✅ No manual external ID configuration required in Lambda deployment"
    echo ""
    print_info "The Lambda will now be able to automatically discover and register your ECR repositories!"
}

# Check for help flags
case "${1:-}" in
    -h|--help|help)
        usage
        ;;
esac

# Add debug at start
debug_log "Script started with arguments: $@"

# Check AWS CLI
debug_log "Checking AWS CLI availability..."
if ! command -v aws >/dev/null 2>&1; then
    print_error "AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

debug_log "AWS CLI found, checking version:"
aws --version 2>&1 | head -1 || {
    print_error "AWS CLI seems to be installed but not working properly"
    exit 1
}

debug_log "Checking AWS credentials..."
aws sts get-caller-identity >/dev/null 2>&1 || {
    print_error "AWS credentials not configured. Please run 'aws configure' first."
    exit 1
}

debug_log "Checking jq availability..."
if ! command -v jq >/dev/null 2>&1; then
    print_error "jq not found. Please install jq for JSON processing."
    exit 1
fi

# Run main function
debug_log "Calling main function"
main "$@"
debug_log "Script completed"