# External ID Flow - No Manual Configuration Required

> **Back to**: [README.md](README.md) | **Setup Guide**: [Quick Start](README.md#quick-start) | **Removal**: [REMOVAL_GUIDE.md](REMOVAL_GUIDE.md)

## How External IDs Work in ECR Auto-Onboarding

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                            EXTERNAL ID FLOW                                      │
 └─────────────────────────────────────────────────────────────────────────────────┘

 Step 1: Customer Setup (One-time)
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                 │
 │  Customer finds their CSPM external ID:                                        │
 │  aws iam get-role --role-name CrowdStrikeCSPMReader-xyz                        │
 │                                                                                 │
 │  Updates CSPM role trust policy to include Container Security:                 │
 │  {                                                                              │
 │    "Principal": {                                                               │
 │      "AWS": [                                                                   │
 │        "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector",              │
 │        "arn:aws:iam::292230061137:role/CrowdStrikeCustomerRegistryAssessmentRole" │
 │      ]                                                                          │
 │    },                                                                           │
 │    "Condition": {                                                               │
 │      "StringEquals": {                                                          │
 │        "sts:ExternalId": "d704125f265d436482e6ce36ca5be581"  ← SAME ID         │
 │      }                                                                          │
 │    }                                                                            │
 │  }                                                                              │
 └─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │
                                        ▼
 Step 2: Lambda Runtime (Automatic)
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                 │
 │  Lambda queries CSPM API automatically:                                        │
 │  GET /cloud-security-registration-aws/entities/account/v1                      │
 │                                                                                 │
 │  API Response:                                                                  │
 │  {                                                                              │
 │    "account_id": "284837339769",                                                │
 │    "resource_metadata": {                                                       │
 │      "iam_role_arn": "arn:aws:iam::284837339769:role/CrowdStrikeCSPMReader-xyz", │
 │      "external_id": "d704125f265d436482e6ce36ca5be581"  ← DISCOVERED           │
 │    }                                                                            │
 │  }                                                                              │
 │                                                                                 │
 │  Lambda Code (line 196):                                                       │
 │  external_id = resource_metadata.get('external_id')                            │
 │                                                                                 │
 └─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │
                                        ▼
 Step 3: ECR Registration (Automatic)
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                 │
 │  Lambda registers ECR with Container Security API:                             │
 │  POST /container-security/entities/registries/v1                               │
 │                                                                                 │
 │  Request Payload:                                                               │
 │  {                                                                              │
 │    "type": "ecr",                                                               │
 │    "url": "https://284837339769.dkr.ecr.us-west-2.amazonaws.com",              │
 │    "credential": {                                                              │
 │      "details": {                                                               │
 │        "aws_iam_role": "arn:aws:iam::284837339769:role/CrowdStrikeCSPMReader-xyz", │
 │        "aws_external_id": "d704125f265d436482e6ce36ca5be581"  ← SAME ID        │
 │      }                                                                          │
 │    }                                                                            │
 │  }                                                                              │
 │                                                                                 │
 │  ✅ SUCCESS: Container Security validates the credential because:               │
 │     1. IAM role trust policy allows Container Security principal               │
 │     2. External ID matches what's in the trust policy                          │
 │                                                                                 │
 └─────────────────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                                 KEY POINTS                                      │
 │                                                                                 │
 │  ✅ NO manual external ID configuration in Lambda deployment                   │
 │  ✅ Same external ID works for both CSPM and Container Security                │
 │  ✅ Lambda automatically discovers external IDs from CSPM API                  │
 │  ✅ Zero coordination needed between role setup and Lambda                     │
 │  ✅ Works for multiple AWS accounts (each with its own external ID)           │
 │                                                                                 │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

## Why This Works

1. **Single Source of Truth**: CSPM API is the authoritative source for external IDs
2. **Automatic Discovery**: Lambda queries CSPM API at runtime - no hardcoded values
3. **Same External ID**: Customer uses their existing CSPM external ID for Container Security
4. **Trust Policy**: Updated once to allow both CSPM and Container Security principals
5. **Zero Configuration**: No external ID parameters needed in CloudFormation deployment

## Customer Experience

**Before**: Complex coordination between role setup and Lambda configuration
**After**: Update role trust policy once, deploy Lambda with zero external ID configuration

The Lambda "just works" because it discovers everything it needs from the CSPM API!