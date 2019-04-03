#!/bin/bash -e

# get the directory of this script
# snippet from https://stackoverflow.com/a/246128/10102404
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# default to us-west-2 region
AWS_REGION=${AWS_REGION:-"us-west-2"}
GREENGRASS_SERVICE_ROLE=${GREENGRASS_SERVICE_ROLE:-"Greengrass_ServiceRole"}
GREENGRASS_LAMBDA_ROLE=${GREENGRASS_LAMBDA_ROLE:-Greengrass_Lambda_EmptyRole}
LAMBDA_NAME=${LAMBDA_NAME:-SimulatedTemperatureSensor}
GREENGRASS_LAMBDA_NAME=${GREENGRASS_LAMBDA_NAME:-GreengrassSimulatedTemperatureSensor}
GREENGRASS_LAMBDA_ALIAS=${GREENGRASS_LAMBDA_ALIAS:-Greengrass_Alias2}
GREENGRASS_GROUP_NAME=${GREENGRASS_GROUP_NAME:-SimulatedTemperatureSensorThing}
IOT_THING_NAME="${GREENGRASS_GROUP_NAME}_Core"
IOT_THING_POLICY_NAME="${GREENGRASS_GROUP_NAME}-policy"
GREENGRASS_SUBSCRIPTION_MQTT_TOPIC=${GREENGRASS_SUBSCRIPTION_MQTT_TOPIC:-hello/world}
GREENGRASS_SUBSCRIPTION_NAME=${GREENGRASS_SUBSCRIPTION_NAME:-GreengrassSubscription}
GREENGRASS_GROUP_NAME=${GREENGRASS_GROUP_NAME:-SimulatedTemperatureSensorThing}

# for ctrl-c catching - we don't want to leak random device definitions and 
# such in aws
trap cleanup_fatal INT

function cleanup_fatal {
  cleanup_deployments
  exit 1
}

function cleanup_deployments() {
  set +e
  echo "cleaning up greengrass deployment, group, core, subscription, and function definitions"
  aws greengrass reset-deployments --force \
    --group-id "$greengrassGroupID" > /dev/null
  aws greengrass delete-group \
    --group-id "$greengrassGroupID"
  aws greengrass delete-core-definition \
    --core-definition-id "$greengrassCoreDefinitionID"
  aws greengrass delete-subscription-definition \
    --subscription-definition-id "$greengrassSubscriptionDefinitionID"
  aws greengrass delete-function-definition \
    --function-definition-id "$greengrassFunctionDefinitionID"

  echo "cleaning up lambda function"
  aws lambda delete-function \
    --function-name "$LAMBDA_NAME"

  
  # note that aws iot won't let us delete the device until all principals have
  # been detached from it first
  echo "cleaning up iot thing and attached principals"
  for principal in $(aws iot list-thing-principals --thing-name "$IOT_THING_NAME" | jq -r '.principals | .[]'); do 
    aws iot detach-thing-principal \
      --thing-name "$IOT_THING_NAME" \
      --principal "$principal";
  done
  aws iot delete-thing \
    --thing-name "$IOT_THING_NAME"
}

# check if this aws account has a greengrass service role for the specified region
# if it doesn't exist then we create it
echo "ensuring greengrass service role for this account"
set +e
if ! aws greengrass get-service-role-for-account --region "$AWS_REGION" 2>/dev/null > /dev/null ; then
    set -e
    # note: copied from https://docs.aws.amazon.com/greengrass/latest/developerguide/service-role.html
    # create the role - getting the role ARN if successful
    roleArn=$(aws iam create-role --role-name "$GREENGRASS_SERVICE_ROLE" --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "greengrass.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' | jq -r ".Role | .Arn")

    # attach the policy role to the greengrass policy
    aws iam attach-role-policy --role-name "$GREENGRASS_SERVICE_ROLE" \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSGreengrassResourceAccessRolePolicy > /dev/null

    # associate the greengrass service role to the account
    aws greengrass associate-service-role-to-account --role-arn "$roleArn" --region "$AWS_REGION" > /dev/null
fi
set -e

echo "downloading greengrass sdk and building lambda function zip"
# download the greengrass python sdk
curl -s -o greengrass-core-python-sdk-1.3.0.tar.gz \
    https://d1onfpft10uf5o.cloudfront.net/greengrass-sdk/downloads/python/2.7/greengrass-core-python-sdk-1.3.0.tar.gz

# extract the sdk
if [ -d "$SCRIPT_DIR/greengrass-sdk" ]; then 
    rm -r "$SCRIPT_DIR/greengrass-sdk"
fi
mkdir -p "$SCRIPT_DIR/greengrass-sdk"
tar -xf greengrass-core-python-sdk-1.3.0.tar.gz -C "$SCRIPT_DIR/greengrass-sdk"

pushd "$SCRIPT_DIR/greengrass-sdk/aws_greengrass_core_sdk/sdk" > /dev/null
  # extract the specific python package from the sdk
  unzip -q python_sdk_1_3_0.zip

  # copy the source file into the sdk folder  
  cp "$SCRIPT_DIR/greengrassSimulatedTemperatureSensor.py" "$SCRIPT_DIR/greengrass-sdk/aws_greengrass_core_sdk/sdk/"

  # make a zip of the files 
  if [ -f "$SCRIPT_DIR/python_lambda.zip" ] ; then
    rm "$SCRIPT_DIR/python_lambda.zip"
  fi
  zip -q -r "$SCRIPT_DIR/python_lambda.zip" \
      greengrasssdk \
      greengrassSimulatedTemperatureSensor.py
popd > /dev/null

# create an iam role for this lambda function
set +e
echo "ensuring iam role for greengrass lambda ready"
if ! aws iam get-role --role-name "$GREENGRASS_LAMBDA_ROLE" >/dev/null ; then
  set -e
  lambdaRoleArn=$(aws iam create-role --role-name "$GREENGRASS_LAMBDA_ROLE" --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' | jq -r ".Role | .Arn")
else
  set -e
  lambdaRoleArn=$(aws iam get-role --role-name "$GREENGRASS_LAMBDA_ROLE" | jq -r ".Role | .Arn")
fi

# now attempt to upload it as a lambda function using the execution role we 
# just created/downloaded
set +e
echo "ensuring uploaded version of lambda function"
if ! aws lambda get-function --function-name "$LAMBDA_NAME" 2>/dev/null > /dev/null ; then
  set -e
  aws lambda create-function --function-name "$LAMBDA_NAME" \
    --zip-file "fileb://$SCRIPT_DIR/python_lambda.zip" \
    --handler greengrassSimulatedTemperatureSensor.function_handler \
    --runtime python2.7 \
    --role "$lambdaRoleArn" > /dev/null
fi
set -e

echo "publishing new version of lambda function"

# publish a new version of the lambda
lambdaVersion=$(aws lambda publish-version \
  --function-name "$LAMBDA_NAME" \
  --description "First version" | jq -r '.Version')

# now create an alias if it doesn't already exist for this version
set +e
echo "ensuring alias of lambda function"
if ! aws lambda get-alias --function-name "$LAMBDA_NAME" --name "$GREENGRASS_LAMBDA_ALIAS" 2>/dev/null > /dev/null ; then
  set -e
  aws lambda create-alias \
    --function-name "$LAMBDA_NAME" \
    --name "$GREENGRASS_LAMBDA_ALIAS" \
    --function-version "$lambdaVersion" > /dev/null
fi
set -e

lambdaAliasArn=$(aws lambda get-alias --function-name "$LAMBDA_NAME" --name "$GREENGRASS_LAMBDA_ALIAS" | jq -r '.AliasArn')

# create a new greengrass function definition from the lambda alias

echo "creating greengrass function definition from lambda function"

# we need to set the FunctionArn in this JSON to be the $funcArn, but
# it's awkward with all the quotes in the string, so it's easier to just 
# pipe the generic JSON into a jq command and use that instead
genericLambdaVersionJSON='{
  "DefaultConfig": {
      "Execution": {
          "IsolationMode": "GreengrassContainer"
      }
  },
  "Functions": [
      {
          "FunctionArn": "function arn",
          "FunctionConfiguration": {
              "EncodingType": "json",
              "Environment": {
                  "Execution": {
                      "RunAs": {
                          "Gid": 0,
                          "Uid": 0
                      }
                  },
                  "ResourceAccessPolicies": [],
                  "Variables": {}
              },
              "MemorySize": 16384,
              "Pinned": true,
              "Timeout": 25
          },
          "Id": "this-is-necessary-even-though-its-generated-by-aws-so-yay"
      }
  ]
}'
lambdaVersionJSON=$(echo "$genericLambdaVersionJSON" | jq -r --arg FUNCARN "$lambdaAliasArn" '.Functions[0].FunctionArn = $FUNCARN')

# create the function definition
functionIDLambdaArn=$(aws greengrass create-function-definition \
  --name "$GREENGRASS_LAMBDA_NAME" \
  --initial-version "$lambdaVersionJSON" | jq -r '"\(.Id),\(.LatestVersionArn)"')

# read in the group id and group version ID from the jq output
IFS=, read -r greengrassFunctionDefinitionID ggLambdaArn <<< "$functionIDLambdaArn";

echo "creating iot thing and certificates"

# make an aws thing to associated with the greengrass core
thingArn=$(aws iot create-thing --thing-name "$IOT_THING_NAME" | jq -r '.thingArn')

# make some certificates for this group
certArnID=$(aws iot create-keys-and-certificate \
  --set-as-active \
  --certificate-pem-outfile "$SCRIPT_DIR/cert.pem" \
  --public-key-outfile "$SCRIPT_DIR/public-key.pem" \
  --private-key-outfile "$SCRIPT_DIR/private-key.pem" | jq -r '"\(.certificateArn),\(.certificateId)"')

# read in the cert arn and cert ID to use later
IFS=, read -r certArn certId <<< "$certArnID";

if [ -d zip ]; then
    rm -rf zip
fi
mkdir -p "$SCRIPT_DIR/zip/certs"
mkdir -p "$SCRIPT_DIR/zip/config"

# rename the certificate files to be the first 10 characters of the certId
shortCertId=$(echo "$certId" |cut -c1-10)
mv "$SCRIPT_DIR/cert.pem" "$SCRIPT_DIR/zip/certs/$shortCertId.cert.pem"
mv "$SCRIPT_DIR/public-key.pem" "$SCRIPT_DIR/zip/certs/$shortCertId.public.key"
mv "$SCRIPT_DIR/private-key.pem" "$SCRIPT_DIR/zip/certs/$shortCertId.private.key"

echo "attaching certificates to iot thing"

# attach the certificates (also called a "thing principal" to the thing)
aws iot attach-thing-principal \
  --thing-name "$IOT_THING_NAME" \
  --principal "$certArn"

echo "ensuring iot thing policy attached to certificates"

# create a policy which we will attach to the ceritficate 
set +e
if ! aws iot get-policy --policy-name "$IOT_THING_POLICY_NAME" >/dev/null ; then
  set -e
  aws iot create-policy --policy-name "$IOT_THING_POLICY_NAME" --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:Publish",
        "iot:Subscribe",
        "iot:Connect",
        "iot:Receive"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:GetThingShadow",
        "iot:UpdateThingShadow",
        "iot:DeleteThingShadow"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "greengrass:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}'
fi
set -e

# attach the policy to the certificate
aws iot attach-policy \
  --policy-name "$IOT_THING_POLICY_NAME" \
  --target "$certArn"

echo "creating greengrass core"

# we need to set the CertificateArn/ThingArn in this JSON to be the $certArn,
# but it's awkward with all the quotes in the string, so it's easier to just 
# pipe the generic JSON into a jq command and use that instead
genericCoreVersionJSON='{
  "Cores": [
    {
      "CertificateArn": "certificate arn",
      "Id": "this-is-necessary-even-though-its-generated-by-aws-so-yay",
      "SyncShadow": true,
      "ThingArn": "thing"
    }
  ]
}
'
coreVerionsJSON=$(echo "$genericCoreVersionJSON" | \
  jq -r --arg CERTARN "$certArn" \
  --arg THINGARN "$thingArn" \
  '.Cores[0].CertificateArn = $CERTARN | .Cores[0].ThingArn = $THINGARN')

# create a new core with this certificate
coreIdVersionArn=$(aws greengrass create-core-definition \
  --name "$IOT_THING_NAME" \
  --initial-version "$coreVerionsJSON" | jq -r '"\(.Id),\(.LatestVersionArn)"')

# read in the core ID and the version Arn from the jq output
IFS=, read -r greengrassCoreDefinitionID coreVersionArn <<< "$coreIdVersionArn";

echo "creating greengrass subscription"

genericSubVersionJSON='{
    "Subscriptions": [
        {
            "Id": "this-is-necessary-even-though-its-generated-by-aws-so-yay",
            "Source": "function",
            "Subject": "mqtt subject",
            "Target": "cloud"
        }
    ]
}
'
subVersionJSON=$(echo "$genericSubVersionJSON" | \
  jq -r --arg SUBJECT "$GREENGRASS_SUBSCRIPTION_MQTT_TOPIC" \
  --arg SOURCE "$lambdaAliasArn" \
  '.Subscriptions[0].Subject = $SUBJECT | .Subscriptions[0].Source = $SOURCE')


# now create a subscription definition
subscriptionIdVersionArn=$(aws greengrass create-subscription-definition \
  --name "$GREENGRASS_SUBSCRIPTION_NAME" \
  --initial-version "$subVersionJSON" | jq -r '"\(.Id),\(.LatestVersionArn)"')

# read in the subscription ID and the version Arn from the jq output
IFS=, read -r greengrassSubscriptionDefinitionID subscriptionVersionArn <<< "$subscriptionIdVersionArn";

echo "creating greengrass group"

genericGroupVersionJSON='{
  "CoreDefinitionVersionArn": "",
  "FunctionDefinitionVersionArn": "",
  "SubscriptionDefinitionVersionArn": ""
}'

# TODO: when AWS's api supports it, it would be nice to be able to set this
# in the group, like you can in the group.json or through the web console
# settings
# '"Lambdas": {
#     "DefaultConfig": {
#       "Execution": {
#         "IsolationMode": "GreengrassContainer",
#         "RunAs": {
#           "Uid": 0,
#           "Gid": 0
#         }
#       }
#     }
#   }'

groupVersionJSON=$(echo "$genericGroupVersionJSON" | jq -r \
  --arg SUBSCRIPTIONARN "$subscriptionVersionArn"   \
  --arg COREARN "$coreVersionArn"\
  --arg FUNCARN "$ggLambdaArn" \
  '.CoreDefinitionVersionArn = $COREARN | 
  .SubscriptionDefinitionVersionArn = $SUBSCRIPTIONARN |
  .FunctionDefinitionVersionArn = $FUNCARN')

# now create a new group
groupIDVersion=$(aws greengrass create-group \
  --name "$GREENGRASS_GROUP_NAME" \
  --initial-version "$groupVersionJSON" | jq -r '"\(.Id),\(.LatestVersion)"')

# read in the group id and group version ID from the jq output
IFS=, read -r greengrassGroupID greengrassGroupVersionID <<< "$groupIDVersion";

echo "creating greengrass tar archive for snap set"

# process the config.json to specify the keys we created and downloaded for 
# this group - note that we default to using the greengrass-ats endpoint
mkdir -p zip/config
jq -r \
  --arg PRIVATEKEY "$shortCertId.private.key" \
  --arg PUBLICCERT "$shortCertId.cert.pem" \
  --arg GGHOST "greengrass-ats.iot.$AWS_REGION.amazonaws.com" \
  --arg THINGARN "$thingArn" \
  --arg IOTHOST "$(aws iot describe-endpoint --endpoint-type iot:Data-ATS | jq -r .endpointAddress)" \
  '
  .crypto.principals.SecretsManager.privateKeyPath = $PRIVATEKEY | 
  .crypto.principals.IoTCertificate.privateKeyPath = $PRIVATEKEY | 
  .crypto.principals.IoTCertificate.certificatePath = $PUBLICCERT | 
  .coreThing.certPath = $PUBLICCERT |
  .coreThing.keyPath = $PRIVATEKEY |
  .coreThing.thingArn = $THINGARN |
  .coreThing.iotHost = $IOTHOST | 
  .coreThing.ggHost = $GGHOST
  ' < config.json.in > zip/config/config.json

# create the tar archive with the config files and the certificates for this 
# group/thing
pushd "$SCRIPT_DIR/zip" > /dev/null
tar -cf certs.tgz certs/ config/
mv certs.tgz ..
popd > /dev/null

echo "installing snap + ggc_user/ggc_group"

# install greengrass
snap remove aws-iot-greengrass
# TODO: when the aws cli supports setting the default uid/gid for a group
# then we can set them to run as root and drop this
set +e
UBUNTU_CORE=$(grep "snap_core=" /proc/cmdline | grep "snap_kernel=")
if [ -n "$UBUNTU_CORE" ]; then
  sudo adduser --extrausers --system ggc_user >/dev/null 2>/dev/null
  sudo addgroup --extrausers --system ggc_group >/dev/null 2>/dev/null
else 
  sudo adduser --system ggc_user >/dev/null 2>/dev/null
  sudo addgroup --system ggc_group >/dev/null 2>/dev/null
fi
set -e
snap install aws-iot-greengrass

echo "seeding certificate and configuration files to the snap"

# provide greengrass with these certificates
snap set aws-iot-greengrass gg-certs="$(pwd)/certs.tgz"

# TODO: implement a more robust check to see that the greengrassd service 
# is successfully started from the previous snap set command and that it 
# keeps running
# for now let's just sleep
sleep 30

echo "deploying greengrass group to the snap"

# deploy the group so that we can start things running
greengrassDeploymentID=$(aws greengrass create-deployment \
  --group-id "$greengrassGroupID" \
  --group-version-id "$greengrassGroupVersionID" \
  --deployment-type NewDeployment | jq -r '.DeploymentId')

echo "waiting for deployment to succeed"

# wait for the deployment to be successful, timing out after 5 minutes (300 seconds)
export num_tries=0
export MAX_DEPLOYMENT_TRIES=30
deploymentNotDone=true
while [ "$deploymentNotDone" = "true" ]; do
  deploymentStatus=$(aws greengrass get-deployment-status --group-id "$greengrassGroupID" --deployment-id "$greengrassDeploymentID" | jq -r .DeploymentStatus)
  case "$deploymentStatus" in 
    "Success")
      deploymentNotDone=false
      break
      ;;
    "InProgress"|"Building")
      ;;
    *)
      echo "invalid status for deployment: $deploymentStatus"
      cleanup_fatal
  esac
  num_tries=$((num_tries+1))
  if (( num_tries > MAX_DEPLOYMENT_TRIES )); then
      echo "max tries attempting to check for deployment status"
      echo "failed to get a successful deployment"
      cleanup_fatal
  fi
  sleep 10
done

echo "waiting for lambda to start running"

# now that the deployment is complete, we have to wait for the lambda to start
# up, however this is difficult to test for, so instead just wait for a 
# somewhat reasonable amount of time - 60 seconds - and then check on the 
# lambda
sleep 60

# now the deployment is complete, we need to check that messages are actually
# being sent "across the wire" however that's actually non-trivial to do from
# the command line, as we need to generate yet more certificates and things in
# order to connect to the MQTT broker to actually receive real messages, since
# if we just tried to use the same certs we generated for this aws group, aws
# would kick off the MQTT client in greengrass so that this one could connect,
# and then that one would immediately attempt to re-connect, kicking our
# subscriber client off, resulting in an infinite loop which we don't want

# instead, we will just make sure that the lambda function ran and created 
# some log files in the correct location in $SNAP_DATA and also that there is
# a process that is running the lambda python file on the system

lambdaLogFile="/var/snap/aws-iot-greengrass/current/ggc-writable/var/log/user/$AWS_REGION/$(aws sts get-caller-identity | jq -r '.Account')/SimulatedTemperatureSensor.log"
if sudo [ ! -f "$lambdaLogFile" ]; then
  echo "no logs for the lambda process"
  cleanup_fatal
fi

set +e
lambdaPID=$(pgrep -f greengrassSimulatedTemperatureSensor)
set -e
if [ -z "$lambdaPID" ]; then
  echo "couldn't find the lambda process"
  cleanup_fatal
fi

echo "test successful - cleaning up"

# cleanup the deployment we created
cleanup_deployments
