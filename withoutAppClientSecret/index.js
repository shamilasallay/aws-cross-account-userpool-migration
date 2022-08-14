/*Basic Scenarios Summary:

The User Migration Lambda function will assume a role in the old user pool account to authenticate users. 
The expanded summary of the steps based on this approach are:

        1.The user tries to authenticate or reset password on the new user pool
        2.User Migration Lambda function is triggered if the user is not found
        3.User Migration Lambda function assumes a role in the source user pool account
        4.User Migration Lambda function uses the cross-account assumed role to authenticate the user and get the user's attributes
        5.The valid user is migrated

Throughout this guide, I will use the terms below:
"old user pool" - the existing user pool that users are migrating from, which is also the source user pool in the AWS account 111111111111
"new user pool" - the new user pool that users will be migrating to, which is also the destination user pool in the AWS account 222222222222

Configuration Steps - Old User pool account 111111111111

Step 1: Enable username password auth for admin APIs for authentication (ALLOW_ADMIN_USER_PASSWORD_AUTH). This makes programmatic user authentication easier. This option should be disabled after user migration to enforce the secure SRP flow which does not send passwords over the network.

    1.Sign in to the Cognito User Pool console and on the left navigation menu, click on "App Clients".
    2.On the App clients page, click on "Show Details" button of the app client that will be used for authenticating users
    3.Ensure that the option "Enable username password auth for admin APIs for authentication (ALLOW_ADMIN_USER_PASSWORD_AUTH)" is selected
    4.Save the App client changes if any was made.

Alternatively, you can use the CLI command:

$ aws cognito-idp update-user-pool-client --user-pool-id <value> --client-id <value> --explicit-auth-flows ALLOW_ADMIN_USER_PASSWORD_AUTH ALLOW_CUSTOM_AUTH ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH


Step 2: Create a role that can be assumed to authenticate existing users.

    1.Sign in to the IAM console and on the left navigation menu, choose Roles and then choose Create role.
    2.Choose the "Another AWS account" role type.
    3.For Account ID, type the new user pool account ID. In the context of this guide, this will be 222222222222. 
    4.Choose the "next" button through the next pages till you get to the Review page. We will create an inline permissions policy for the role in a later step.
    5.On the Review page, add a Role name. For this guide, the we will use "CognitoCrossAccountMigrationRole"
    6.Choose "Create role"
    7.Once the role is created, grant the role permission to make the API calls - adminInitiateAuth and adminGetUser. To do this, add an inline policy to this role with the following policy:

    {    
       "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PermissionForUserPoolActions",
                "Effect": "Allow",
                "Action": [
                    "cognito-idp:AdminInitiateAuth",
                    "cognito-idp:AdminGetUser"
                ],
                "Resource": "*"
            }
        ]
    }


    For simplicity, the policy allows the API call to all resources. You may limit the resource to the old user pool by specifying the old user pool ARN. Optionally, you may also limit the role's trust policy principal to only the new user pool's execution role ARN.


Configuration Steps - New User pool account 222222222222

Step 1: Enable username password based authentication (ALLOW_USER_PASSWORD_AUTH). This step is required to pass the user's password to the triggered Lambda function so that the user's authentication credentials can be used to authenticate against the old user directory which in this case is the old user pool in account 111111111111.
After migration, it is recommended to disable the ALLOW_USER_PASSWORD_AUTH option so that the only option of authenticating user will be secure SRP flow which does not send passwords over the network..

    1.Sign in to the Cognito User Pool console and on the left navigation menu, click on "App Clients".
    2.On the App clients page, click on "Show Details" button of the app client that will be used for authenticating users
    3.Ensure that the option "Enable username password based authentication (ALLOW_USER_PASSWORD_AUTH)" is selected
    4.Save the App client changes if any was made.

Alternatively, you can use the CLI command:

$ aws cognito-idp update-user-pool-client --user-pool-id <value> --client-id <value> --explicit-auth-flows ALLOW_CUSTOM_AUTH ALLOW_USER_PASSWORD_AUTH ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH


Step 2: Create the User Migration Lambda function that will assume a role in the old user pool account and migrate the user based on the user attributes returned of the user.

    1.Sign in to the Lambda console and on the left navigation menu, click on "Functions"
    2.Click on "Create Function" button to create a new function
    3.On the create function page, Select "Author from scratch" and under the Basic information section, give it a function name and choose Node.js 14.x for the Runtime. Lets assume that the function name is "migrationLambdaFunction". Then click on "Create function" button.
    4.On the "Configuration" tab of the Lambda function, replace the default function code with the following:

    In summary, the code expects a username and password for the UserMigration_Authentication trigger source or just a username for the UserMigration_ForgotPassword trigger source. A valid user's attributes are returned. These attributes are used to migrate the user.

    Note: If your app client has a secret, please use the attached Lambda function named "migrationLambdaFunctionWithSecret.txt" instead.
**/

const AWS = require('aws-sdk')
const stsclient = new AWS.STS()

const sourceAccountRoleARN = 'ROLEARN';
const sourceAccountRegion = 'REGION';
const sourceAccountUserPoolId = 'USERPOOLID';
const sourceAccountClientId = 'APPCLIENTID';
let cognitoidpclient;

exports.handler = async (event, context, callback) => {
    console.log(event)

    let user;

    var paramsAssumeRole = {
        RoleArn: sourceAccountRoleARN,
        RoleSessionName: 'CrossAccountCognitoMigration'
    };
    const { Credentials } = await stsclient.assumeRole(paramsAssumeRole).promise()

    const tempCredentialsObj = {
        accessKeyId: Credentials.AccessKeyId,
        secretAccessKey: Credentials.SecretAccessKey,
        sessionToken: Credentials.SessionToken
    }

    AWS.config.update({ credentials: tempCredentialsObj });
    cognitoidpclient = new AWS.CognitoIdentityServiceProvider({ region: sourceAccountRegion });

    if (event.triggerSource == "UserMigration_Authentication") {
        // authenticate the user with your existing user directory service
        user = await authenticateUser(event.userName, event.request.password);

        let userAttributes = {};

        if (user.Username) {
            user.UserAttributes.forEach(attribute => {
                if (attribute.Name == "sub") { return; }
                userAttributes[attribute.Name] = attribute.Value;
            })

            event.response.userAttributes = userAttributes;

            event.response.finalUserStatus = "CONFIRMED";
            event.response.messageAction = "SUPPRESS";
            context.succeed(event);
        } else {
            // Return error to Amazon Cognito
            callback("Bad password");
        }
    } else if (event.triggerSource == "UserMigration_ForgotPassword") {
        // Lookup the user in your existing user directory service
        user = await getUserPoolUser(event.userName);

        if (user.Username) {

            let userAttributes = {};

            user.UserAttributes.forEach(attribute => {
                if (attribute.Name == "sub") { return; }
                userAttributes[attribute.Name] = attribute.Value;
            })

            //***Note:*** email_verified or phone_number_verified must be set to true 
            //to enable password-reset code to be sent to user
            //If the attribute is not already set in the source user pool,
            //you can uncomment the following line as an example to set email as verified 

            //userAttributes['email_verified'] = "true";

            event.response.userAttributes = userAttributes;

            event.response.messageAction = "SUPPRESS"
            context.succeed(event)
        } else {
            // Return error to Amazon Cognito
            callback("Bad password")
        }
    } else {
        // Return error to Amazon Cognito
        callback("Bad triggerSource " + event.triggerSource)
    }
}

async function getUserPoolUser(username) {
    let res = ""
    const paramGetuser = {
        UserPoolId: sourceAccountUserPoolId,
        Username: username
    }

    res = await cognitoidpclient.adminGetUser(paramGetuser).promise()
    return res
}

async function authenticateUser(username, password) {
    let res = ""
    const paramInitiateAuth = {
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        ClientId: sourceAccountClientId,
        UserPoolId: sourceAccountUserPoolId,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password
        }
    }

    const authres = await cognitoidpclient.adminInitiateAuth(paramInitiateAuth).promise()
    if (authres.hasOwnProperty('AuthenticationResult')) {
        res = getUserPoolUser(username)
    }
    return res
}

/*
    Kindly replace the following values in the first few lines of the code with your valid values:

    'ROLEARN' - Old user pool account role ARN that will be assumed which we setup earlier. For example arn:aws:iam::111111111111:role/CognitoCrossAccountMigrationRole
    'REGION' - Old user pool region. For example 'us-east-1'
    'USERPOOLID' - Old user pool id. For example 'us-east-1_Example'
    'APPCLIENTID' - Old user pool app client id. For example 't8pkkgexmapleq1t1vexampleer'

    5.Click on "Deploy"
    6.Grant the Lambda function execution role permission to assume the role in the old user pool account. The lambda execution role can be found by navigating to the "Permissions" tab (In new console: Configuration > Permissions). The role name is found under the Execution role section of the permissions tab. Click on the role name to go straight to the role settings on the IAM console and add an inline policy to this role with the following policy:


{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PermissionToAssumeRole",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::111111111111:role/CognitoCrossAccountMigrationRole"
        }
    ]
}


Ensure that the resource in the policy is replaced with the correct role ARN with the right AWS account ID based on your own setup.


Step 3: Set the Lambda function in the User Migration trigger option

    1.Sign in to the Cognito User Pool console and on the left navigation menu, click on "Triggers".
    2.On the Triggers page, set "User Migration"  to the Lambda function that was just created in the new user pool account. In our example, it was named migrationLambdaFunction.
    Note: If the created lambda function is not found, ensure that you created the lambda function in the same region as the new user pool. You may also want to reload the Triggers page.
    3.Save Changes.


Step 4: Test Migration using the hosted UI

    1.On the left navigation menu, click on "App client settings"
    2.On the app client setting page, click on "Launch Hosted UI" of your app client to open the Cognito Hosted UI.
    3.Test authentication with a valid user that exists in the old user pool
    4.Test the forget password migration by clicking the "Forgot your password?" link on the Hosted UI.


References

[1] Importing Users into a User Pool - https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-import-users.html
[2] Migrate User Lambda Trigger - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html