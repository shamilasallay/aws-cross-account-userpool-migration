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