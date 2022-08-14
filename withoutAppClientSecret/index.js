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