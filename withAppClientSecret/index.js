const AWS = require('aws-sdk')
const stsclient = new AWS.STS()

const sourceAccountRoleARN = 'ROLEARN';
const sourceAccountRegion = 'REGION';
const sourceAccountUserPoolId = 'USERPOOLID';
const sourceAccountClientId = 'APPCLIENTID';
const sourceAccountClientSecret = 'APPCLIENTSECERT';
let cognitoidpclient;

exports.handler = async (event, context, callback) => {
    
    let user;
    
    const paramsAssumeRole = {
      RoleArn: sourceAccountRoleARN,
      RoleSessionName: 'CrossAccountCognitoMigration'
    };
    const {Credentials} = await stsclient.assumeRole(paramsAssumeRole).promise()
    
    const tempCredentialsObj = {
            accessKeyId: Credentials.AccessKeyId,
            secretAccessKey: Credentials.SecretAccessKey,
            sessionToken: Credentials.SessionToken
    }
  
    AWS.config.update({credentials: tempCredentialsObj});
    cognitoidpclient = new AWS.CognitoIdentityServiceProvider({region: sourceAccountRegion});
    
    if (event.triggerSource == "UserMigration_Authentication") {
        // authenticate the user with existing user pool
        user = await authenticateUser(event.userName, event.request.password);
        
        let userAttributes = {};
        
        if (user.Username) {
            user.UserAttributes.forEach(attribute => {
                if(attribute.Name == "sub"){return;}
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
        // Lookup the user in existing user pool
        user = await getUserPoolUser(event.userName);
        
        if (user.Username) {
            
            let userAttributes = {};
            
            user.UserAttributes.forEach(attribute => {
                if(attribute.Name == "sub"){return;}
                userAttributes[attribute.Name] = attribute.Value;
            })
            
            /**
             * email_verified or phone_number_verified must be set to true
             * to enable password-reset code to be sent to user
             * If the attribute is not already set in the source user pool,
             * uncomment the following line as an example to set email as verified 
                
                userAttributes['email_verified'] = "true";
            */
            
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
    let rez =""
    const paramGetuser = {
        UserPoolId: sourceAccountUserPoolId,
        Username: username
    }
    
    rez = await cognitoidpclient.adminGetUser(paramGetuser).promise()
    return rez
}

async function authenticateUser(username, password) {
    let rez =""
	
	const message = username + sourceAccountClientId
    const secrethash = require('crypto').createHmac('sha256',sourceAccountClientSecret).update(message).digest('base64');
	
    const paramInitiateAuth = {
            AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
            ClientId: sourceAccountClientId,
            UserPoolId: sourceAccountUserPoolId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
				SECRET_HASH: secrethash
            }
    }
    
    const authrez = await cognitoidpclient.adminInitiateAuth(paramInitiateAuth).promise()
    if (authrez.hasOwnProperty('AuthenticationResult')) {
        rez = getUserPoolUser(username)
    }
    return rez
}