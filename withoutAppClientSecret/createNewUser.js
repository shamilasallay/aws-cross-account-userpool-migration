
const AWS = require('aws-sdk')

const stsclient = new AWS.STS()

const destinationAccountRoleARN = 'LAMBDAROLEARN';
const destinationAccountRole = 'LAMBDAROLE';
const destinationAccountUserPoolId = 'USERPOOLID';

async function createNewUser(email, password) {

    const paramsAssumeRole = {
        RoleArn: destinationAccountRoleARN,
        RoleSessionName: destinationAccountRole
    };
    
    const { Credentials } = await stsclient.assumeRole(paramsAssumeRole).promise()

    const tempCredentialsObj = {
        accessKeyId: Credentials.AccessKeyId,
        secretAccessKey: Credentials.SecretAccessKey,
        sessionToken: Credentials.SessionToken
    }

    AWS.config.update({ credentials: tempCredentialsObj });

    const cognitoidpServiceProvider = new AWS.CognitoIdentityServiceProvider({ region: 'eu-west-2' });
    //Create the user with AdminCreateUser()
    const params = {
        UserPoolId: destinationAccountUserPoolId,
        Username: email,
        MessageAction: 'SUPPRESS', //suppress the sending of an invitation to the user
        TemporaryPassword: password,
        UserAttributes: [
            { Name: 'email', Value: email }, //using sign-in with email, so username is email
            { Name: 'email_verified', Value: 'true' }
        ]
    };
    const createUserRes = await cognitoidpServiceProvider.adminCreateUser(params).promise();
    if (createUserRes.User.UserStatus == 'FORCE_CHANGE_PASSWORD') {

        const params = {
            Password: password, /* required */
            UserPoolId: destinationAccountUserPoolId, /* required */
            Username: createUserRes.User.Username, /* required */
            Permanent: true
        };
        await cognitoidpServiceProvider.adminSetUserPassword(params).promise();
        return
    }

}
module.exports = createNewUser;