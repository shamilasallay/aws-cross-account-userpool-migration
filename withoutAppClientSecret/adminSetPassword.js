const AWS = require('aws-sdk')

const stsclient = new AWS.STS()

function adminSetPassword(email, password) {
    return new Promise(async (resolve, reject) => {
        try {

            const { DESTINATION_ROLE_ARN, DESTINATION_ROLE_NAME, DESTINATION_USERPOOL_ID } = process.env;

            /**
               set aws configuration to new user pool account by using current lambda role 
               to get  aws access key and secret
            **/
            let paramsAssumeRole = {
                RoleArn: DESTINATION_ROLE_ARN,
                RoleSessionName: DESTINATION_ROLE_NAME
            };
            const { Credentials } = await stsclient.assumeRole(paramsAssumeRole).promise();

            const tempCredentialsObj = {
                accessKeyId: Credentials.AccessKeyId,
                secretAccessKey: Credentials.SecretAccessKey,
                sessionToken: Credentials.SessionToken
            }

            AWS.config.update({ credentials: tempCredentialsObj });

            const cognitoidpServiceProvider = new AWS.CognitoIdentityServiceProvider({ region: 'eu-west-2' });

            const params = {
                Password: password,
                UserPoolId: DESTINATION_USERPOOL_ID,
                Username: email,
                Permanent: true
            };

            //set password in new userpool
            await cognitoidpServiceProvider.adminSetUserPassword(params).promise();

            resolve();
        }
        catch (err) {
            reject({
                message: `something went wrong when updating password `,
                error: err
            })
        }
    })


}


module.exports = adminSetPassword;