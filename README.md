# keycloak-lambda-authorizer
Lambda function to validate keycloak JWT 

## Instructions

* `npm install`
* Get the public key from the Keycloak server: https://your.server/auth/realms/your-realm/protocol/openid-connect/certs
  * Note: you have to use one of the JSON objects from the "keys" array
* `echo "JWT_SECRET=your-secret" > .env` to pass in the secret signing key or the public key into a `.env` file in this project directory.
* Zip up the content in this project and upload it to a newly created or existing AWS Lambda
* Set the lambda as the API Gateway Authorizer
  * Lambda Event Payload : **Token**
  * Token Source: **Authorization** (or whatever other source you are using in your application)