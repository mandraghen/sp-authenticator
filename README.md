# sp-authenticator
This project exposes an API to sign the requests to be authenticated by satispay: https://developers.satispay.com/reference#introduction
It creates the required headers that are returned in the response.
It calls the signature tester API on satispay that verifies the signature is correct.

Client id and private key are provided as configurations inside the project
