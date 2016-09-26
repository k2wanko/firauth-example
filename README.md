# Firebase Auth with AppEngine example

## Setup

require `gcloud`, `AppEngine/Go SDK`

1. Create Firebase project
    1. Create Service Account (name: dev-app)
    2. generate p12 file
    3. `$ cat /path/to/key.p12 | openssl pkcs12 -nodes -nocerts -passin pass:notasecret | openssl rsa > backend/service_account.pem`
2. Create Slack App
    1. Set Redirect URL `https://<projectID>.appspot.com/auth/handler`
    2. `$ export SLACK_CLIENT_ID=<slack client id>`
    3. `$ export SLACK_CLIENT_SECRET=<slack client secret>`
3. Update Files. replace `k2lab-firauth` to your projectID
    - .firebaserc
    - storage.rules
4. `$ export GOOGLE_CLOUD_PROJECT=<projectID>`
5. `$ gcloud config set project $GOOGLE_CLOUD_PROJECT`
6. `$ export SESSION_SECRET=$(base64 /dev/random| head -c 32)`
7. `$ npm run export`

## Dev server

`$ npm run serve`
access to http://localhost:8080/
