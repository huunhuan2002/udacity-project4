// TODO: Once your application is deployed, copy an API id here so that the frontend could interact with it
const apiId = '...'
export const apiEndpoint = `https://${apiId}.execute-api.us-east-1.amazonaws.com/dev`

export const authConfig = {
  domain: 'nhuanlh.us.auth0.com',
  clientId: 'fyunmZdiGn4ZRveVI3PAhFGF8e2D2pqZ',
  callbackUrl: 'http://localhost:3000/callback'
}
