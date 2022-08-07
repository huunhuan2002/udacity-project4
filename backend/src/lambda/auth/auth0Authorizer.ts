import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const authCert = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIJNHWaRqts1fEnMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNV
BAMTFG5odWFubGgudXMuYXV0aDAuY29tMB4XDTIyMDQyMTEyMTc0MFoXDTM1MTIy
OTEyMTc0MFowHzEdMBsGA1UEAxMUbmh1YW5saC51cy5hdXRoMC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/kVpis1To0qXLqjlYlcl7EGFkK4u9
gQ3smBCyurxXQ6Li+tCMeovpZtaylyF0F7jV52Fs3dIS13ryWJHk77ljcCJtwfnZ
HJ7nqms0j7m1JOd7rBn7k2jZCzBajaLtc/6CLfoxj659no2Zfe8f/abwuDoJsJh/
YkSoPo2IOdwTwm/sFb/CHkk0B2LoafxYwku0zhoc2Y/kpKWOkpmr0S+lZfo94NcN
U5YeZDQvmdkixU2C7CgR0Yfbu+TdYH4KM3DqLNmsr+EDS2V/bGZdcY+1b9ZUtnDI
gD4PSdcWF2koFGumWy6ccHzZYttWJgHRisczHxdXI9AOyTzBzlnZdJ2ZAgMBAAGj
QjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPYRuask95UWzgCSmibuf5Hp
o50VMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAH42r6UD1x3xc
GFUjwiwT5X/SUynU96cbPN0KGwyVhRU/08+QTLdpqeLtLbcRpcprdIBPUmFX4Eh8
eVwpgLJIAJstFCCVuKQTa2VFs0W55r6fRHJ3C+9+7RV2yGOOhJnFn7feiJW/9/YI
Nkp7bSJN639hedfKyu3vCvnT4H1W8hIMRFYpN3q6d2Onr88X2eTAVinkPRXaAz4G
yKJO5tWe2Ue6pQUwGC/Ij0J26AaVHMlDhUWNpstpIhluStGoJ6CgIfT0N3VywU1n
M3bEjanq+coJUbC4mvBEY+xFsLWMhueiR1hfle1mp3khLbMOPki2WE9CsGBaeeP3
Kt5Bzjb93A==
-----END CERTIFICATE-----
`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)  
  return verify(token, authCert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')
  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')
  const split = authHeader.split(' ')
  const token = split[1]
  return token
}
