import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const authCert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJDF1DkHCZJ1TsMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1hMGVvOXNqai51cy5hdXRoMC5jb20wHhcNMjIwNjEyMTAzNzM2WhcN
MzYwMjE5MTAzNzM2WjAkMSIwIAYDVQQDExlkZXYtYTBlbzlzamoudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/J/Y1Ha3WkMv27P
0b34y3rvkCPRXem8caAeih/hiRARirvQGc0r5x2G0MIYevUtJq2B8pYi+Kh/3SuM
PWmePh9s0VvMjjeC3P1VyISzGs39v+hzA0A9SWROmzalF5hiVPhoQoT+UbDaPq65
i0xVKOSrXc71SbZe7q705qSBK/ZNVYo4xeLjiONbgQYZQp2kiz+7/zDepFTLKUTZ
hiKnyNQu5r9gQpRrqjp39ZblvtbvWVOyuBV0soIkT5IHKyUShFieXFKLfYaPvWTO
mhAXgxcb62Fz8VcMdB7vE7tUjeTDlemzXRHJ3yKljIfgRqhzMCSw+4G7K7k0wfci
mRCkXQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQuoUjhMFJ7
WNCtLHAngLZ8J7gZUTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AHWz+FJDviKqY6QLKBne/rTT3lq353AFua8k/Aslh/1xz3Hp+MnbtqvDn6GETeDd
e1Kf2lIkPlJjnBuvi0OkyyyKtfDeZl3KXoMU/Y5C3spdtjeveUAwgrrx9aCjgfVG
dcV7+esWfnx0+APJlhHlxHsK6RSuFDB3gfOpczb17DDJcL6QRrU6lTCv2q7nX0H7
AJ2J2j283LwS4s4P9eU5eNLLs64zw59xmtCT4dB9GMxk2o97CQOBn/Q+zeGpZsk6
rxqd24YWrog78s23aAB8siO7Rxb1I4PDHCEU8UVOicfZIT3sf+Cmb0TzIjOWwr38
yFj8QPzULJ7iTJjcuzNAo/M=
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
