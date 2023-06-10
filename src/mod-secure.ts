import crypto from 'crypto'
import * as bcrypt from 'bcryptjs'
import { v4 as uuid } from 'uuid'
import { ISecure, ConfigType } from 'ninsho-base'

type DeepPartial<T> = { [K in keyof T]?: T[K] extends Record<string, unknown>
  ? DeepPartial<T[K]>
  : T[K] }

export default class ModSecure extends ISecure {

  internal_version = '0.0'

  /* istanbul ignore next */
  public static init(options: DeepPartial<ConfigType> = {}): ModSecure {
    const instance = new ModSecure()
    const defaultOP: ConfigType = {
      secretKey: 'default_secret_key',
      bcrypt: {
        bcrypt_salt_rounds: 10,
      },
      crypt: {
        crypto_algorithm: 'sha256',
      },
      override: {
        toHashForPassword: null,
        checkHashPassword: null,
        createUUID: null,
        toHashForSessionToken: null,
        createSessionTokenWithHash: null
      }
    }
    instance.config = mergeDeep(defaultOP, options) as any

    if (instance.config.secretKey === 'default_secret_key'
    || !instance.config.secretKey
    ) /* istanbul ignore next */ {
      console.log(innerError.NoSetSecretKey)
    }
    
    defaultOP.override.toHashForPassword = defaultOP.override.toHashForPassword || (
      (pass: string) => bcrypt.hashSync(pass, defaultOP.bcrypt.bcrypt_salt_rounds)
    )

    defaultOP.override.checkHashPassword = defaultOP.override.checkHashPassword || (
      (pass: string, hash: string): boolean => {
        return bcrypt.compareSync(pass, hash)
      }
    )

    defaultOP.override.createUUID = defaultOP.override.createUUID || (
      () => uuid()
    )

    defaultOP.override.toHashForSessionToken = defaultOP.override.toHashForSessionToken || (
      (userToken: string): string => {
        return crypto.createHmac(defaultOP.crypt.crypto_algorithm, defaultOP.secretKey)
          .update(userToken)
          .digest('hex')
      }
    )

    defaultOP.override.createSessionTokenWithHash = defaultOP.override.createSessionTokenWithHash || (
      (): {
        sessionToken: string
        hashToken: string
      } => {
        const token = defaultOP.override.createUUID!()
        return {
          sessionToken: token,
          hashToken: defaultOP.override.toHashForSessionToken!(token)
        }
      }
    )

    return instance
  }

  public toHashForPassword(pass: string): string {
    return this.config.override.toHashForPassword!(pass)
  }

  public checkHashPassword(pass: string, hash: string): boolean {
    return this.config.override.checkHashPassword!(pass, hash)
  }

  public createUUID(): string {
    return this.config.override.createUUID!()
  }

  public toHashForSessionToken(userToken: string): string {
    return this.config.override.toHashForSessionToken!(userToken)
  }

  public createSessionTokenWithHash(): {
    sessionToken: string
    hashToken: string
  } {
    return this.config.override.createSessionTokenWithHash!()
  }

}

const innerError = {
  NoSetSecretKey: `\x1b[31mWARNING                             
| Secret key not updated, your system's vulnerable to threats.
| Update your secret key now, ensure system safety and integrity.
| The secret key can be changed by setting options during initialization.
| SecureCrypt.init({ secretKey: '....' })\x1b[0m`
}

const mergeDeep = <T>(target: T, source: T): T => {
  for (const key in source) {
    if (typeof source[key as keyof T] === 'object') {
      // if (typeof target[key as keyof T] !== 'object') {
      //   target[key as keyof T] = {} as T[Extract<keyof T, string>]
      // }
      mergeDeep(
        target[key as keyof T] as T[Extract<keyof T, string>],
        source[key as keyof T] as T[Extract<keyof T, string>]
      )
    } else {
      target[key as keyof T] = source[key as keyof T]
    }
  }
  return target
}