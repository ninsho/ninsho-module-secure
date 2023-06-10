import ModSecure from "../mod-secure"

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

describe('module-secure', () => {

  it('SCS: toHashForPassword', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    expect(module.toHashForPassword('example') != null).toEqual(true)
  })

  it('SCS: checkHashPassword', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    const res = module.checkHashPassword("test1234", "$2a$10$2KttwB3orSyRJ0zDbBL3g.ZVlsbTioT45POJDLQidXAnsVIWaqCUO")
    expect(res).toEqual(true)
  })

  it('Fail: checkHashPassword', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    const res = module.checkHashPassword("any", "any")
    expect(res).toEqual(false)
  })

  it('null: checkHashPassword', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    const res = module.checkHashPassword("", "any")
    expect(res).toEqual(false)
  })

  it('SCS: checkHashPassword', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    expect(module.createUUID()).toMatch(uuidRegex)
  })

  it('SCS: toHashForSessionToken', () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    expect(module.toHashForSessionToken('any') != null).toEqual(true)
  })

  it('SCS: createSessionTokenWithHash', async () => {
    const module = ModSecure.init({ secretKey: 'custom_secret_key' })
    const { sessionToken, hashToken } = module.createSessionTokenWithHash()
    expect(sessionToken).toMatch(uuidRegex)
    expect(hashToken.length).toEqual(64)
  })

  it('SCS: other', async () => {
    const module = ModSecure.init({ 
      secretKey: 'custom_secret_key',
      bcrypt: {
        bcrypt_salt_rounds: {} as any
      }
    })
    expect(module.config.bcrypt.bcrypt_salt_rounds).toEqual(10)
  })

})
