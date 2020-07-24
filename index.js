const getJwt = (request) => {
  let authHeader = request.headers.get('Authorization')
  if (!authHeader || authHeader.substring(0, 6) !== 'Bearer') return null
  return authHeader.substring(6).trim()
}

const decodeJwt = (encoded) => {
  const parts = encoded.split('.')
  const header = JSON.parse(atob(parts[0]))
  const payload = JSON.parse(atob(parts[1]))
  const signature = atob(parts[2].replace(/_/g, '/').replace(/-/g, '+'))
  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: { header: parts[0], payload: parts[1], signature: parts[2] }
  }
}

const getKey = async (kid, url) => {
  let key
  try {
    const res = await fetch(url, { cf: { cacheTtl: 300 } })
    let data = await res.json()
    let jwk = data.keys.find((x) => x.kid === kid) || null
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
  } catch (err) {
    console.log(err)
    key = null
  }
  return key
}

const verify = async (request, jwkUrl) => {
  let output = {
    valid: false,
    message: true
  }
  try {
    let encodedToken = getJwt(request)
    const token = decodeJwt(encodedToken)
    const expired = token.payload.exp * 1000 < Date.now()
    const key = await getKey(token.header.kid, jwkUrl)
    const encoder = new TextEncoder()
    const data = encoder.encode([token.raw.header, token.raw.payload].join('.'))
    const signature = new Uint8Array(Array.from(token.signature).map((c) => c.charCodeAt(0)))
    output.valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)
    if (output.valid === true && expired === true) {
      throw new Error('Token is valid but expired.')
    }
  } catch (err) {
    console.log(err)
    output.valid = false
    output.message = err.message
  }
  return output
}

export { verify }
