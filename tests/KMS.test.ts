import {
  Attributes,
  Create,
  CryptographicAlgorithm,
  CryptographicUsageMask,
  KMIPOperations,
  KeyFormatType,
  KeyValue,
  KmsClient,
  Link,
  LinkType,
  RecommendedCurve,
  SymmetricKey,
  SymmetricKeyAlgorithm,
  TransparentECPublicKey,
  TransparentSymmetricKey,
  deserialize,
  fromTTLV,
  serialize,
  toTTLV,
} from ".."

import { beforeAll, expect, test } from "vitest"
import {
  NIST_P256_CERTIFICATE,
  NIST_P256_PRIVATE_KEY,
} from "./data/certificates"

const kmsToken = process.env.AUTH0_TOKEN_1
let client: KmsClient

beforeAll(async () => {
  client = new KmsClient(
    `http://${process.env.KMS_HOST ?? "localhost"}:9998`,
    kmsToken,
  )
})

test("serialize/deserialize Create", async () => {
  const attributes = new Attributes()
  attributes.objectType = "SymmetricKey"
  attributes.link = [new Link(LinkType.ParentLink, "SK")]
  attributes.cryptographicAlgorithm = CryptographicAlgorithm.AES
  attributes.keyFormatType = KeyFormatType.TransparentSymmetricKey

  const create = new Create(attributes.objectType, attributes)

  const ttlv = toTTLV(create)
  const create2 = fromTTLV<Create>(ttlv)

  const ttlv2 = toTTLV(create2)

  expect(ttlv2).toEqual(ttlv)
})

test("deserialize", () => {
  const create: Create = deserialize<Create>(CREATE_SYMMETRIC_KEY)
  expect(create.objectType).toEqual("SymmetricKey")
  expect(create.protectionStorageMasks).toBeNull()
  expect(create.attributes.cryptographicAlgorithm).toEqual(
    CryptographicAlgorithm.AES,
  )
  expect(create.attributes.link).toBeDefined()
  // linter guard
  if (typeof create.attributes.link !== "undefined") {
    expect(create.attributes.link.length).toEqual(1)
    const link: Link = create.attributes.link[0]
    expect(link.linkType).toEqual(LinkType.ParentLink)
    expect(link.linkedObjectIdentifier).toEqual("SK")
  }
})

// generated from Rust
const CREATE_SYMMETRIC_KEY = `{
  "tag": "Create",
  "type": "Structure",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SymmetricKey"
    },
    {
      "tag": "Attributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        },
        {
          "tag": "Link",
          "type": "Structure",
          "value": [
            {
              "tag": "Link",
              "type": "Structure",
              "value": [
                {
                  "tag": "LinkType",
                  "type": "Enumeration",
                  "value": "ParentLink"
                },
                {
                  "tag": "LinkedObjectIdentifier",
                  "type": "TextString",
                  "value": "SK"
                }
              ]
            }
          ]
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "SymmetricKey"
        }
      ]
    }
  ]
}`

test(
  "KMS Locate using tags",
  async () => {
    const TAG = (Math.random() * 100000000).toString()
    const uniqueIdentifier = await client.createSymmetricKey(
      SymmetricKeyAlgorithm.AES,
      256,
      undefined,
      [TAG],
    )
    const uniqueIdentifier2 = await client.createSymmetricKey(
      SymmetricKeyAlgorithm.AES,
      256,
      undefined,
      [TAG],
    )

    const uniqueIdentifiers = await client.getUniqueIdentifiersByTags([TAG])
    expect(uniqueIdentifiers.length).toEqual(2)
    expect(uniqueIdentifiers).toContain(uniqueIdentifier)
    expect(uniqueIdentifiers).toContain(uniqueIdentifier2)
    const objects = await client.getObjectsByTags([TAG])
    expect(objects.length).toEqual(2)
    expect(objects[0].type).toEqual("SymmetricKey")

    const notExist = await client.getUniqueIdentifiersByTags(["TAG_NOT_EXIST"])
    expect(notExist.length).toEqual(0)
  },
  {
    timeout: 30 * 1000,
  },
)

test(
  "KMS Symmetric Key manipulation",
  async () => {
    // create
    const uniqueIdentifier = await client.createSymmetricKey(
      SymmetricKeyAlgorithm.AES,
      256,
    )
    expect(uniqueIdentifier).toBeTypeOf("string")

    // recover
    const key: SymmetricKey = await client.retrieveSymmetricKey(
      uniqueIdentifier,
    )
    expect(key.keyBlock.cryptographicAlgorithm).toEqual(
      CryptographicAlgorithm.AES,
    )
    expect(key.keyBlock.cryptographicLength).toEqual(256)
    expect(key.keyBlock.keyFormatType).toEqual(
      KeyFormatType.TransparentSymmetricKey,
    )
    expect(key.keyBlock.keyValue).not.toBeNull()
    expect(key.keyBlock.keyValue).toBeInstanceOf(KeyValue)

    const keyValue = key?.keyBlock?.keyValue as KeyValue
    expect(keyValue.keyMaterial).toBeInstanceOf(TransparentSymmetricKey)

    const sk = keyValue.keyMaterial as TransparentSymmetricKey
    expect(sk.key.length).toEqual(32)

    // import
    const uid = await client.importSymmetricKey(
      uniqueIdentifier + "-1",
      key.bytes(),
      false,
    )
    expect(uid).toEqual(uniqueIdentifier + "-1")

    // get
    const key_ = await client.retrieveSymmetricKey(uid)
    expect(key_.bytes()).toEqual(key.bytes())

    // revoke
    await client.revokeSymmetricKey(uniqueIdentifier, "revoked")
    await client.revokeSymmetricKey(uid, "revoked")
    try {
      await client.retrieveSymmetricKey(uid)
    } catch (error) {
      expect(error).toMatch(/(Item not found)/i)
    }
    // destroy
    await client.destroySymmetricKey(uid)
    await client.destroySymmetricKey(uniqueIdentifier)
  },
  {
    timeout: 30 * 1000,
  },
)

test("Big Ints", async () => {
  const publicKey = new TransparentECPublicKey(
    RecommendedCurve.ANSIX9C2PNB163V1,
    99999999999999999999999998888888888888888n,
  )

  const json = JSON.stringify(toTTLV(publicKey))
  expect(json).toEqual(
    '{"tag":"TransparentECPublicKey","type":"Structure","value":[{"tag":"RecommendedCurve","type":"Enumeration","value":"ANSIX9C2PNB163V1"},{"tag":"Q","type":"BigInteger","value":"0x125DFA371A19E6F7CB54391D77348EA8E38"}]}',
  )

  const publicKey2 = deserialize<TransparentECPublicKey>(json)
  expect(publicKey2.q).toBe(99999999999999999999999998888888888888888n)
})

test("Enums", async () => {
  const attributes = new Attributes("SymmetricKey")
  attributes.keyFormatType = KeyFormatType.TransparentSymmetricKey
  attributes.cryptographicUsageMask =
    CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt

  const json = serialize(attributes)
  const attributes2 = deserialize<Attributes>(json)

  expect(attributes2.keyFormatType).toEqual(attributes.keyFormatType)
  expect(attributes2.cryptographicUsageMask).toEqual(
    attributes.cryptographicUsageMask,
  )
})

test(
  "Grant and revoke Access",
  async () => {
    const kmsToken2 = process.env.AUTH0_TOKEN_2

    // Create a simple KmsObject
    const keyId = await client.createSymmetricKey()
    const key = await client.getObject(keyId)
    const client2 = new KmsClient(
      `http://${process.env.KMS_HOST ?? "localhost"}:9998`,
      kmsToken2,
    )

    // Check that another user cannot get this object
    try {
      await client2.getObject(keyId)
    } catch (error) {
      expect(error).toMatch(/(Item not found)/i)
    }

    // Grant access to another user, to get this object
    await client.grantAccess(keyId, "ci2@cosmian.com", KMIPOperations.get)
    const fetchedKey = await client2.getObject(keyId)
    expect(fetchedKey).toEqual(key)

    // List associated access to this object
    const access = await client.listAccess(keyId)
    expect(await access.text()).toEqual(
      '[{"user_id":"ci2@cosmian.com","operations":["get"]}]',
    )

    // Revoke access to this user
    await client.revokeAccess(keyId, "ci2@cosmian.com", KMIPOperations.get)
    try {
      await client2.getObject(keyId)
    } catch (error) {
      expect(error).toMatch(/(Item not found)/i)
    }
  },
  {
    timeout: 30 * 1000,
  },
)

test(
  "KMS Export wrapping key and Import unwrapping key",
  async () => {
    // Import certificate and private key
    const importedCertificateUniqueIdentifier = await client.importPem(
      "my_cert_id",
      new TextEncoder().encode(NIST_P256_CERTIFICATE),
      ["certificate", "x509"],
      true,
    )

    await client.importPem(
      "my_private_key_id",
      new TextEncoder().encode(NIST_P256_PRIVATE_KEY),
      ["private key", "x509"],
      true,
    )

    // Export key while wrapping it using certificate
    const keyUniqueIdentifier = await client.createSymmetricKey()

    const wrappedKey = await client.getWrappedKey(
      keyUniqueIdentifier,
      importedCertificateUniqueIdentifier,
    )

    // Import key while unwrapping it
    const unwrappedKeyIdentifier = await client.importKey(
      "unwrappedKey",
      wrappedKey,
      true,
      null,
      true,
    )

    const initialKey = await client.getObject(keyUniqueIdentifier)
    const unwrappedKey = await client.getObject(unwrappedKeyIdentifier)

    if (
      initialKey.type === "Certificate" ||
      initialKey.type === "CertificateRequest" ||
      initialKey.type === "OpaqueObject"
    ) {
      throw new Error(`The KmsObject ${initialKey.type} cannot be unwrapped.`)
    }
    if (
      !(initialKey.value.keyBlock.keyValue instanceof KeyValue) ||
      initialKey.value.keyBlock.keyValue.attributes == null
    ) {
      throw new Error(`KmsObject is missing the attributes property.`)
    }
    if (
      unwrappedKey.type === "Certificate" ||
      unwrappedKey.type === "CertificateRequest" ||
      unwrappedKey.type === "OpaqueObject"
    ) {
      throw new Error(`The KmsObject ${initialKey.type} cannot be unwrapped.`)
    }
    if (
      !(unwrappedKey.value.keyBlock.keyValue instanceof KeyValue) ||
      unwrappedKey.value.keyBlock.keyValue.attributes == null
    ) {
      throw new Error(`KmsObject is missing the attributes property.`)
    }

    expect(initialKey.value.keyBlock.keyValue.keyMaterial).toEqual(
      unwrappedKey.value.keyBlock.keyValue.keyMaterial,
    )
  },
  {
    timeout: 10 * 1000,
  },
)

test(
  "Overwrite KeyWrappingData when importing key",
  async () => {
    const keyUid = await client.createSymmetricKey()

    const importedCertificateUniqueIdentifier = await client.importPem(
      "my_cert_id",
      new TextEncoder().encode(NIST_P256_CERTIFICATE),
      ["certificate", "x509"],
      true,
    )

    await client.importPem(
      "my_private_key_id",
      new TextEncoder().encode(NIST_P256_PRIVATE_KEY),
      ["private key", "x509"],
      true,
    )

    const wrappedKey = await client.getWrappedKey(
      keyUid,
      importedCertificateUniqueIdentifier,
    )

    // Key can be unwrapped directly specifying the private key id (matching the certificate)
    let unwrappedKeyUid = await client.importKey(
      "unwrappedSymmetricKey",
      wrappedKey,
      true,
      "my_private_key_id",
      true,
    )

    const unwrappedKey = await client.getObject(unwrappedKeyUid)

    if (
      unwrappedKey.type === "Certificate" ||
      unwrappedKey.type === "CertificateRequest" ||
      unwrappedKey.type === "OpaqueObject"
    ) {
      throw new Error(`The KmsObject ${unwrappedKey.type} cannot be unwrapped.`)
    }

    expect(unwrappedKey.value.keyBlock.keyWrappingData).toEqual(null)

    // Key can also be unwrapped indirectly using the certificate id. In that case, KMS will locate the private key if already imported
    unwrappedKeyUid = await client.importKey(
      "unwrappedSymmetricKey",
      wrappedKey,
      true,
      "my_cert_id",
      true,
    )
  },
  {
    timeout: 10 * 1000,
  },
)

test(
  "KMS With JWE encryption",
  async () => {
    client.setEncryption({
      kty: "OKP",
      use: "enc",
      crv: "X25519",
      kid: "DX3GC+Fx3etxfRJValQNbqaB0gs=",
      x: "gdF-1TtAjsFqNWr9nwhGUlFG38qrDUqYgcILgtYrpTY",
      alg: "ECDH-ES",
    })

    await client.createSymmetricKey()
  },
  {
    timeout: 30 * 1000,
  },
)