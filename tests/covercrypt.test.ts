import { KmsClient, Link, LinkType, PolicyKms } from "../src"

import "dotenv/config"
import { beforeAll, expect, test } from "vitest"

const kmsToken = process.env.AUTH0_TOKEN_1
let client: KmsClient

beforeAll(async () => {
  client = new KmsClient(
    `http://${process.env.KMS_HOST ?? "localhost"}:9998`,
    kmsToken,
  )
})

test(
  "Create, retrieve, import and rekey Covercrypt keys",
  async () => {
    // one unordered dimension policy "Security" with 2 attributes: "Classic", "TopSecret"
    const bytesPolicy = new TextEncoder().encode(
      '{"version":"V2","last_attribute_value":2,"dimensions":{"Security":{"Unordered":{"Simple":{"id":1,"encryption_hint":"Classic","write_status":"EncryptDecrypt"},"TopSecret":{"id":2,"encryption_hint":"Classic","write_status":"EncryptDecrypt"}}}}}',
    )
    const policy: PolicyKms = new PolicyKms(bytesPolicy)

    // create master keys
    const [mskID, mpkID] = await client.createCoverCryptMasterKeyPair(policy)
    const topSecretData = Uint8Array.from([1, 2, 3])
    const ciphertext = await client.coverCryptEncrypt(
      mpkID,
      "Security::TopSecret",
      topSecretData,
    )

    const simpleUser = await client.createCoverCryptUserDecryptionKey(
      "Security::Simple",
      mskID,
    )
    const topSecretUser = await client.createCoverCryptUserDecryptionKey(
      "Security::TopSecret",
      mskID,
    )

    const simpleUserKey = await client.retrieveCoverCryptUserDecryptionKey(
      simpleUser,
    )

    // Use the simple user key but pretend to have top secret access
    const temperedUserKeyID = await client.importCoverCryptUserDecryptionKey(
      `${simpleUser}-HACK`,
      { bytes: simpleUserKey.bytes(), policy: "Security::TopSecret" },
      {
        link: [new Link(LinkType.ParentLink, mskID)],
      },
    )
    expect(temperedUserKeyID).toEqual(`${simpleUser}-HACK`)

    // Top secret user can read the ciphertext
    {
      const { plaintext } = await client.coverCryptDecrypt(
        topSecretUser,
        ciphertext,
      )
      expect(plaintext).toEqual(topSecretData)
    }

    // Simple user cannot decrypt top secret ciphertext
    await expect(async () => {
      return await client?.coverCryptDecrypt(simpleUser, ciphertext)
    }).rejects.toThrow()

    // Neither can the tempered user
    await expect(async () => {
      return await client.coverCryptDecrypt(temperedUserKeyID, ciphertext)
    }).rejects.toThrow()

    // 1 - Generate new top secret key

    await client.rekeyCoverCryptAccessPolicy(mskID, "Security::TopSecret")

    // Top secret user can still read the old ciphertext
    {
      const { plaintext } = await client.coverCryptDecrypt(
        topSecretUser,
        ciphertext,
      )
      expect(plaintext).toEqual(topSecretData)
    }

    // simple use still has no access to the top secret ciphertext
    await expect(async () => {
      return await client.coverCryptDecrypt(simpleUser, ciphertext)
    }).rejects.toThrow()

    // the temperedUserKey has not been granted access to the new nor the old TopSecret key
    await expect(async () => {
      return await client.coverCryptDecrypt(temperedUserKeyID, ciphertext)
    }).rejects.toThrow()

    const newTopSecretData = Uint8Array.from([4, 5, 6])
    const newCiphertext = await client.coverCryptEncrypt(
      mpkID,
      "Security::TopSecret",
      newTopSecretData,
    )

    // Top secret user can read the new ciphertext
    {
      const { plaintext } = await client.coverCryptDecrypt(
        topSecretUser,
        newCiphertext,
      )
      expect(plaintext).toEqual(newTopSecretData)
    }

    await expect(async () => {
      return await client.coverCryptDecrypt(simpleUser, newCiphertext)
    }).rejects.toThrow()

    // cannot decrypt the new top secret cipher with the tempered user key
    await expect(async () => {
      return await client.coverCryptDecrypt(temperedUserKeyID, newCiphertext)
    }).rejects.toThrow()

    // 2 - Remove old top secret key

    await client.pruneCoverCryptAccessPolicy(mskID, "Security::TopSecret")

    // top secret user can no longer read the old ciphertext
    await expect(async () => {
      return await client.coverCryptDecrypt(topSecretUser, ciphertext)
    }).rejects.toThrow()

    // top secret user can still read the new ciphertext
    {
      const { plaintext } = await client.coverCryptDecrypt(
        topSecretUser,
        newCiphertext,
      )
      expect(plaintext).toEqual(newTopSecretData)
    }

    // 3 - Adding new attribute confidential
    await client.addCoverCryptAttribute(mskID, "Security::Confidential", false)

    // 4 - Renaming attribute
    await client.renameCoverCryptAttribute(
      mskID,
      "Security::Simple",
      "Security::Protected",
    )

    // 5 - Disable top secret attribute

    await client.disableCoverCryptAttribute(mskID, "Security::TopSecret")

    // encrypting data is no longer possible for this attribute
    await expect(async () => {
      return await client.coverCryptEncrypt(
        mpkID,
        "Security::TopSecret",
        Uint8Array.from([7, 8, 9]),
      )
    }).rejects.toThrow()

    // decryption still works
    {
      const { plaintext } = await client.coverCryptDecrypt(
        topSecretUser,
        newCiphertext,
      )
      expect(plaintext).toEqual(newTopSecretData)
    }

    // Removing "Top Secret" attribute
    await client.removeCoverCryptAttribute(mskID, "Security::TopSecret")

    // decrypting top secret ciphers is no longer possible
    await expect(async () => {
      return await client.coverCryptDecrypt(topSecretUser, newCiphertext)
    }).rejects.toThrow()
  },
  {
    timeout: 30 * 1000,
  },
)
