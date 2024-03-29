import * as jose from "jose"
import { EncryptResponse } from "./responses/EncryptResponse"
import { deserialize, serialize } from "./kmip"
import { Create } from "./requests/Create"
import { CreateKeyPair } from "./requests/CreateKeyPair"
import { Decrypt } from "./requests/Decrypt"
import { Destroy } from "./requests/Destroy"
import { Encrypt } from "./requests/Encrypt"
import { Get } from "./requests/Get"
import { Import } from "./requests/Import"
import { Locate } from "./requests/Locate"
import { ReKeyKeyPair } from "./requests/ReKeyKeyPair"
import { Revoke } from "./requests/Revoke"
import {
  Attributes,
  CryptographicParameters,
  Link,
  LinkType,
  VendorAttributes,
} from "./structs/object_attributes"
import {
  CryptographicAlgorithm,
  EncryptionKeyInformation,
  KeyBlock,
  KeyFormatType,
  KeyValue,
  KeyWrappingSpecification,
  TransparentSymmetricKey,
  WrappingMethod,
  ByteString,
} from "./structs/object_data_structures"
import {
  AccessPolicyKms,
  Certificate,
  CertificateType,
  KmsObject,
  ObjectType,
  PolicyKms,
  PrivateKey,
  PublicKey,
  RekeyActionKmsBuilder,
  SymmetricKey,
} from "./structs/objects"
import {
  CryptographicUsageMask,
  KeyWrapType,
  RevocationReasonEnumeration,
} from "./structs/types"
import { decode, encode } from "./utils/leb128"

// eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
export interface KmsRequest<TResponse> {
  // If the `TResponse` type is only present in the `implements KmsRequest<…>`
  // TypeScript cannot found it. We need to have it present in the body of the class.
  // The only solution I found to fix this problem is to have a dummy property of the correct
  // type inside the body. This property is never assigned, nor read.
  __response: TResponse | undefined
}

export class KmsClient {
  private readonly url: string
  private readonly headers: HeadersInit
  private publicKey: jose.JWK | null = null

  /**
   * Instantiate a KMS Client
   * @param {string} url of the KMS server
   * @param {string} apiKey optional, to authenticate to the KMS server
   */
  constructor(url: string, apiKey: string | null = null) {
    this.url = url
    this.headers = {
      "Content-Type": "application/json; charset=utf-8",
    }
    if (apiKey !== null) {
      this.headers.Authorization = `Bearer ${apiKey}`
    }
  }

  setEncryption(publicKey: jose.JWK): void {
    this.publicKey = publicKey
  }

  /**
   * Execute a KMIP request and get a response
   * It is easier and safer to use the specialized methods of this class, for each crypto system
   * @param request a valid KMIP operation
   * @returns an instance of the KMIP response
   */
  private async post<TResponse>(
    request: KmsRequest<TResponse> & { tag: string },
  ): Promise<TResponse> {
    const kmipUrl = new URL("kmip/2_1", this.url)
    let body = serialize(request)

    if (this.publicKey !== null) {
      body = await new jose.CompactEncrypt(new TextEncoder().encode(body))
        .setProtectedHeader({
          alg: "ECDH-ES",
          enc: "A256GCM",
          kid: this.publicKey.kid,
        })
        .encrypt(await jose.importJWK(this.publicKey))
    }

    const response = await fetch(kmipUrl, {
      method: "POST",
      body,
      headers: this.headers,
    })

    if (response.status >= 400) {
      throw new Error(
        `KMIP request failed (${request.tag}): ${await response.text()}`,
      )
    }

    const content = await response.text()
    return deserialize<TResponse>(content)
  }

  /**
   * Returns KMS version
   * @returns {Response} containing X.Y.Z version (via `text()` function)
   */
  public async version(): Promise<Response> {
    const versionUrl = new URL("version", this.url)
    const response = await fetch(versionUrl, {
      method: "GET",
      headers: this.headers,
    })
    if (!response.ok || response.status >= 400) {
      throw new Error(`version request failed (${response.status})`)
    }

    return response
  }

  /**
   * Tests whether the KMS server is responding
   * @returns {boolean} true if up
   */
  public async up(): Promise<boolean> {
    try {
      await this.version()
      return true
    } catch (error) {
      return false
    }
  }

  /**
   * Retrieve a KMIP Object from the KMS
   * @param uniqueIdentifier the unique identifier of the object
   * @param options Additional options
   * @param options.keyWrappingSpecification specifies keys and other information for wrapping the returned object
   * @param options.keyFormatType specifies the required format type (bytestring being the default value returned by server)
   * @returns an instance of the KMIP Object
   */
  public async getObject(
    uniqueIdentifier: string,
    options: {
      keyWrappingSpecification?: KeyWrappingSpecification
      keyFormatType?: KeyFormatType
    } = {},
  ): Promise<KmsObject> {
    const response = await this.post(
      new Get(
        uniqueIdentifier,
        options.keyWrappingSpecification,
        options.keyFormatType,
      ),
    )
    return response.object
  }

  /**
   * Retrieve a list of KMIP Object from the KMS
   * @param {string[]} tags list of tags
   * @returns {KmsObject[]} list of KMIP Objects
   */
  public async getObjectsByTags(tags: string[]): Promise<KmsObject[]> {
    const uniqueIdentifiers = await this.getUniqueIdentifiersByTags(tags)
    return await Promise.all(
      uniqueIdentifiers.map(async (uniqueId) => await this.getObject(uniqueId)),
    )
  }

  /**
   * Retrieve a list of unique identifiers from the KMS
   * @param {string[]} tags list of tags
   * @returns {string[]} list of unique identifiers in the KMS
   */
  public async getUniqueIdentifiersByTags(tags: string[]): Promise<string[]> {
    const attributes = new Attributes()
    const enc = new TextEncoder()
    const vendor = new VendorAttributes(
      VendorAttributes.VENDOR_ID_COSMIAN,
      VendorAttributes.TAG,
      enc.encode(JSON.stringify(tags)),
    )
    attributes.vendorAttributes.push(vendor)
    const response = await this.post(new Locate(attributes))
    return response.uniqueIdentifier
  }

  /**
   * Import a KMIP Object inside the KMS
   * @param {string} uniqueIdentifier the Object unique identifier in the KMS
   * @param {Attributes} attributes the indexed attributes of the Object
   * @param {ObjectType} objectType the objectType of the Object
   * @param {KmsObject} object the KMIP Object instance
   * @param {boolean} replaceExisting replace the existing object
   * @param {KeyWrapType} keyWrapType determines the Key Wrap Type of the returned key value.
   * @returns {string} the unique identifier
   */
  public async importObject(
    uniqueIdentifier: string,
    attributes: Attributes,
    objectType: ObjectType,
    object: KmsObject,
    replaceExisting: boolean = false,
    keyWrapType?: KeyWrapType,
  ): Promise<string> {
    const response = await this.post(
      new Import(
        uniqueIdentifier,
        objectType,
        object,
        attributes,
        replaceExisting,
        keyWrapType,
      ),
    )

    return response.uniqueIdentifier
  }

  /**
   * Revoke a KMIP Object in the KMS
   * @param {string} uniqueIdentifier the unique identifier of the object
   * @param {string} reason the explanation of the revocation
   */
  public async revokeObject(
    uniqueIdentifier: string,
    reason: string | RevocationReasonEnumeration,
  ): Promise<void> {
    await this.post(new Revoke(uniqueIdentifier, reason))
  }

  /**
   * Destroy a KMIP Object in the KMS
   * @param {string} uniqueIdentifier the unique identifier of the object
   */
  public async destroyObject(uniqueIdentifier: string): Promise<void> {
    await this.post(new Destroy(uniqueIdentifier))
  }

  /**
   * Create a symmetric key
   * @param {SymmetricKeyAlgorithm} algorithm defaults to AES
   * @param {number} bits number of bits of the key, defaults to 256
   * @param {Link[]} links potential links to other keys
   * @param {string[]} tags potential list of tags
   * @returns {string} the unique identifier of the created key
   */
  public async createSymmetricKey(
    algorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES,
    bits: number | null = null,
    links: Link[] = [],
    tags: string[] = [],
  ): Promise<string> {
    const algo =
      algorithm === SymmetricKeyAlgorithm.ChaCha20
        ? CryptographicAlgorithm.ChaCha20
        : CryptographicAlgorithm.AES

    const attributes = new Attributes()
    attributes.objectType = "SymmetricKey"
    attributes.link = links
    attributes.cryptographicAlgorithm = algo
    attributes.cryptographicLength = bits
    attributes.keyFormatType = KeyFormatType.TransparentSymmetricKey

    if (tags.length > 0) {
      const enc = new TextEncoder()
      const vendor = new VendorAttributes(
        VendorAttributes.VENDOR_ID_COSMIAN,
        VendorAttributes.TAG,
        enc.encode(JSON.stringify(tags)),
      )
      attributes.vendorAttributes.push(vendor)
    }
    const response = await this.post(
      new Create(attributes.objectType, attributes, null),
    )
    return response.uniqueIdentifier
  }

  /**
   * Import a symmetric key into the KMS
   * @param {string} uniqueIdentifier  the unique identifier of the key
   * @param {Uint8Array} keyBytes the bytes of the key
   * @param {boolean} replaceExisting set to true to replace an existing key with the same identifier
   * @param  {CryptographicAlgorithm} algorithm the intended algorithm, defaults to AES
   * @param {Link[]} links links to other KMIP Objects
   * @returns {string} the unique identifier of the key
   */
  public async importSymmetricKey(
    uniqueIdentifier: string,
    keyBytes: Uint8Array,
    replaceExisting: boolean = false,
    algorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES,
    links: Link[] = [],
  ): Promise<string> {
    const algo =
      algorithm === SymmetricKeyAlgorithm.ChaCha20
        ? CryptographicAlgorithm.ChaCha20
        : CryptographicAlgorithm.AES

    const attributes = new Attributes()
    attributes.objectType = "SymmetricKey"
    attributes.link = links
    attributes.cryptographicAlgorithm = algo
    attributes.cryptographicLength = keyBytes.length * 8
    attributes.keyFormatType = KeyFormatType.TransparentSymmetricKey
    attributes.cryptographicUsageMask =
      CryptographicUsageMask.Encrypt | CryptographicUsageMask.Decrypt

    const symmetricKey = new SymmetricKey(
      new KeyBlock(
        KeyFormatType.TransparentSymmetricKey,
        new KeyValue(new TransparentSymmetricKey(keyBytes), attributes),
        algo,
        keyBytes.length * 8,
      ),
    )
    return await this.importObject(
      uniqueIdentifier,
      attributes,
      attributes.objectType,
      { type: "SymmetricKey", value: symmetricKey },
      replaceExisting,
    )
  }

  /**
   * Import a X509 certificate in DER encoding
   * @param {string} uniqueIdentifier  the unique identifier of the certificate
   * @param {Uint8Array} derBytes the DER certificate as bytes
   * @param {string[]} tags potential list of tags
   * @param {boolean} replaceExisting replace the existing object
   * @param options Additional optional options
   * @param {string} options.privateKeyIdentifier the link with the private key
   * @returns {string}  the unique identifier of the certificate
   */
  public async importCertificate(
    uniqueIdentifier: string,
    derBytes: Uint8Array,
    tags: string[] = [],
    replaceExisting: boolean = false,
    options: {
      privateKeyIdentifier?: string
    } = {},
  ): Promise<string> {
    const attributes = new Attributes()
    attributes.objectType = "Certificate"
    if (
      options.privateKeyIdentifier !== undefined &&
      options.privateKeyIdentifier.length > 0
    ) {
      attributes.link = [
        new Link(LinkType.PrivateKeyLink, options.privateKeyIdentifier),
      ]
    }
    const der = new Certificate(CertificateType.X509, derBytes)
    if (tags.length > 0) {
      const enc = new TextEncoder()
      const vendor = new VendorAttributes(
        VendorAttributes.VENDOR_ID_COSMIAN,
        VendorAttributes.TAG,
        enc.encode(JSON.stringify(tags)),
      )
      attributes.vendorAttributes.push(vendor)
    }

    return await this.importObject(
      uniqueIdentifier,
      attributes,
      attributes.objectType,
      { type: "Certificate", value: der },
      replaceExisting,
    )
  }

  /**
   * Import a private key in DER encoding
   * @param {string} uniqueIdentifier  the unique identifier of the key
   * @param {Uint8Array} bytes the DER private key as bytes
   * @param {string[]} tags potential list of tags
   * @param {boolean} replaceExisting replace the existing object
   * @param options Additional optional options
   * @param {string} options.keyFormatType the key format type as specified in `object_data_structures.ts`
   * @param {string} options.certificateIdentifier the link with the associated certificate
   * @returns {string}  the unique identifier of the key
   */
  public async importPrivateKey(
    uniqueIdentifier: string,
    bytes: Uint8Array,
    tags: string[] = [],
    replaceExisting: boolean = false,
    options: {
      keyFormatType?: KeyFormatType
      certificateIdentifier?: string
    } = {},
  ): Promise<string> {
    const attributes = new Attributes()
    attributes.objectType = "PrivateKey"
    if (
      options.certificateIdentifier !== undefined &&
      options.certificateIdentifier.length > 0
    ) {
      attributes.link = [
        new Link(LinkType.CertificateLink, options.certificateIdentifier),
      ]
    }
    attributes.cryptographicLength = bytes.length * 8

    const privateKey = new PrivateKey(
      new KeyBlock(
        options.keyFormatType ?? KeyFormatType.ECPrivateKey,
        new KeyValue(new ByteString(bytes), attributes),
        null,
        attributes.cryptographicLength,
        null,
      ),
    )
    if (tags.length > 0) {
      const enc = new TextEncoder()
      const vendor = new VendorAttributes(
        VendorAttributes.VENDOR_ID_COSMIAN,
        VendorAttributes.TAG,
        enc.encode(JSON.stringify(tags)),
      )
      attributes.vendorAttributes.push(vendor)
    }

    return await this.importObject(
      uniqueIdentifier,
      attributes,
      attributes.objectType,
      { type: "PrivateKey", value: privateKey },
      replaceExisting,
    )
  }

  /**
   *  Retrieve a symmetric key
   *
   *  Use SymmetricKey.bytes() to recover the bytes
   * @param {string} uniqueIdentifier the Object unique identifier in the KMS
   * @returns {SymmetricKey} the KMIP symmetric Key
   */
  public async retrieveSymmetricKey(
    uniqueIdentifier: string,
  ): Promise<SymmetricKey> {
    const object = await this.getObject(uniqueIdentifier, {
      keyFormatType: KeyFormatType.TransparentSymmetricKey,
    })
    if (object.type !== "SymmetricKey") {
      throw new Error(
        `The KMS server returned a ${object.type} instead of a SymmetricKey for the identifier ${uniqueIdentifier}`,
      )
    }
    return object.value
  }

  /**
   * Mark a KMIP Symmetric Key as Revoked
   * @param {string} uniqueIdentifier the unique identifier of the key
   * @param {string} reason the explanation of the revocation
   * @returns nothing
   */
  public async revokeSymmetricKey(
    uniqueIdentifier: string,
    reason: string,
  ): Promise<void> {
    return await this.revokeObject(uniqueIdentifier, reason)
  }

  /**
   * Encrypt some data
   * @param uniqueIdentifier the unique identifier of the key
   * @param data to encrypt
   * @param options optional fields for request
   * @param options.cryptographicParameters cryptographic Parameters corresponding to the particular decryption method requested
   * @param options.ivCounterNonce the initialization vector, counter or nonce to be used
   * @param options.correlationValue specifies the existing stream or by-parts cryptographic operation
   * @param options.initIndicator initial operation
   * @param options.finalIndicator final operation
   * @param options.authenticatedEncryptionAdditionalData Additional data to be authenticated
   * @returns the ciphertext
   */
  public async encrypt(
    uniqueIdentifier: string,
    data: Uint8Array,
    options: {
      cryptographicParameters?: CryptographicParameters
      ivCounterNonce?: Uint8Array
      correlationValue?: Uint8Array
      initIndicator?: boolean
      finalIndicator?: boolean
      authenticatedEncryptionAdditionalData?: Uint8Array | null
    },
  ): Promise<EncryptResponse> {
    const dataToEncrypt = Uint8Array.from([...data])

    const encrypted = new Encrypt(uniqueIdentifier, dataToEncrypt)

    if (typeof options.cryptographicParameters !== "undefined") {
      encrypted.cryptographicParameters = options.cryptographicParameters
    }
    if (typeof options.ivCounterNonce !== "undefined") {
      encrypted.ivCounterNonce = options.ivCounterNonce
    }
    if (typeof options.correlationValue !== "undefined") {
      encrypted.correlationValue = options.correlationValue
    }
    if (typeof options.initIndicator !== "undefined") {
      encrypted.initIndicator = options.initIndicator
    }
    if (typeof options.finalIndicator !== "undefined") {
      encrypted.finalIndicator = options.finalIndicator
    }
    if (typeof options.authenticatedEncryptionAdditionalData !== "undefined") {
      encrypted.authenticatedEncryptionAdditionalData =
        options.authenticatedEncryptionAdditionalData
    }
    return await this.post(encrypted)
  }

  /**
   * Decrypt some data
   * @param uniqueIdentifier the unique identifier of the key
   * @param data to decrypt
   * @param options optional fields for request
   * @param options.cryptographicParameters cryptographic Parameters corresponding to the particular decryption method requested
   * @param options.ivCounterNonce the initialization vector, counter or nonce to be used
   * @param options.correlationValue specifies the existing stream or by-parts cryptographic operation
   * @param options.initIndicator initial operation
   * @param options.finalIndicator final operation
   * @param options.authenticatedEncryptionAdditionalData additional data to be authenticated
   * @param options.authenticatedEncryptionTag the tag that will be needed to authenticate the decrypted data
   * @returns the ciphertext
   */
  public async decrypt(
    uniqueIdentifier: string,
    data: Uint8Array,
    options: {
      cryptographicParameters?: CryptographicParameters
      ivCounterNonce?: Uint8Array
      correlationValue?: Uint8Array
      initIndicator?: boolean
      finalIndicator?: boolean
      authenticatedEncryptionTag?: Uint8Array
      authenticatedEncryptionAdditionalData?: Uint8Array
    },
  ): Promise<Uint8Array> {
    const dataToDecrypt = Uint8Array.from([...data])

    const decrypted = new Decrypt(uniqueIdentifier, dataToDecrypt)
    if (typeof options.cryptographicParameters !== "undefined") {
      decrypted.cryptographicParameters = options.cryptographicParameters
    }
    if (typeof options.ivCounterNonce !== "undefined") {
      decrypted.ivCounterNonce = options.ivCounterNonce
    }
    if (typeof options.correlationValue !== "undefined") {
      decrypted.correlationValue = options.correlationValue
    }
    if (typeof options.initIndicator !== "undefined") {
      decrypted.initIndicator = options.initIndicator
    }
    if (typeof options.finalIndicator !== "undefined") {
      decrypted.finalIndicator = options.finalIndicator
    }
    if (typeof options.authenticatedEncryptionTag !== "undefined") {
      decrypted.authenticatedEncryptionTag = options.authenticatedEncryptionTag
    }
    if (typeof options.authenticatedEncryptionAdditionalData !== "undefined") {
      decrypted.authenticatedEncryptionAdditionalData =
        options.authenticatedEncryptionAdditionalData
    }
    return (await this.post(decrypted)).data
  }

  /**
   *  Mark a symmetric key as destroyed
   * @param {string} uniqueIdentifier the Object unique identifier in the KMS
   * @returns {string} the unique identifier of the symmetric Key
   */
  public async destroySymmetricKey(uniqueIdentifier: string): Promise<void> {
    return await this.destroyObject(uniqueIdentifier)
  }

  public async createCoverCryptMasterKeyPair(
    policy: PolicyKms,
    tags: string[] = [],
  ): Promise<string[]> {
    const attributes = new Attributes()
    attributes.objectType = "PrivateKey"
    attributes.cryptographicAlgorithm = CryptographicAlgorithm.CoverCrypt
    attributes.keyFormatType = KeyFormatType.CoverCryptSecretKey
    attributes.vendorAttributes = [policy.toVendorAttribute()]
    if (tags.length > 0) {
      const enc = new TextEncoder()
      const vendor = new VendorAttributes(
        VendorAttributes.VENDOR_ID_COSMIAN,
        VendorAttributes.TAG,
        enc.encode(JSON.stringify(tags)),
      )
      attributes.vendorAttributes.push(vendor)
    }

    const response = await this.post(new CreateKeyPair(attributes))
    return [
      response.privateKeyUniqueIdentifier,
      response.publicKeyUniqueIdentifier,
    ]
  }

  /**
   *  Retrieve a CoverCrypt Secret Master key
   *
   *  Use PrivateKey.bytes() to recover the bytes
   * @param {string} uniqueIdentifier the key unique identifier in the KMS
   * @returns {PrivateKey} the KMIP symmetric Key
   */
  public async retrieveCoverCryptSecretMasterKey(
    uniqueIdentifier: string,
  ): Promise<PrivateKey> {
    const object = await this.getObject(uniqueIdentifier)

    if (object.type !== "PrivateKey") {
      throw new Error(
        `The KMS server returned a ${object.type} instead of a PrivateKey for the identifier ${uniqueIdentifier}`,
      )
    }

    if (
      object.value.keyBlock.keyFormatType !== KeyFormatType.CoverCryptSecretKey
    ) {
      throw new Error(
        `The KMS server returned a private key of format ${object.value.keyBlock.keyFormatType} for the identifier ${uniqueIdentifier} instead of a CoverCryptSecretKey`,
      )
    }

    return object.value
  }

  /**
   *  Retrieve a CoverCrypt Public Master key
   *
   *  Use PublicKey.bytes() to recover the bytes
   * @param {string} uniqueIdentifier the key unique identifier in the KMS
   * @returns {PublicKey} the KMIP symmetric Key
   */
  public async retrieveCoverCryptPublicMasterKey(
    uniqueIdentifier: string,
  ): Promise<PublicKey> {
    const object = await this.getObject(uniqueIdentifier)

    if (object.type !== "PublicKey") {
      throw new Error(
        `The KMS server returned a ${object.type} instead of a PublicKey for the identifier ${uniqueIdentifier}`,
      )
    }

    if (
      object.value.keyBlock.keyFormatType !== KeyFormatType.CoverCryptPublicKey
    ) {
      throw new Error(
        `The KMS server returned a private key of format ${object.value.keyBlock.keyFormatType} for the identifier ${uniqueIdentifier} instead of a CoverCryptPublicKey`,
      )
    }

    return object.value
  }

  /**
   * Import a Private Master Key key into the KMS
   * @param {string} uniqueIdentifier  the unique identifier of the key
   * @param {PrivateKey} key the Private Master Key
   * @param options some additional optional options
   * @param {boolean} options.replaceExisting set to true to replace an existing key with the same identifier
   * @param options.link list of links to add to the Attributes KMIP object
   * @returns {string} the unique identifier of the key
   */
  public async importCoverCryptSecretMasterKey(
    uniqueIdentifier: string,
    key: PrivateKey | { bytes: Uint8Array; policy: PolicyKms },
    options: {
      replaceExisting?: boolean
      link?: Link[]
    } = {},
  ): Promise<string> {
    return await this.importCoverCryptKey(
      uniqueIdentifier,
      "PrivateKey",
      key,
      options,
    )
  }

  /**
   * Import a Public Master Key key into the KMS
   * @param {string} uniqueIdentifier  the unique identifier of the key
   * @param {PublicKey} key the Public Master Key
   * @param options some additional optional options
   * @param {boolean} options.replaceExisting set to true to replace an existing key with the same identifier
   * @param options.link list of links to add to the Attributes KMIP object
   * @returns {string} the unique identifier of the key
   */
  public async importCoverCryptPublicMasterKey(
    uniqueIdentifier: string,
    key: PublicKey | { bytes: Uint8Array; policy: PolicyKms },
    options: {
      replaceExisting?: boolean
      link?: Link[]
    } = {},
  ): Promise<string> {
    return await this.importCoverCryptKey(
      uniqueIdentifier,
      "PublicKey",
      key,
      options,
    )
  }

  /**
   * Import a Public or Private Master Key key into the KMS
   * @param uniqueIdentifier  the unique identifier of the key
   * @param type  PublicKey or PrivateKey. PrivateKey could be a master key or a user key
   * @param key the object key or bytes with a policy (Policy for master keys, AccessPolicy for user keys)
   * @param options additional optional options
   * @param options.replaceExisting set to true to replace an existing key with the same identifier
   * @param options.link list of links to add to the Attributes KMIP object
   * @returns the unique identifier of the key
   */
  private async importCoverCryptKey(
    uniqueIdentifier: string,
    type: "PublicKey" | "PrivateKey",
    key:
      | PublicKey
      | PrivateKey
      | {
          bytes: Uint8Array
          policy: PolicyKms | AccessPolicyKms
        },
    options: {
      replaceExisting?: boolean
      link?: Link[]
    } = {},
  ): Promise<string> {
    // If we didn't pass a real Key object, build one from bytes and policy
    if (!(key instanceof PublicKey) && !(key instanceof PrivateKey)) {
      const attributes = new Attributes(type)
      attributes.cryptographicAlgorithm = CryptographicAlgorithm.CoverCrypt
      attributes.keyFormatType = {
        PublicKey: KeyFormatType.CoverCryptPublicKey,
        PrivateKey: KeyFormatType.CoverCryptSecretKey,
      }[type]
      attributes.vendorAttributes = [await key.policy.toVendorAttribute()]
      if (typeof options.link !== "undefined") {
        attributes.link = options.link
      }

      const keyValue = new KeyValue(new ByteString(key.bytes), attributes)
      const keyBlock = new KeyBlock(
        attributes.keyFormatType,
        keyValue,
        attributes.cryptographicAlgorithm,
        key.bytes.length,
      )

      if (type === "PublicKey") {
        key = new PublicKey(keyBlock)
      } else {
        key = new PrivateKey(keyBlock)
      }
    }

    if (key.keyBlock === null) {
      throw new Error(`The Master ${type} keyBlock shouldn't be null`)
    }
    if (!(key.keyBlock.keyValue instanceof KeyValue)) {
      throw new Error(
        `The Master ${type} keyBlock.keyValue should be a KeyValue`,
      )
    }
    if (key.keyBlock.keyValue.attributes === null) {
      throw new Error(
        `The Master ${type} keyBlock.keyValue.attributes shouldn't be null`,
      )
    }

    return await this.importObject(
      uniqueIdentifier,
      key.keyBlock.keyValue.attributes,
      type,
      { type, value: key },
      options.replaceExisting,
    )
  }

  /**
   * Mark a CoverCrypt Secret Master Key as Revoked
   * @param {string} uniqueIdentifier the unique identifier of the key
   * @param {string} reason the explanation of the revocation
   * @returns nothing
   */
  public async revokeCoverCryptSecretMasterKey(
    uniqueIdentifier: string,
    reason: string,
  ): Promise<void> {
    return await this.revokeObject(uniqueIdentifier, reason)
  }

  /**
   * Mark a CoverCrypt Public Master Key as Revoked
   * @param {string} uniqueIdentifier the unique identifier of the key
   * @param {string} reason the explanation of the revocation
   * @returns nothing
   */
  public async revokeCoverCryptPublicMasterKey(
    uniqueIdentifier: string,
    reason: string,
  ): Promise<void> {
    return await this.revokeObject(uniqueIdentifier, reason)
  }

  /**
   * Create a CoverCrypt User Decryption Key with a given access policy
   * @param {string | AccessPolicyKms} accessPolicy the access policy expressed as a boolean expression e.g.
   * (Department::MKG || Department::FIN) && Security Level::Confidential
   * @param {string} secretMasterKeyIdentifier the secret master key identifier which will derive this key
   * @param {string[]} tags a list of tags
   * @returns {string} the unique identifier of the user decryption key
   */
  public async createCoverCryptUserDecryptionKey(
    accessPolicy: AccessPolicyKms | string,
    secretMasterKeyIdentifier: string,
    tags: string[] = [],
  ): Promise<string> {
    if (typeof accessPolicy === "string") {
      accessPolicy = new AccessPolicyKms(accessPolicy)
    }

    const attributes = new Attributes()
    attributes.objectType = "PrivateKey"
    attributes.link = [new Link(LinkType.ParentLink, secretMasterKeyIdentifier)]
    attributes.vendorAttributes = [await accessPolicy.toVendorAttribute()]
    attributes.cryptographicAlgorithm = CryptographicAlgorithm.CoverCrypt
    attributes.cryptographicUsageMask = CryptographicUsageMask.Decrypt
    attributes.keyFormatType = KeyFormatType.CoverCryptSecretKey
    if (tags.length > 0) {
      const enc = new TextEncoder()
      const vendor = new VendorAttributes(
        VendorAttributes.VENDOR_ID_COSMIAN,
        VendorAttributes.TAG,
        enc.encode(JSON.stringify(tags)),
      )
      attributes.vendorAttributes.push(vendor)
    }

    const response = await this.post(
      new Create(attributes.objectType, attributes),
    )
    return response.uniqueIdentifier
  }

  /**
   *  Retrieve a CoverCrypt User Decryption key
   *
   *  Use PrivateKey.bytes() to recover the bytes
   * @param {string} uniqueIdentifier the key unique identifier in the KMS
   * @returns {PrivateKey} the KMIP symmetric Key
   */
  public async retrieveCoverCryptUserDecryptionKey(
    uniqueIdentifier: string,
  ): Promise<PrivateKey> {
    return await this.retrieveCoverCryptSecretMasterKey(uniqueIdentifier)
  }

  /**
   * Import a CoverCrypt User Decryption Key key into the KMS
   * @param {string} uniqueIdentifier  the unique identifier of the key
   * @param {PrivateKey} key the CoverCrypt User Decryption Key
   * @param options some additional optional options
   * @param {boolean} options.replaceExisting set to true to replace an existing key with the same identifier
   * @param options.link list of links to add to the Attributes KMIP object
   * @returns {string} the unique identifier of the key
   */
  public async importCoverCryptUserDecryptionKey(
    uniqueIdentifier: string,
    key: PrivateKey | { bytes: Uint8Array; policy: AccessPolicyKms | string },
    options: {
      replaceExisting?: boolean
      link?: Link[]
    } = {},
  ): Promise<string> {
    if (!(key instanceof PrivateKey) && typeof key.policy === "string") {
      key.policy = new AccessPolicyKms(key.policy)
    }

    return await this.importCoverCryptKey(
      uniqueIdentifier,
      "PrivateKey",
      key as any,
      options,
    )
  }

  /**
   * Mark a CoverCrypt User Decryption Key as Revoked
   * @param {string} uniqueIdentifier the unique identifier of the key
   * @param {string} reason the explanation of the revocation
   * @returns nothing
   */
  public async revokeCoverCryptUserDecryptionKey(
    uniqueIdentifier: string,
    reason: string,
  ): Promise<void> {
    return await this.revokeObject(uniqueIdentifier, reason)
  }

  /**
   * Encrypt some data
   * @param uniqueIdentifier the unique identifier of the public key
   * @param accessPolicy the access policy to use for encryption
   * @param data to encrypt
   * @param {object} options Additional optional options to the encryption
   * @param {Uint8Array} options.headerMetadata Data encrypted in the header
   * @param {Uint8Array} options.authenticationData Data use to authenticate the encrypted value when decrypting (if use, should be use during decryption)
   * @returns the ciphertext
   */
  public async coverCryptEncrypt(
    uniqueIdentifier: string,
    accessPolicy: string,
    data: Uint8Array,
    options: {
      headerMetadata?: Uint8Array
      authenticationData?: Uint8Array
    } = {},
  ): Promise<Uint8Array> {
    const accessPolicyBytes = new TextEncoder().encode(accessPolicy)
    const accessPolicySize = encode(accessPolicyBytes.length)

    let headerMetadataSize = encode(0)
    let headerMetadata = Uint8Array.from([])
    if (typeof options.headerMetadata !== "undefined") {
      headerMetadataSize = encode(options.headerMetadata.length)
      headerMetadata = options.headerMetadata
    }

    const dataToEncrypt = Uint8Array.from([
      ...accessPolicySize,
      ...accessPolicyBytes,
      ...headerMetadataSize,
      ...headerMetadata,
      ...data,
    ])

    const encrypt = new Encrypt(uniqueIdentifier, dataToEncrypt)
    if (typeof options.authenticationData !== "undefined") {
      encrypt.authenticatedEncryptionAdditionalData = options.authenticationData
    }

    return (await this.post(encrypt)).data
  }

  /**
   * Encrypt multiple data at once
   * @param uniqueIdentifier the unique identifier of the public key
   * @param accessPolicy the access policy to use for encryption
   * @param data multiple data to encrypt
   * @param {object} options Additional optional options to the encryption
   * @param {Uint8Array} options.headerMetadata Data encrypted in the header
   * @param {Uint8Array} options.authenticationData Data use to authenticate the encrypted value when decrypting (if use, should be use during decryption)
   * @returns an array containing multiple ciphertexts
   */
  public async coverCryptBulkEncrypt(
    uniqueIdentifier: string,
    accessPolicy: string,
    data: Uint8Array[],
    options: {
      headerMetadata?: Uint8Array
      authenticationData?: Uint8Array
    } = {},
  ): Promise<Uint8Array[]> {
    const accessPolicyBytes = new TextEncoder().encode(accessPolicy)
    const accessPolicySize = encode(accessPolicyBytes.length)

    let headerMetadataSize = encode(0)
    let headerMetadata = Uint8Array.from([])
    if (typeof options.headerMetadata !== "undefined") {
      headerMetadataSize = encode(options.headerMetadata.length)
      headerMetadata = options.headerMetadata
    }

    const cryptographicParameters = new CryptographicParameters()
    cryptographicParameters.cryptographicAlgorithm =
      CryptographicAlgorithm.CoverCryptBulk

    let plaintext = encode(data.length)

    for (const chunk of data) {
      plaintext = Uint8Array.from([
        ...plaintext,
        ...encode(chunk.length),
        ...chunk,
      ])
    }

    const dataToEncrypt = Uint8Array.from([
      ...accessPolicySize,
      ...accessPolicyBytes,
      ...headerMetadataSize,
      ...headerMetadata,
      ...plaintext,
    ])

    const encrypt = new Encrypt(
      uniqueIdentifier,
      dataToEncrypt,
      cryptographicParameters,
    )
    if (typeof options.authenticationData !== "undefined") {
      encrypt.authenticatedEncryptionAdditionalData = options.authenticationData
    }

    const encryptedData = (await this.post(encrypt)).data

    let { result: nbChunks, tail: tailCiphertext } = decode(encryptedData)

    const encryptedChunks = []
    for (let i = 0; i < nbChunks; i++) {
      const { result: chunkSize, tail } = decode(tailCiphertext)
      const chunk = tail.slice(0, chunkSize)
      tailCiphertext = tail.slice(chunkSize)

      encryptedChunks.push(chunk)
    }

    return encryptedChunks
  }

  /**
   * Decrypt some data
   * @param uniqueIdentifier the unique identifier of the private key
   * @param data to decrypt
   * @param {object} options Additional optional options to the encryption
   * @param {Uint8Array} options.authenticationData Data use to authenticate the encrypted value when decrypting (if use, should have been use during encryption)
   * @returns the header metadata and the plaintext
   */
  public async coverCryptDecrypt(
    uniqueIdentifier: string,
    data: Uint8Array,
    options: {
      authenticationData?: Uint8Array
    } = {},
  ): Promise<{ headerMetadata: Uint8Array; plaintext: Uint8Array }> {
    const decrypt = new Decrypt(uniqueIdentifier, data)
    if (typeof options.authenticationData !== "undefined") {
      decrypt.authenticatedEncryptionAdditionalData = options.authenticationData
    }

    const response = await this.post(decrypt)

    const { result: headerMetadataLength, tail } = decode(response.data)
    const headerMetadata = tail.slice(0, headerMetadataLength)
    const plaintext = tail.slice(headerMetadataLength)

    return { headerMetadata, plaintext }
  }

  /**
   * Decrypt multiple data at once
   * @param uniqueIdentifier the unique identifier of the private key
   * @param data multiple data to decrypt
   * @param {object} options Additional optional options to the encryption
   * @param {Uint8Array} options.authenticationData Data use to authenticate the encrypted value when decrypting (if use, should have been use during encryption)
   * @returns header metadata and an array containing multiple plaintext
   */
  public async coverCryptBulkDecrypt(
    uniqueIdentifier: string,
    data: Uint8Array[],
    options: {
      authenticationData?: Uint8Array
    } = {},
  ): Promise<{
    headerMetadata: Uint8Array
    plaintext: Uint8Array[]
  }> {
    const cryptographicParameters = new CryptographicParameters()
    cryptographicParameters.cryptographicAlgorithm =
      CryptographicAlgorithm.CoverCryptBulk

    let ciphertext = encode(data.length)

    for (const chunk of data) {
      ciphertext = Uint8Array.from([
        ...ciphertext,
        ...encode(chunk.length),
        ...chunk,
      ])
    }

    const decrypt = new Decrypt(
      uniqueIdentifier,
      ciphertext,
      cryptographicParameters,
    )
    if (typeof options.authenticationData !== "undefined") {
      decrypt.authenticatedEncryptionAdditionalData = options.authenticationData
    }

    const response = await this.post(decrypt)

    const { result: headerMetadataLength, tail } = decode(response.data)
    const headerMetadata = tail.slice(0, headerMetadataLength)
    const plaintext = tail.slice(headerMetadataLength)

    let { result: nbChunks, tail: tailPlaintext } = decode(plaintext)
    const decryptedChunks = []
    for (let i = 0; i < nbChunks; i++) {
      const { result: chunkSize, tail } = decode(tailPlaintext)
      const chunk = tail.slice(0, chunkSize)
      tailPlaintext = tail.slice(chunkSize)

      decryptedChunks.push(chunk)
    }

    return { headerMetadata, plaintext: decryptedChunks }
  }

  async processCoverCryptRekeyRequest(
    privateMasterKeyUniqueIdentifier: string,
    action: RekeyActionKmsBuilder,
  ): Promise<string[]> {
    const privateKeyAttributes = new Attributes("PrivateKey")
    privateKeyAttributes.link = [
      new Link(LinkType.ParentLink, privateMasterKeyUniqueIdentifier),
    ]
    privateKeyAttributes.vendorAttributes = [action.toVendorAttribute()]
    privateKeyAttributes.cryptographicAlgorithm =
      CryptographicAlgorithm.CoverCrypt
    privateKeyAttributes.keyFormatType = KeyFormatType.CoverCryptSecretKey

    const request = new ReKeyKeyPair(privateMasterKeyUniqueIdentifier)
    request.privateKeyAttributes = privateKeyAttributes

    const response = await this.post(request)
    return [
      response.privateKeyUniqueIdentifier,
      response.publicKeyUniqueIdentifier,
    ]
  }

  /**
   * Generate new keys associated to the given access policy in the master keys.
   * This will rekey in the KMS:
   * - the master keys
   * - any user key associated to the access policy
   *
   * Non Rekeyed User Decryption Keys cannot decrypt data encrypted with the rekeyed Master Public Key and the given
   * attributes.
   * Rekeyed User Decryption Keys however will be able to decrypt data encrypted by the previous Master Public Key and
   * the rekeyed one.
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} accessPolicy to rekey e.g. "Department::MKG && Security Level::Confidential"
   * @returns {string[]} returns the updated master keys uids
   */
  public async rekeyCoverCryptAccessPolicy(
    privateMasterKeyUniqueIdentifier: string,
    accessPolicy: string,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().rekeyAccessPolicy(accessPolicy),
    )
  }

  /**
   * Removes old keys associated to the given access policy from the master
   * keys. This will permanently remove access to old ciphers.
   *
   * This will rekey in the KMS:
   * - the master keys
   * - any user key associated to the access policy
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} accessPolicy to rekey e.g. "Department::MKG && Security Level::Confidential"
   * @returns {string[]} returns the updated master keys uids
   */
  public async pruneCoverCryptAccessPolicy(
    privateMasterKeyUniqueIdentifier: string,
    accessPolicy: string,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().pruneAccessPolicy(accessPolicy),
    )
  }

  /**
   * Remove a specific attribute from a keypair's policy.
   * Permanently removes the ability to encrypt new messages and decrypt all existing ciphers associated
   * with this attribute.
   *
   * This will rekey in the KMS:
   * - the master keys
   * - any user decryption keys associated to the attribute
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} attribute to remove e.g. "Department::HR"
   * @returns {string[]} returns the updated master keys uids
   */
  public async removeCoverCryptAttribute(
    privateMasterKeyUniqueIdentifier: string,
    attribute: string,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().removeAttribute(attribute),
    )
  }

  /**
   * Disable a specific attribute from a keypair's policy.
   * Prevents the encryption of new messages for this attribute while keeping the ability to decrypt existing ciphers.
   *
   * This will rekey in the KMS:
   * - the master public key
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} attribute to disable e.g. "Department::HR"
   * @returns {string[]} returns the updated master keys uids
   */
  public async disableCoverCryptAttribute(
    privateMasterKeyUniqueIdentifier: string,
    attribute: string,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().disableAttribute(attribute),
    )
  }

  /**
   * Add a new attribute to a keypair's policy.
   *
   * This will rekey in the KMS:
   * - the master keys
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} attribute to create e.g. "Department::HR"
   * @param {boolean} isHybridized hint for encryption
   * @returns {string[]} returns the updated master keys uids
   */
  public async addCoverCryptAttribute(
    privateMasterKeyUniqueIdentifier: string,
    attribute: string,
    isHybridized = false,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().addAttribute(attribute, isHybridized),
    )
  }

  /**
   * Rename an attribute in a keypair's policy.
   * @param {string} privateMasterKeyUniqueIdentifier the unique identifier of the Private Master Key
   * @param {string} attribute to rename e.g. "Department::HR"
   * @param {string} newName the new name for the attribute
   * @returns {string[]} returns the updated master keys uids
   */
  public async renameCoverCryptAttribute(
    privateMasterKeyUniqueIdentifier: string,
    attribute: string,
    newName: string,
  ): Promise<string[]> {
    return await this.processCoverCryptRekeyRequest(
      privateMasterKeyUniqueIdentifier,
      new RekeyActionKmsBuilder().renameAttribute(attribute, newName),
    )
  }

  /**
   * Get and wrap
   * @param uniqueIdentifier the unique identifier of the object to get and wrap
   * @param encryptionKeyUniqueIdentifier the unique identifier to use to wrap the fetched key
   * @returns wrapped object
   */
  public async getWrappedKey(
    uniqueIdentifier: string,
    encryptionKeyUniqueIdentifier: string,
  ): Promise<KmsObject> {
    const keyWrappingSpecification = new KeyWrappingSpecification(
      WrappingMethod.Encrypt,
      new EncryptionKeyInformation(encryptionKeyUniqueIdentifier),
    )
    const object = await this.getObject(uniqueIdentifier, {
      keyWrappingSpecification,
    })
    return object
  }

  /**
   * Import key - with or without unwrapping
   * @param uniqueIdentifier the unique identifier of the object to import
   * @param wrappedObject wrapped object to import
   * @param unwrap boolean true if object must be unwrapped before importing
   * @param encryptionKeyUniqueIdentifier if unwrap is true, uniqueIdentifier used to unwrap key can be overwritten with a specific one
   * @param replaceExisting boolean replacing if existing object
   * @returns imported object identifier
   */
  public async importKey(
    uniqueIdentifier: string,
    wrappedObject: KmsObject,
    unwrap: boolean,
    encryptionKeyUniqueIdentifier: string | null = null,
    replaceExisting: boolean = false,
  ): Promise<string> {
    if (
      wrappedObject.type === "Certificate" ||
      wrappedObject.type === "CertificateRequest" ||
      wrappedObject.type === "OpaqueObject"
    ) {
      throw new Error(`The KmsObject ${wrappedObject.type} is not a key.`)
    }
    if (
      !(wrappedObject.value.keyBlock.keyValue instanceof KeyValue) ||
      wrappedObject.value.keyBlock.keyValue.attributes == null
    ) {
      throw new Error(`KmsObject is missing the attributes property.`)
    }
    const attributes = wrappedObject.value.keyBlock.keyValue?.attributes
    const keyWrapType = unwrap
      ? KeyWrapType.NotWrapped
      : KeyWrapType.AsRegistered
    const overWrittenWrappedObject = { ...wrappedObject }
    if (
      unwrap &&
      encryptionKeyUniqueIdentifier != null &&
      overWrittenWrappedObject.value.keyBlock.keyWrappingData != null &&
      overWrittenWrappedObject.value.keyBlock.keyWrappingData
        .encryptionKeyInformation != null
    ) {
      overWrittenWrappedObject.value.keyBlock.keyWrappingData.encryptionKeyInformation.uniqueIdentifier =
        encryptionKeyUniqueIdentifier
    }
    return await this.importObject(
      uniqueIdentifier,
      attributes,
      wrappedObject.type,
      overWrittenWrappedObject,
      replaceExisting,
      keyWrapType,
    )
  }

  private async manageAccess(
    uniqueIdentifier: string,
    userIdentifier: string,
    operationTypes: KMIPOperations[],
    urlPath: string,
  ): Promise<Response> {
    const url = new URL(urlPath, this.url)
    const body = {
      unique_identifier: uniqueIdentifier,
      user_id: userIdentifier,
      operation_types: operationTypes,
    }
    const response = await fetch(url, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body),
    })
    if (!response.ok || response.status >= 400) {
      throw new Error(`${urlPath} request failed (${response.status})`)
    }

    return response
  }

  /**
   * Grant access to a KmsObject for a specific user
   * @param uniqueIdentifier the unique identifier of the object to import
   * @param userIdentifier the unique identifier of the user to grant access to
   * @param operationTypes KMIP operation types to grant access for
   * @returns response from KMS server
   */
  public async grantAccess(
    uniqueIdentifier: string,
    userIdentifier: string,
    operationTypes: KMIPOperations[],
  ): Promise<Response> {
    return await this.manageAccess(
      uniqueIdentifier,
      userIdentifier,
      operationTypes,
      "access/grant",
    )
  }

  /**
   * Revoke access to a KmsObject for a specific user
   * @param uniqueIdentifier the unique identifier of the object to import
   * @param userIdentifier the unique identifier of the user to revoke access to
   * @param operationTypes KMIP operation types to revoke access for
   * @returns response from KMS server
   */
  public async revokeAccess(
    uniqueIdentifier: string,
    userIdentifier: string,
    operationTypes: KMIPOperations[],
  ): Promise<Response> {
    return await this.manageAccess(
      uniqueIdentifier,
      userIdentifier,
      operationTypes,
      "access/revoke",
    )
  }

  /**
   * List access to a KmsObject
   * @param uniqueIdentifier the unique identifier of the object to list access for
   * @returns response from KMS server
   */
  public async listAccess(uniqueIdentifier: string): Promise<Response> {
    const listAccessUrl = new URL(`access/list/${uniqueIdentifier}`, this.url)
    const response = await fetch(listAccessUrl, {
      method: "GET",
      headers: this.headers,
    })
    if (!response.ok || response.status >= 400) {
      throw new Error(`list access request failed (${response.status})`)
    }

    return response
  }

  private async listObjects(urlPath: string): Promise<Response> {
    const url = new URL(urlPath, this.url)
    const response = await fetch(url, {
      method: "GET",
      headers: this.headers,
    })
    if (!response.ok || response.status >= 400) {
      throw new Error(`${urlPath} request failed (${response.status})`)
    }

    return response
  }

  /**
   * List owned objects for a user
   * @returns response from KMS server
   */
  public async listOwnedObjects(): Promise<Response> {
    return await this.listObjects("access/owned")
  }

  /**
   * List objects a user has obtained access for
   * @returns response from KMS server
   */
  public async listObtainedObjects(): Promise<Response> {
    return await this.listObjects("access/obtained")
  }
}

export enum SymmetricKeyAlgorithm {
  AES,
  ChaCha20,
}

export enum KMIPOperations {
  get = "get",
  export = "export",
  encrypt = "encrypt",
  decrypt = "decrypt",
  import = "import",
  revoke = "revoke",
  destroy = "destroy",
}
