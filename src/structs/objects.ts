/* tslint:disable:max-classes-per-file */
import { Attributes, VendorAttributes } from "./object_attributes"
import { KeyBlock } from "./object_data_structures"

export type ObjectType =
  | "Certificate"
  | "SymmetricKey"
  | "PublicKey"
  | "PrivateKey"
  | "SplitKey"
  | "SecretData"
  | "OpaqueObject"
  | "PGPKey"
  | "CertificateRequest"

export type KmsObject =
  | { type: "Certificate"; value: Certificate }
  | { type: "CertificateRequest"; value: CertificateRequest }
  | { type: "OpaqueObject"; value: OpaqueObject }
  | { type: "PGPKey"; value: PGPKey }
  | { type: "PrivateKey"; value: PrivateKey }
  | { type: "PublicKey"; value: PublicKey }
  | { type: "SecretData"; value: SecretData }
  | { type: "SplitKey"; value: SplitKey }
  | { type: "SymmetricKey"; value: SymmetricKey }

export enum CertificateType {
  X509 = 0x01,
  PGP = 0x02,
}

export class Certificate {
  tag = "Certificate"

  certificateType: CertificateType
  certificateValue: Uint8Array

  constructor(certificateType: CertificateType, certificateValue: Uint8Array) {
    this.certificateType = certificateType
    this.certificateValue = certificateValue
  }
}

export enum CertificateRequestType {
  CRMF = 0x01,
  PKCS10 = 0x02,
  PEM = 0x03,
}

export class CertificateRequest {
  tag = "CertificateRequest"

  certificateRequestType: CertificateRequestType
  certificateRequestValue: Uint8Array

  constructor(
    certificateRequestType: CertificateRequestType,
    certificateRequestValue: Uint8Array,
  ) {
    this.certificateRequestType = certificateRequestType
    this.certificateRequestValue = certificateRequestValue
  }
}

export enum OpaqueDataType {
  Unknown = 0x8000_0001,
}

export class OpaqueObject {
  tag = "OpaqueObject"

  opaqueDataType: OpaqueDataType
  opaqueDataValue: Uint8Array

  constructor(opaqueDataType: OpaqueDataType, opaqueDataValue: Uint8Array) {
    this.opaqueDataType = opaqueDataType
    this.opaqueDataValue = opaqueDataValue
  }
}

export class PGPKey {
  tag = "PGPKey"

  pgpKeyVersion: number
  keyBlock: KeyBlock

  constructor(pgpKeyVersion: number, keyBlock: KeyBlock) {
    this.pgpKeyVersion = pgpKeyVersion
    this.keyBlock = keyBlock
  }
}

export class PrivateKey {
  tag = "PrivateKey"

  keyBlock: KeyBlock

  constructor(keyBlock: KeyBlock) {
    this.keyBlock = keyBlock
  }

  bytes(): Uint8Array {
    return this.keyBlock.bytes()
  }

  policy(): PolicyKms {
    return this.keyBlock.policy()
  }
}

export class PublicKey {
  tag = "PublicKey"

  keyBlock: KeyBlock

  constructor(keyBlock: KeyBlock) {
    this.keyBlock = keyBlock
  }

  bytes(): Uint8Array {
    return this.keyBlock.bytes()
  }

  policy(): PolicyKms {
    return this.keyBlock.policy()
  }
}

export enum SecretDataType {
  Password = 0x01,
  Seed = 0x02,
  FunctionalKey = 0x8000_0001,
  FunctionalKeyShare = 0x8000_0002,
}

export class SecretData {
  tag = "SecretData"

  secretDataType: SecretDataType
  keyBlock: KeyBlock

  constructor(secretDataType: SecretDataType, keyBlock: KeyBlock) {
    this.secretDataType = secretDataType
    this.keyBlock = keyBlock
  }
}

export enum SplitKeyMethod {
  XOR = 0x00000001,
  PolynomialSharingGf2_16 = 0x0000_0002,
  PolynomialSharingPrimeField = 0x0000_0003,
  PolynomialSharingGf2_8 = 0x0000_0004,
}

export class SplitKey {
  tag = "SplitKey"

  splitKeyParts: number
  keyPartIdentifier: number
  splitKeyThreshold: number
  splitKeyMethod: SplitKeyMethod
  keyBlock: KeyBlock
  primeFieldSize: BigInt | null = null

  constructor(
    splitKeyParts: number,
    keyPartIdentifier: number,
    splitKeyThreshold: number,
    splitKeyMethod: SplitKeyMethod,
    keyBlock: KeyBlock,
    primeFieldSize: BigInt | null = null,
  ) {
    this.splitKeyParts = splitKeyParts
    this.keyPartIdentifier = keyPartIdentifier
    this.splitKeyThreshold = splitKeyThreshold
    this.splitKeyMethod = splitKeyMethod
    this.keyBlock = keyBlock
    this.primeFieldSize = primeFieldSize
  }
}

export class SymmetricKey {
  tag = "SymmetricKey"

  keyBlock: KeyBlock

  constructor(keyBlock: KeyBlock) {
    this.keyBlock = keyBlock
  }

  public bytes(): Uint8Array {
    return this.keyBlock.bytes()
  }
}

export class PolicyKms {
  public _policyBytes: Uint8Array

  constructor(PolicyKmsBytes: Uint8Array) {
    this._policyBytes = PolicyKmsBytes
  }

  /**
   * Packages the policy into a vendor attribute to include in a key
   * @returns {VendorAttributes} the Policy as a VendorAttributes
   */
  public toVendorAttribute(): VendorAttributes {
    return new VendorAttributes(
      VendorAttributes.VENDOR_ID_COSMIAN,
      VendorAttributes.VENDOR_ATTR_COVER_CRYPT_POLICY,
      this._policyBytes,
    )
  }

  /**
   * Recover the Policy from the key attributes, throws otherwise
   * @param {Attributes} attributes the key attributes to parse
   * @returns {PolicyKms} the Policy
   */
  public static fromAttributes(attributes: Attributes): PolicyKms {
    const attrs = attributes.vendorAttributes
    if (typeof attrs === "undefined" || attrs.length === 0) {
      throw new Error("No policy available in the vendor attributes")
    }
    for (const att of attrs) {
      if (
        att.attributeName === VendorAttributes.VENDOR_ATTR_COVER_CRYPT_POLICY
      ) {
        return PolicyKms.fromBytes(att.attributeValue)
      }
    }
    throw new Error("No policy available in the vendor attributes")
  }

  static fromBytes(policyBytes: Uint8Array): PolicyKms {
    const policy = new PolicyKms(policyBytes)
    return policy
  }

  /**
   * Returns the policy bytes.
   * @returns {Uint8Array} the string
   */
  public toBytes(): Uint8Array {
    return this._policyBytes
  }

  /**
   * Attempt to extract the Policy from a CoverCrypt public or private key
   * Throws if not found
   * @param {PrivateKey | PublicKey} key the CoverCrypt key
   * @returns {PolicyKms} the recovered Policy
   */
  public static fromKey(key: PrivateKey | PublicKey): PolicyKms {
    return key.policy()
  }
}

export class AccessPolicyKms {
  private readonly _booleanAccessPolicy: string

  /**
   * Create an Access Policy from a boolean expression over the attributes e.g.
   * (Department::MKG || Department::FIN) && Security Level::Confidential
   * @param {string} booleanAccessPolicy the boolean expression
   */
  constructor(booleanAccessPolicy: string) {
    this._booleanAccessPolicy = booleanAccessPolicy
  }

  public get booleanAccessPolicy(): string {
    return this._booleanAccessPolicy
  }

  /**
   * Packages the access policy into a vendor attribute to include in a user decryption key
   * @returns {VendorAttributes} the Access Policy as a VendorAttributes
   */
  public async toVendorAttribute(): Promise<VendorAttributes> {
    return new VendorAttributes(
      VendorAttributes.VENDOR_ID_COSMIAN,
      VendorAttributes.VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY,
      new TextEncoder().encode(await this._booleanAccessPolicy),
    )
  }

  /**
   * Recover the Access Policy from the key attributes, throws otherwise
   * @param {Attributes} attributes the key attributes to parse
   * @returns {AccessPolicyKms} the Access Policy
   */
  public static fromAttributes(attributes: Attributes): AccessPolicyKms {
    const attrs = attributes.vendorAttributes
    if (typeof attrs === "undefined" || attrs.length === 0) {
      throw new Error("No access policy available in the vendor attributes")
    }
    for (const att of attrs) {
      if (
        att.attributeName ===
          VendorAttributes.VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY ||
        att.attributeName === VendorAttributes.VENDOR_ATTR_ABE_ACCESS_POLICY
      ) {
        return new AccessPolicyKms(new TextDecoder().decode(att.attributeValue))
      }
    }
    throw new Error("No access policy available in the vendor attributes")
  }

  /**
   * Attempt to extract the Access Policy from a CoverCrypt User Decryption Key
   * Throws if not found
   * @param {PrivateKey} key the CoverCrypt User Decryption Key
   * @returns {AccessPolicyKms} the recovered Access Policy
   */
  public static fromKey(key: PrivateKey): AccessPolicyKms {
    const keyValue = key.keyBlock.keyValue
    if (
      keyValue === null ||
      keyValue instanceof Uint8Array ||
      keyValue.attributes === null
    ) {
      throw new Error("No policy can be extracted from that key")
    }

    return this.fromAttributes(keyValue.attributes)
  }
}
