import { KmsRequest } from "../kms"
import { DecryptResponse } from "../responses/DecryptResponse"
import { CryptographicParameters } from "../structs/object_attributes"

export class Decrypt implements KmsRequest<DecryptResponse> {
  __response: DecryptResponse | undefined

  tag = "Decrypt"

  uniqueIdentifier: string
  data: Uint8Array
  cryptographicParameters: CryptographicParameters | null = null
  ivCounterNonce: Uint8Array | null = null
  correlationValue: Uint8Array | null = null
  initIndicator: boolean | null = null
  finalIndicator: boolean | null = null
  authenticatedEncryptionTag: Uint8Array | null = null
  authenticatedEncryptionAdditionalData: Uint8Array | null = null

  constructor(
    uniqueIdentifier: string,
    data: Uint8Array,
    cryptographicParameters: CryptographicParameters | null = null,
    ivCounterNonce: Uint8Array | null = null,
    correlationValue: Uint8Array | null = null,
    initIndicator: boolean | null = null,
    finalIndicator: boolean | null = null,
    authenticatedEncryptionTag: Uint8Array | null = null,
    authenticatedEncryptionAdditionalData: Uint8Array | null = null,
  ) {
    this.uniqueIdentifier = uniqueIdentifier
    this.data = data
    this.cryptographicParameters = cryptographicParameters
    this.ivCounterNonce = ivCounterNonce
    this.correlationValue = correlationValue
    this.initIndicator = initIndicator
    this.finalIndicator = finalIndicator
    this.authenticatedEncryptionTag = authenticatedEncryptionTag
    this.authenticatedEncryptionAdditionalData =
      authenticatedEncryptionAdditionalData
  }
}
