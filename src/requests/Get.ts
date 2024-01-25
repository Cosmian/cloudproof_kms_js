import { KmsRequest } from "../kms"
import { GetResponse } from "../responses/GetResponse"
import {
  KeyFormatType,
  KeyWrappingSpecification,
} from "../structs/object_data_structures"

export class Get implements KmsRequest<GetResponse> {
  __response: GetResponse | undefined
  tag = "Get"

  uniqueIdentifier: string
  keyWrappingSpecification: KeyWrappingSpecification | null = null
  keyFormatType: KeyFormatType | null = null

  constructor(
    uniqueIdentifier: string,
    keyWrappingSpecification: KeyWrappingSpecification | null = null,
    keyFormatType: KeyFormatType | null = null,
  ) {
    this.uniqueIdentifier = uniqueIdentifier
    this.keyWrappingSpecification = keyWrappingSpecification
    this.keyFormatType = keyFormatType
  }
}
