import { KmsRequest } from "../kms"
import { GetResponse } from "../responses/GetResponse"
import { KeyWrappingSpecification } from "../structs/object_data_structures"

export class Get implements KmsRequest<GetResponse> {
  __response: GetResponse | undefined
  tag = "Get"

  uniqueIdentifier: string
  keyWrappingSpecification: KeyWrappingSpecification | null = null

  constructor(
    uniqueIdentifier: string,
    keyWrappingSpecification: KeyWrappingSpecification | null = null,
  ) {
    this.uniqueIdentifier = uniqueIdentifier
    this.keyWrappingSpecification = keyWrappingSpecification
  }
}
