import secp256k1 from 'secp256k1'

import { Transaction } from "./transaction";
import { Signature } from "./wallet";
import { getDigest, getPayloadSECP256K1 } from "./wallet/utils";
import { SignatureType } from "./artifacts/wallet";
import { NetworkPrefix } from './artifacts/address';
import { AddressSecp256k1 } from './address';
import { Buffer } from 'buffer'

/**
 * Verify message signature
 * @param message - signed message
 * @param signature - signed string (base64)
 * @param networkPrefix - network type this account belongs
 * @returns Returns the address of the account that signed message to generate signature.
 */
export async function verifyMessage(message: Transaction | string, signature: string, networkPrefix?: NetworkPrefix): Promise<string> {
  networkPrefix = networkPrefix ? networkPrefix : NetworkPrefix.Mainnet
  let serialized: Buffer
  if (typeof message === 'object') {
    serialized = await message.serialize()
  } else {
    serialized = Buffer.from(message)
  }
  const txDigest = getDigest(serialized)
  const sign = Signature.fromJSON({Type: SignatureType.SECP256K1, Data: signature})
  const sigDat = sign.getData()
  const uncompressedPublicKey = secp256k1.ecdsaRecover(sigDat.subarray(0, -1), sigDat[64], txDigest, false)
  const payload = getPayloadSECP256K1(uncompressedPublicKey)
  return (new AddressSecp256k1(networkPrefix, payload)).toString()
}